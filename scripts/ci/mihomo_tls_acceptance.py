"""Probe Mihomo certificate pin candidates, not ping-rust client exports."""

import json
import os
import re
import secrets
import signal
import sys
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

import tls_client_acceptance as tls


SPELLINGS = ("hex-lower", "hex-upper", "colon-lower", "colon-upper")
PIN_CASES = ("matching-leaf", "wrong-pin", "different-key", "same-key-reissued", "mismatched-name")
CANDIDATES = {"no-pin": "no-pin", **{f"{spelling}/{case}": case for spelling in SPELLINGS for case in PIN_CASES}}
PASS_EVIDENCE = {
    "no-pin": {"certificate"}, "matching-leaf": {"marker"}, "wrong-pin": {"pin-mismatch"},
    "different-key": {"pin-mismatch"}, "same-key-reissued": {"pin-mismatch"},
    "mismatched-name": {"name-checked", "name-not-checked"},
}
EVIDENCE = tls.PHASES | set().union(*PASS_EVIDENCE.values()) | {"download-mihomo", "node-profile", "hostname"}
WRONG_NAME = "other.example.com"
PROFILE_TYPES = {
    "hysteria2": "Hysteria2", "tuic": "Tuic", "trojan-tls": "Trojan", "anytls": "AnyTls",
    "vless-tls": "VlessTls", "vless-ws-tls": "VlessTls", "vmess-ws-tls": "VmessTls",
}


class Results:
    def __init__(self, output):
        self.output = output
        self.rows = []

    def record(self, protocol, candidate, verdict, evidence):
        row = {
            "protocol": protocol if protocol in tls.PROTOCOLS else "-",
            "candidate": candidate if candidate in CANDIDATES else "-",
            "verdict": "pass" if verdict == "pass" else "fail",
            "evidence": evidence if evidence in EVIDENCE else "internal",
        }
        line = json.dumps(row)
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        self.rows.append(row)
        if row["verdict"] == "fail":
            print(line, file=sys.stderr, flush=True)

    def cleanup_failed(self, _started):
        self.record("-", "-", "fail", "cleanup")


def matrix_status(rows):
    expected = {(protocol, candidate) for protocol in tls.PROTOCOLS for candidate in CANDIDATES}
    observed = {(row["protocol"], row["candidate"]) for row in rows if row["verdict"] == "pass"
                and row["evidence"] in PASS_EVIDENCE.get(CANDIDATES.get(row["candidate"]), ())}
    return int(len(rows) != len(expected) or observed != expected)


def candidate_verdict(case, observed):
    if case == "matching-leaf" or (case == "mismatched-name" and observed.curl_code == 0):
        status, phase = tls.verdict(tls.POSITIVE, observed)
        if status or observed.rejection:
            evidence = observed.rejection if observed.rejection and phase in {"request", "acceptance"} else phase
            return "fail", evidence
        return "pass", "marker" if case == "matching-leaf" else "name-not-checked"
    if case == "mismatched-name":
        attributed = "certificate" if observed.rejection == "hostname" else None
        status, phase = tls.verdict(tls.CERTIFICATE, replace(observed, rejection=attributed))
        evidence = "name-checked"
    elif case == "no-pin":
        status, phase = tls.verdict(tls.CERTIFICATE, observed)
        evidence = "certificate"
    else:
        status, phase = tls.verdict(tls.DIFFERENT_KEY, observed)
        evidence = "pin-mismatch"
    return ("fail", phase) if status else ("pass", evidence)


def route_evidence(trace, outbound):
    origin = rf"{re.escape(tls.LOOPBACK)}:\d+ --> {re.escape(tls.LOOPBACK)}:{tls.ORIGIN_PORT}"
    routes = re.findall(rf"\[TCP\] (?:dial (\S+) \(match ([^)]*)\) ({origin}) error: (.*)"
                        rf"|{origin} match (\S+) using ([^\s\"]+)\"?[ \t]*$)",
                        trace, re.M)
    if len(routes) == 1 and routes[0][-2:] == ("Match", outbound):
        return True, None

    rejections = set()
    for failed, failure_rule, endpoints, reason, _, _ in routes:
        if failure_rule not in {"Match/", "Match"} or failed != outbound:
            return False, None
        evidence = certificate_rejection(reason)
        if evidence is None:
            return False, None
        rejections.add((endpoints, evidence))
    if len(rejections) != 1:
        return False, None
    (_, evidence), = rejections
    return True, evidence


def certificate_rejection(reason):
    if re.search(r"\bfingerprints? (?:mismatch|(?:(?:do(?:es)?|did) )?not match(?:ed)?)\b|"
                 r"\bcertificate (?:do(?:es)?|did) not match (?:the )?(?:expected )?fingerprint\b", reason, re.I):
        return "pin-mismatch"
    if "x509: certificate signed by unknown authority" in reason:
        return "certificate"
    if re.search(rf"x509: certificate is (?:valid for [^\r\n]+, not |"
                 rf"not valid for any names, but wanted to match ){re.escape(tls.SERVER_NAME)}(?![\w.-])", reason):
        return "hostname"
    return None


def leaf_digest(cert, phase):
    fingerprint = tls.checked([*tls.SUDO, "openssl", "x509", "-in", cert, "-noout", "-sha256", "-fingerprint"], phase)
    match = re.fullmatch(r"SHA256 Fingerprint=((?:[0-9A-F]{2}:){31}[0-9A-F]{2})", fingerprint.strip(), re.I)
    if not match:
        raise tls.Failure(phase)
    return match[1].replace(":", "").lower()


def verify_leaf_name(certificate, phase, *, matches=True):
    result = tls.command([*tls.SUDO, "openssl", "verify", "-trusted", certificate,
                          "-verify_hostname", tls.SERVER_NAME, certificate], phase)
    if matches and result.returncode == 0:
        return
    if not matches and result.returncode and re.search(r"^error 62 at 0 depth lookup: hostname mismatch$",
                                                       result.stderr, re.M):
        return
    raise tls.Failure(phase)


@contextmanager
def alternate_leaf(work, node, case, original_digest):
    phase = "replace-certificate"
    if case == "different-key":
        with tls.different_certificate(work, node.profile, node.protocol, node.port) as pid:
            verify_leaf_name(node.certificate, phase)
            yield pid, original_digest
        return

    _, key = tls.certificate_files(node.profile)
    original_key = tls.public_key_pin(node.certificate, phase)
    name = WRONG_NAME if case == "mismatched-name" else tls.SERVER_NAME
    replacement = work / "replacement.pem"
    pem = tls.checked([*tls.SUDO, "openssl", "req", "-x509", "-new", "-key", key, "-config", os.devnull,
                       "-days", "1", "-set_serial", f"0x{secrets.token_hex(16)}", "-subj", f"/CN={name}",
                       "-addext", f"subjectAltName=DNS:{name}"], phase)
    replacement.write_text(pem, encoding="utf-8")
    digest = leaf_digest(replacement, phase)
    if digest == original_digest or tls.public_key_pin(replacement, phase) != original_key:
        raise tls.Failure(phase)
    verify_leaf_name(replacement, phase, matches=case != "mismatched-name")
    with tls.installed_certificate(node.profile, node.protocol, node.port, replacement) as pid:
        yield pid, digest if case == "mismatched-name" else original_digest


def experimental_proxy(node):
    phase = "node-profile"
    try:
        state = json.loads(tls.checked([*tls.SUDO, "cat", tls.CONFIG_DIR / "ping-rust-state.json"], phase))
        profile, = (profile for profile in state["profiles"] if profile["id"] == node.profile)
        credentials = profile["credentials"][PROFILE_TYPES[node.slug]]
        if (profile["name"] != node.name or profile["port"] != node.port
                or profile["self_signed_certificate"] is not True
                or profile["certificate_path"] != str(node.certificate)
                or credentials["server_name"] != tls.SERVER_NAME):
            raise ValueError
        proxy = {"name": "tls-pin-probe", "type": node.protocol.outbound_type,
                 "server": tls.LOOPBACK, "port": node.port, "alpn": credentials["alpn_protocols"],
                 "skip-cert-verify": False}
        if proxy["type"] in {"vless", "vmess"}:
            path = credentials.get("websocket_path")
            proxy.update({"uuid": credentials["user_id"], "servername": tls.SERVER_NAME,
                          "tls": True, "network": "ws" if path else "tcp"})
            if node.slug.endswith("-ws-tls") != bool(path):
                raise ValueError
            if path:
                proxy["ws-opts"] = {"path": path, "headers": {"Host": tls.SERVER_NAME}}
            if proxy["type"] == "vmess":
                proxy.update({"alterId": 0, "cipher": "aes-128-gcm"})
            else:
                if credentials["vision"] != (node.slug == "vless-tls"):
                    raise ValueError
                if credentials["vision"]:
                    proxy["flow"] = "xtls-rprx-vision"
        else:
            proxy["sni"] = tls.SERVER_NAME
            if node.slug in {"trojan-tls", "anytls"} and credentials["security"] != "Tls":
                raise ValueError
            user = credentials
            if node.slug == "anytls":
                user, = credentials["users"]
            proxy["password"] = user["password"]
            if node.slug == "tuic":
                proxy.update({"uuid": credentials["user_id"], "reduce-rtt": False,
                              "congestion-controller": "bbr", "udp-relay-mode": "native"})
        if node.protocol.network == "tcp":
            proxy["client-fingerprint"] = "chrome"
        if not all(isinstance(proxy[field], str) and proxy[field] for field in node.protocol.auth_fields):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise tls.Failure(phase) from None
    return proxy


def candidate_config(base, digest=None, spelling=None):
    proxy = dict(base)
    if digest is not None:
        if spelling.startswith("colon-"):
            digest = ":".join(re.findall(r"..", digest))
        proxy["fingerprint"] = digest.upper() if spelling.endswith("-upper") else digest
    return {"socks-port": tls.SOCKS_PORT, "bind-address": tls.LOOPBACK, "allow-lan": False,
            "mode": "rule", "log-level": "debug", "find-process-mode": "off",
            "proxies": [proxy], "rules": [f"MATCH,{proxy['name']}"]}


@dataclass(frozen=True)
class Mihomo:
    binary: Path
    home: Path

    @classmethod
    def prepare(cls, work):
        phase = "download-mihomo"
        loader = Path(__file__).with_name("external-client-acceptance.sh")
        tls.checked(["bash", loader, "--download-mihomo-only", work], phase, log=work / phase, timeout=120)
        binary = work / "mihomo"
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise tls.Failure("missing-binary")
        home = work / "mihomo-home"
        home.mkdir(mode=0o700)
        return cls(binary, home)

    def observe(self, case, config, work, label, server, pid):
        path, log = work / f"{label}.json", work / f"{label}.log"
        path.write_text(json.dumps(config), encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if key not in {"SSL_CERT_FILE", "SSL_CERT_DIR"}}
        env.update(NO_COLOR="1", TERM="dumb")
        args = [self.binary, "-d", self.home, "-f", path]
        check = tls.command([*args, "-t"], "check", log=work / f"{label}-check", env=env)
        if check.returncode:
            return tls.Observation(check_ok=False)
        tls.require_free_ports({tls.SOCKS_PORT}, ignore_time_wait=True)
        server.marker_path, server.marker = f"/{secrets.token_hex(16)}", secrets.token_hex(32)
        before = len(server.hits)
        with tls.running_client(args, log, env) as client:
            tls.wait_port("tcp", tls.SOCKS_PORT, client.pid, "client-ready", alive=lambda: client.poll() is None)
            tls.require_service_pid(pid)
            result, alive = tls.request_via_socks(work, label, server, pid, client)
        trace = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(encoding="utf-8", errors="replace"))
        attempted, rejection = route_evidence(trace, config["proxies"][0]["name"])
        marker_case = tls.POSITIVE if case in {"matching-leaf", "mismatched-name"} and not rejection else tls.CERTIFICATE
        return replace(tls.observe_origin(marker_case, server, before, result, alive),
                       outbound_attempt=attempted, rejection=rejection)


def run_protocol(slug, protocol, port, ping_rust, work, backend, server, results):
    work.mkdir(mode=0o700)
    try:
        node = tls.generate_node(ping_rust, work, slug, protocol, port)
        proxy = experimental_proxy(node)
        digest = leaf_digest(node.certificate, "node-profile")
        verify_leaf_name(node.certificate, "node-profile")
    except tls.Failure as error:
        if str(error) == "port-conflict":
            raise
        for candidate in CANDIDATES:
            results.record(slug, candidate, "fail", str(error))
        return

    def probe(case, pid, fingerprint=None, spelling=None, *, phase=None):
        candidate = f"{spelling}/{case}" if spelling else case
        if phase is None:
            try:
                config = candidate_config(proxy, fingerprint, spelling)
                observed = backend.observe(case, config, work, candidate.replace("/", "-"), server, pid)
                verdict, evidence = candidate_verdict(case, observed)
            except tls.Failure as error:
                if str(error) == "port-conflict":
                    raise
                verdict, evidence = "fail", str(error)
        else:
            verdict, evidence = "fail", phase
        results.record(slug, candidate, verdict, evidence)
        return verdict == "pass"

    passing = {spelling for spelling in SPELLINGS if probe("matching-leaf", node.pid, digest, spelling)}
    probe("no-pin", node.pid, phase=None if passing else "positive-control")
    wrong_digest = f"{int(digest[0], 16) ^ 1:x}{digest[1:]}"
    for spelling in SPELLINGS:
        probe("wrong-pin", node.pid, wrong_digest, spelling, phase=None if spelling in passing else "positive-control")
    for case in ("different-key", "same-key-reissued", "mismatched-name"):
        for spelling in SPELLINGS:
            if spelling not in passing:
                probe(case, node.pid, spelling=spelling, phase="positive-control")
        if not passing:
            continue
        entered = False
        try:
            with alternate_leaf(work, node, case, digest) as (pid, fingerprint):
                entered = True
                for spelling in SPELLINGS:
                    if spelling in passing:
                        probe(case, pid, fingerprint, spelling)
        except tls.Failure as error:
            if entered or str(error) in {"port-conflict", "restore-certificate"}:
                raise
            for spelling in SPELLINGS:
                if spelling in passing:
                    probe(case, node.pid, spelling=spelling, phase=str(error))


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, tls.interrupted)
    if sys.argv[1:] == ["--list"]:
        print(json.dumps({protocol: list(CANDIDATES) for protocol in tls.PROTOCOLS}))
        return 0
    try:
        if sys.argv[1:]:
            raise tls.Failure("preflight")
        work, public = tls.directories()
    except (tls.Failure, OSError, KeyError, ValueError):
        print("需要两个绝对、互不包含且尚不存在的验收目录（私有和结果）。", file=sys.stderr)
        return 1
    results = Results(public / "results.jsonl")
    try:
        ping_rust = Path(os.environ.get("PING_RUST", "target/release/ping-rust")).resolve()
        tls.accept(ping_rust, work, results, prepare_backend=Mihomo.prepare, run_node=run_protocol)
    except tls.Failure as error:
        results.record("-", "-", "fail", str(error))
    except KeyboardInterrupt:
        results.record("-", "-", "fail", "interrupted")
    except Exception:
        results.record("-", "-", "fail", "internal")
    return matrix_status(results.rows)


if __name__ == "__main__":
    sys.exit(main())
