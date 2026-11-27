"""Managed TLS client acceptance on a fresh Ubuntu systemd runner."""

import copy
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LOOPBACK = "127.0.0.1"
SERVER_NAME = "node.example.com"
ORIGIN_PORT, SOCKS_PORT, FIRST_NODE_PORT = 24860, 24861, 24862
SHOES_VERSION, SING_BOX_VERSION = "v0.3.7", "v1.14.2"
SHOES_BIN = Path("/usr/local/bin/shoes")
CONFIG_DIR = Path("/etc/shoes")
UNIT = "shoes.service"
SUDO = ("sudo", "-n")
POSITIVE, AUTH, CERTIFICATE = CASES = ("self-signed-insecure", "wrong-credentials", "untrusted-certificate")


@dataclass(frozen=True)
class Protocol:
    outbound_type: str
    auth_fields: tuple[str, ...]
    network: str = "tcp"


PROTOCOLS = {
    "hysteria2": Protocol("hysteria2", ("password",), "udp"),
    "tuic": Protocol("tuic", ("password", "uuid"), "udp"),
    "trojan-tls": Protocol("trojan", ("password",)),
    "vless-tls": Protocol("vless", ("uuid",)),
    "vless-ws-tls": Protocol("vless", ("uuid",)),
    "vmess-ws-tls": Protocol("vmess", ("uuid",)),
    "anytls": Protocol("anytls", ("password",)),
}
PHASES = {
    "preflight", "missing-binary", "port-conflict", "download-shoes", "download-sing-box",
    "install", "origin", "generate", "service-health", "server-ready", "export",
    "positive-control", "check", "client-ready", "request-timeout", "request", "unexpected-traffic",
    "rejection-unconfirmed", "acceptance", "cleanup", "interrupted", "internal",
}


class Failure(Exception):
    pass


class Results:
    def __init__(self, output):
        self.output = output
        self.rows = []

    def record(self, protocol, case, phase, started, status):
        row = {
            "protocol": protocol if protocol in PROTOCOLS else "-",
            "case": case if case in CASES else "-",
            "shoes_version": SHOES_VERSION, "sing_box_version": SING_BOX_VERSION,
            "phase": phase if phase in PHASES else "internal",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "verdict": "fail" if status else "pass",
        }
        line = json.dumps(row)
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        print(line, flush=True)
        self.rows.append(row)


def matrix_status(rows):
    expected = {(protocol, case) for protocol in PROTOCOLS for case in CASES}
    observed = {(row["protocol"], row["case"]) for row in rows if row["verdict"] == "pass"}
    return int(len(rows) != len(expected) or observed != expected)


def wrap_export(exported, socks_port):
    outbounds = copy.deepcopy(exported["outbounds"])
    if len(outbounds) != 1 or not outbounds[0]["tag"] or outbounds[0]["type"] == "direct":
        raise Failure("export")
    return {
        "log": {"level": "info"},
        "inbounds": [{"type": "socks", "listen": LOOPBACK, "listen_port": socks_port}],
        "outbounds": outbounds,
        "route": {"final": outbounds[0]["tag"]},
    }


def negative_copy(wrapped, field):
    config = copy.deepcopy(wrapped)
    outbound = config["outbounds"][0]
    if field == "certificate":
        outbound["tls"]["insecure"] = False
    elif field == "uuid":
        outbound[field] = str(uuid.UUID(int=uuid.UUID(outbound[field]).int ^ 1))
    else:
        outbound[field] += "-invalid"
    return config


@dataclass(frozen=True)
class Observation:
    curl_code: int = -1
    check_ok: bool = True
    client_alive: bool = True
    positive_ok: bool = True
    outbound_attempt: bool = False
    marker_received: bool = False
    origin_hits: int = 0
    rejection: str | None = None


def verdict(case, observed):
    if not observed.positive_ok:
        return 1, "positive-control"
    if not observed.check_ok:
        return 1, "check"
    if not observed.client_alive:
        return 1, "client-ready"
    if case != POSITIVE and (observed.marker_received or observed.origin_hits):
        return 1, "unexpected-traffic"
    if observed.curl_code == 28:
        return 1, "request-timeout"
    if case == POSITIVE:
        if not (observed.curl_code == 0 and observed.outbound_attempt
                and observed.marker_received and observed.origin_hits == 1):
            return 1, "request"
    else:
        expected = "credentials" if case == AUTH else "certificate"
        if not (observed.curl_code in {35, 52, 55, 56, 97} and observed.outbound_attempt
                and observed.rejection == expected):
            return 1, "rejection-unconfirmed"
    return 0, "acceptance"


def rejection_signal(client_log, curl_error):
    if "x509: certificate signed by unknown authority" in client_log:
        return "certificate"
    if re.search(
        r"auth(?:entication)? (?:error|failed|rejected)|invalid (?:password|user|credential)|"
        r"unauthorized|application error 0x[0-9a-f]+ \(remote\)|"
        r"stream \d+ canceled by remote|connection reset by peer|\beof\b",
        client_log, re.I,
    ) or re.search(r"empty reply from server|connection reset by peer|connection to proxy closed", curl_error, re.I):
        return "credentials"
    return None


def command(args, phase, *, log=None, timeout=15, env=None):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise Failure("request-timeout" if phase == "request" else phase) from None
    except OSError:
        raise Failure(phase) from None
    if log is not None:
        log.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        log.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
    return result


def checked(args, phase, **kwargs):
    result = command(args, phase, **kwargs)
    if result.returncode:
        raise Failure(phase)
    return result.stdout


def download(work, name, path, member, digest):
    phase = f"download-{name}"
    archive, executable = work / f"{name}.tar.gz", work / name
    checked(["curl", "-q", "--fail", "--silent", "--show-error", "--location", "--proto", "=https",
             "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "45",
             "--retry", "2", "--retry-max-time", "60", "--output", archive, f"https://github.com/{path}"],
            phase, log=work / phase, timeout=110)
    try:
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise Failure(phase)
        with tarfile.open(archive, "r:gz") as bundle:
            entries = [entry for entry in bundle.getmembers() if entry.name.removeprefix("./") == member]
            if len(entries) != 1 or not entries[0].isfile():
                raise Failure(phase)
            with bundle.extractfile(entries[0]) as stream, executable.open("xb") as output:
                shutil.copyfileobj(stream, output)
        executable.chmod(0o700)
    except (OSError, tarfile.TarError, EOFError):
        raise Failure(phase) from None
    return executable


def sockets(phase, privileged=False):
    output = checked([*(SUDO if privileged else ()), "ss", "-H", "-antup"], phase)
    for line in output.splitlines():
        network, state, _, _, local, _, *owner = line.split()
        port = local.rsplit(":", 1)[-1]
        if port.isdecimal():
            yield network, state, int(port), re.findall(r"\bpid=([0-9]+)\b", " ".join(owner))


def preflight(ping_rust):
    if not ping_rust.is_file() or not os.access(ping_rust, os.X_OK) or any(
        shutil.which(tool) is None for tool in ("curl", "sudo", "ss", "systemctl", "pgrep")
    ):
        raise Failure("missing-binary")
    if (os.geteuid() == 0 or platform.machine() != "x86_64" or sys.platform != "linux"
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise Failure("preflight")
    checked([*SUDO, "true"], "preflight")
    if os.path.lexists(SHOES_BIN) or CONFIG_DIR.is_symlink():
        raise Failure("preflight")
    if CONFIG_DIR.exists():
        info = CONFIG_DIR.stat()
        if (not CONFIG_DIR.is_dir() or info.st_uid != 0 or info.st_mode & 0o022
                or checked([*SUDO, "find", CONFIG_DIR, "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"],
                           "preflight")):
            raise Failure("preflight")
    state = command(["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "DropInPaths", UNIT],
                    "preflight")
    properties = set(state.stdout.splitlines()) - {"DropInPaths="}
    if (state.returncode not in {0, 1, 4} or properties != {"LoadState=not-found", "ActiveState=inactive"}
            or command([*SUDO, "pgrep", "-x", "shoes"], "preflight").returncode != 1):
        raise Failure("preflight")
    reserved = {ORIGIN_PORT, SOCKS_PORT, *range(FIRST_NODE_PORT, FIRST_NODE_PORT + len(PROTOCOLS))}
    require_free_ports(reserved)


def require_free_ports(ports, *, ignore_time_wait=False):
    if any(port in ports and not (ignore_time_wait and state == "TIME-WAIT")
           for _, state, port, _ in sockets("port-conflict")):
        raise Failure("port-conflict")


def wait_port(network, port, pid, phase, *, privileged=False, alive=lambda: True):
    expected = network, "LISTEN" if network == "tcp" else "UNCONN", port
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline and alive():
        listeners = [set(owners) for found_network, state, found_port, owners in sockets(phase, privileged)
                     if (found_network, state, found_port) == expected]
        if listeners:
            if any(owners != {str(pid)} for owners in listeners):
                raise Failure("port-conflict")
            return
        time.sleep(0.1)
    raise Failure(phase)


def service_pid():
    state = checked(["systemctl", "show", "-p", "ActiveState", "-p", "MainPID", UNIT], "service-health")
    pid = re.search(r"^MainPID=([1-9][0-9]*)$", state, re.M)
    if not pid or "ActiveState=active" not in state.splitlines():
        raise Failure("service-health")
    return pid[1]


def managed_export(ping_rust, work, slug, protocol, port):
    name = f"tls-e2e-{slug}-{secrets.token_hex(5)}"
    options = ["--anytls-mode", "tls"] if slug == "anytls" else []
    require_free_ports({port})
    generated = checked([*SUDO, ping_rust, "generate", slug, "--name", name, "--port", str(port),
                         "--server-name", SERVER_NAME, *options], "generate", log=work / "generate", timeout=120)
    pid = service_pid()
    wait_port(protocol.network, port, pid, "server-ready", privileged=True)
    try:
        profile, = re.findall(r"^配置 ID：([0-9a-f-]{36})$", generated, re.M)
        profile = str(uuid.UUID(profile))
        exported = json.loads(checked([*SUDO, ping_rust, "export", "sing-box", "--profile", profile,
                                      "--server", LOOPBACK], "export", log=work / "export"))
        wrapped = wrap_export(exported, SOCKS_PORT)
        outbound, = wrapped["outbounds"]
        tls = outbound["tls"]
        if (outbound["type"] != protocol.outbound_type or outbound["tag"] != name
                or outbound["server"] != LOOPBACK or outbound["server_port"] != port
                or "detour" in outbound or set(tls) - {"enabled", "server_name", "insecure", "alpn"}
                or tls["enabled"] is not True or tls["insecure"] is not True or tls["server_name"] != SERVER_NAME
                or not all(isinstance(outbound[field], str) and outbound[field] for field in protocol.auth_fields)
                or (slug == "vless-tls" and outbound.get("flow") != "xtls-rprx-vision")
                or (slug.endswith("-ws-tls") and outbound["transport"]["type"] != "ws")):
            raise Failure("export")
    except (KeyError, ValueError, TypeError):
        raise Failure("export") from None
    return wrapped, pid


class Origin(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


class MarkerHandler(BaseHTTPRequestHandler):
    def parse_request(self):
        if not super().parse_request():
            return False
        self.server.hits.append(self.path)
        with self.server.hit_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(self.path) + "\n")
        return True

    def do_GET(self):
        if self.path != self.server.marker_path:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.server.marker)))
        self.end_headers()
        self.wfile.write(self.server.marker.encode("ascii"))

    def log_message(self, format, *args):
        pass


@contextmanager
def http_origin(work):
    try:
        server = Origin((LOOPBACK, ORIGIN_PORT), MarkerHandler)
    except OSError:
        raise Failure("origin") from None
    with server:
        server.hit_log = work / "origin-hits.jsonl"
        server.hits = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


@contextmanager
def running_client(binary, config, log, env):
    with log.open("w", encoding="utf-8") as stream:
        try:
            process = subprocess.Popen([binary, "run", "-c", config], stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, env=env)
        except OSError:
            raise Failure("client-ready") from None
        try:
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def probe(case, config, work, label, sing_box, server, pid):
    path, log = work / f"{label}.json", work / f"{label}.log"
    path.write_text(json.dumps(config), encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if key not in {"SSL_CERT_FILE", "SSL_CERT_DIR"}}
    env.update(NO_COLOR="1", TERM="dumb")
    check = command([sing_box, "check", "-c", path], "check", log=work / f"{label}-check", env=env)
    if check.returncode:
        return verdict(case, Observation(check_ok=False))
    require_free_ports({SOCKS_PORT}, ignore_time_wait=True)
    server.marker_path, server.marker = f"/{secrets.token_hex(16)}", secrets.token_hex(32)
    before = len(server.hits)
    with running_client(sing_box, path, log, env) as client:
        wait_port("tcp", SOCKS_PORT, client.pid, "client-ready", alive=lambda: client.poll() is None)
        if service_pid() != pid:
            raise Failure("service-health")
        result = command(["curl", "-q", "--fail", "--silent", "--show-error", "--noproxy", "",
                          "--proxy", f"socks5h://{LOOPBACK}:{SOCKS_PORT}", "--max-time", "8",
                          f"http://{LOOPBACK}:{ORIGIN_PORT}{server.marker_path}"],
                         "request", log=work / f"{label}-curl", timeout=12)
        alive = client.poll() is None
        if service_pid() != pid:
            raise Failure("service-health")
        trace = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(encoding="utf-8", errors="replace"))
    outbound, = config["outbounds"]
    dispatch = f"outbound/{outbound['type']}[{outbound['tag']}]: outbound connection to {LOOPBACK}:{ORIGIN_PORT}"
    _, dispatched, after_dispatch = trace.partition(dispatch)
    hits = server.hits[before:]
    marker_received = (server.marker == result.stdout and hits == [server.marker_path]
                       if case == POSITIVE else server.marker in result.stdout)
    return verdict(case, Observation(
        curl_code=result.returncode, client_alive=alive, outbound_attempt=bool(dispatched),
        marker_received=marker_received, origin_hits=len(hits),
        rejection=rejection_signal(after_dispatch, result.stderr),
    ))


def run_protocol(slug, protocol, port, ping_rust, work, sing_box, server, results):
    started = time.monotonic()
    work.mkdir(mode=0o700)
    try:
        config, pid = managed_export(ping_rust, work, slug, protocol, port)
    except Failure as error:
        if str(error) == "port-conflict":
            raise
        results.record(slug, POSITIVE, str(error), started, 1)
        for case in (AUTH, CERTIFICATE):
            results.record(slug, case, "positive-control", started, 1)
        return
    positive_ok = False
    for case in CASES:
        started = time.monotonic()
        status, phase = verdict(case, Observation(positive_ok=False))
        if case == POSITIVE or positive_ok:
            fields = {POSITIVE: (None,), AUTH: protocol.auth_fields, CERTIFICATE: ("certificate",)}[case]
            status, phase = 0, "acceptance"
            for field in fields:
                variant = negative_copy(config, field) if field else config
                try:
                    code, stage = probe(case, variant, work, f"{case}-{field}" if field else case, sing_box, server, pid)
                except Failure as error:
                    if str(error) == "port-conflict":
                        raise
                    code, stage = 1, str(error)
                if code and not status:
                    status, phase = code, stage
        results.record(slug, case, phase, started, status)
        if case == POSITIVE:
            positive_ok = status == 0


def accept(ping_rust, work, results):
    preflight(ping_rust)
    shoes = download(work, "shoes", f"cfal/shoes/releases/download/{SHOES_VERSION}/shoes-x86_64-unknown-linux-musl.tar.gz",
                     "shoes", "c594d7b30b474b6b3ab4cd30cc0996ba39aac2e66ffaadd725894037866a2705")
    package = f"sing-box-{SING_BOX_VERSION[1:]}-linux-amd64"
    sing_box = download(work, "sing-box", f"SagerNet/sing-box/releases/download/{SING_BOX_VERSION}/{package}.tar.gz",
                        f"{package}/sing-box", "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6")
    preflight(ping_rust)
    with http_origin(work) as server:
        if not CONFIG_DIR.exists():
            checked([*SUDO, "mkdir", "-m", "0700", CONFIG_DIR], "install")
        checked([*SUDO, "install", "-m", "0755", shoes, SHOES_BIN], "install")
        try:
            for index, (slug, protocol) in enumerate(PROTOCOLS.items(), FIRST_NODE_PORT):
                run_protocol(slug, protocol, index, ping_rust, work / slug, sing_box, server, results)
        finally:
            started = time.monotonic()
            try:
                unit = command(["systemctl", "show", "--property=LoadState", "--value", UNIT], "cleanup")
                if unit.returncode == 0 and unit.stdout.strip() != "not-found":
                    checked([*SUDO, "systemctl", "disable", "--now", UNIT], "cleanup", log=work / "cleanup")
                elif unit.returncode not in {0, 1, 4} or unit.stdout.strip() != "not-found":
                    raise Failure("cleanup")
            except Failure:
                results.record("-", "-", "cleanup", started, 1)


def directories():
    paths = [Path(os.environ[key]) for key in ("TLS_ACCEPTANCE_PRIVATE_DIR", "TLS_ACCEPTANCE_RESULTS_DIR")]
    if any(not path.is_absolute() or os.path.lexists(path) for path in paths):
        raise Failure("preflight")
    work, public = (path.resolve() for path in paths)
    if work.is_relative_to(public) or public.is_relative_to(work):
        raise Failure("preflight")
    work.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    return work, public


def interrupted(signum, frame):
    raise KeyboardInterrupt


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    if sys.argv[1:] == ["--list"]:
        print(json.dumps({protocol: CASES for protocol in PROTOCOLS}))
        return 0
    try:
        if sys.argv[1:]:
            raise Failure("preflight")
        work, public = directories()
    except (Failure, OSError, KeyError, ValueError):
        print("需要两个绝对、互不包含且尚不存在的验收目录（私有和结果）。", file=sys.stderr)
        return 1
    results = Results(public / "results.jsonl")
    started = time.monotonic()
    try:
        ping_rust = Path(os.environ.get("PING_RUST", "target/release/ping-rust")).resolve()
        accept(ping_rust, work, results)
    except Failure as error:
        results.record("-", "-", str(error), started, 1)
    except KeyboardInterrupt:
        results.record("-", "-", "interrupted", started, 1)
    except Exception:
        with (work / "internal.log").open("w", encoding="utf-8") as stream:
            traceback.print_exc(file=stream)
        results.record("-", "-", "internal", started, 1)
    return matrix_status(results.rows)


if __name__ == "__main__":
    sys.exit(main())
