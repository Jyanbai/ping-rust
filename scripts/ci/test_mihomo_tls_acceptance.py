"""Exercise the Mihomo evidence harness without clients, systemd or sockets."""

import gzip
import hashlib
import json
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import mihomo_tls_acceptance as mihomo
import tls_client_acceptance as tls


class MihomoAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.connected = tls.Observation(curl_code=0, outbound_attempt=True,
                                         marker_received=True, origin_hits=1)
        self.rejected = tls.Observation(curl_code=97, outbound_attempt=True, rejection="pin-mismatch")

    def test_matrix_requires_each_row_once_with_expected_evidence(self):
        complete = [{"protocol": slug, "candidate": candidate, "verdict": "pass",
                     "evidence": sorted(mihomo.PASS_EVIDENCE[case])[0]}
                    for slug in tls.PROTOCOLS for candidate, case in mihomo.CANDIDATES.items()]
        self.assertEqual(len(complete), 147)
        self.assertEqual(mihomo.matrix_status(complete), 0)
        for rows in (complete[:-1], complete + complete[:1], complete[:-1] + complete[:1],
                     complete[:-1] + [dict(complete[-1], evidence="check")],
                     complete[:-1] + [dict(complete[-1], verdict="fail")]):
            self.assertEqual(mihomo.matrix_status(rows), 1)

    def test_marker_and_attributed_rejection_are_required(self):
        for case in ("wrong-pin", "different-key", "same-key-reissued"):
            self.assertEqual(mihomo.candidate_verdict(case, self.rejected), ("pass", "pin-mismatch"))
            for changes in ({"origin_hits": 1}, {"marker_received": True}, {"curl_code": 28},
                            {"outbound_attempt": False}, {"rejection": None}, {"positive_ok": False},
                            {"check_ok": False}, {"client_alive": False}, {"rejection": "certificate"}):
                with self.subTest(case=case, changes=changes):
                    self.assertEqual(mihomo.candidate_verdict(case, replace(self.rejected, **changes))[0], "fail")
        self.assertEqual(mihomo.candidate_verdict("no-pin", replace(self.rejected, rejection="certificate")),
                         ("pass", "certificate"))
        self.assertEqual(mihomo.candidate_verdict("no-pin", self.rejected)[0], "fail")
        self.assertEqual(mihomo.candidate_verdict("matching-leaf", self.connected), ("pass", "marker"))
        for changes in ({"marker_received": False}, {"origin_hits": 0}, {"origin_hits": 2},
                        {"outbound_attempt": False}):
            self.assertEqual(mihomo.candidate_verdict("matching-leaf", replace(self.connected, **changes))[0], "fail")
        self.assertEqual(mihomo.candidate_verdict("mismatched-name", self.connected), ("pass", "name-not-checked"))
        self.assertEqual(mihomo.candidate_verdict("mismatched-name", replace(self.rejected, rejection="hostname")),
                         ("pass", "name-checked"))
        self.assertEqual(mihomo.candidate_verdict("mismatched-name", self.rejected)[0], "fail")
        self.assertEqual(mihomo.candidate_verdict("mismatched-name", replace(self.connected, positive_ok=False))[0],
                         "fail")

    def test_only_the_expected_route_can_supply_evidence(self):
        target = f"127.0.0.1:32100 --> 127.0.0.1:{tls.ORIGIN_PORT}"
        failure = f'[TCP] dial probe (match Match/) {target} error: '
        success = f'time="now" level=info msg="[TCP] {target} match Match using probe"'
        self.assertEqual(mihomo.route_evidence(success, "probe"), (True, None))
        self.assertEqual(mihomo.route_evidence(failure + "tls: certificate fingerprint mismatch", "probe"),
                         (True, "pin-mismatch"))
        self.assertEqual(mihomo.route_evidence(failure + "x509: certificate signed by unknown authority", "probe"),
                         (True, "certificate"))
        self.assertEqual(mihomo.route_evidence(
            failure + f"tls: x509: certificate is valid for other.example.com, not {tls.SERVER_NAME}", "probe"),
            (True, "hostname"))
        self.assertEqual(mihomo.route_evidence(failure + "unexpected EOF", "probe"), (False, None))
        for unrelated in (success.replace("using probe", "using DIRECT"),
                          success.replace(f":{tls.ORIGIN_PORT}", f":{tls.ORIGIN_PORT}0"),
                          failure.replace("dial probe", "dial DIRECT") + "certificate fingerprint mismatch",
                          "certificate fingerprint mismatch",
                          success + "\n" + failure.replace("dial probe", "dial DIRECT") + "EOF"):
            self.assertEqual(mihomo.route_evidence(unrelated, "probe"), (False, None))

    def test_candidate_is_isolated_and_changes_only_the_fingerprint(self):
        digest = "ab" * 32
        proxy = {"name": "probe", "skip-cert-verify": False, "sni": tls.SERVER_NAME}
        for spelling, expected in {"hex-lower": "ab" * 32, "hex-upper": "AB" * 32,
                                   "colon-lower": ":".join(["ab"] * 32),
                                   "colon-upper": ":".join(["AB"] * 32)}.items():
            config = mihomo.candidate_config(proxy, digest, spelling)
            self.assertEqual(config["proxies"], [dict(proxy, fingerprint=expected)])
            self.assertEqual(config["rules"], ["MATCH,probe"])
            self.assertEqual(config["bind-address"], tls.LOOPBACK)
            self.assertEqual(config["socks-port"], tls.SOCKS_PORT)
        self.assertEqual(mihomo.candidate_config(proxy)["proxies"], [proxy])
        self.assertNotIn("fingerprint", proxy)

    def test_experimental_proxies_use_generated_node_identity_and_transport(self):
        profile_id = "00000000-0000-4000-8000-000000000001"
        for slug, protocol in tls.PROTOCOLS.items():
            with self.subTest(slug=slug):
                node = tls.ManagedNode(slug, protocol, "node", 12345, profile_id, "100")
                ws = slug.endswith("-ws-tls")
                quic = protocol.network == "udp"
                alpn = ["h3"] if quic else ["http/1.1"]
                credentials = {"password": "test-only", "user_id": profile_id, "security": "Tls",
                               "users": [{"password": "test-only"}], "server_name": tls.SERVER_NAME,
                               "alpn_protocols": alpn, "vision": slug == "vless-tls",
                               "websocket_path": "/test-only" if ws else None}
                profile = {"id": profile_id, "port": node.port, "name": node.name, "self_signed_certificate": True,
                           "certificate_path": str(node.certificate),
                           "credentials": {mihomo.PROFILE_TYPES[slug]: credentials}}
                with patch.object(tls, "checked", return_value=json.dumps({"profiles": [profile]})) as checked:
                    proxy = mihomo.experimental_proxy(node)
                    self.assertEqual(checked.call_args.args[0][-2:], ["cat", tls.CONFIG_DIR / "ping-rust-state.json"])
                self.assertEqual(proxy["type"], protocol.outbound_type)
                self.assertEqual(proxy["server"], tls.LOOPBACK)
                self.assertEqual(proxy["port"], node.port)
                self.assertEqual(proxy["alpn"], alpn)
                self.assertIs(proxy["skip-cert-verify"], False)
                self.assertEqual(proxy.get("sni", proxy.get("servername")), tls.SERVER_NAME)
                self.assertEqual(set(proxy) & {"uuid", "password"}, set(protocol.auth_fields))
                self.assertEqual(proxy.get("flow"), "xtls-rprx-vision" if slug == "vless-tls" else None)
                self.assertEqual(proxy.get("ws-opts"), {"path": "/test-only", "headers": {"Host": tls.SERVER_NAME}}
                                 if ws else None)
                self.assertEqual(proxy.get("client-fingerprint"), None if quic else "chrome")
                if slug == "tuic":
                    self.assertIs(proxy["reduce-rtt"], False)

    def test_fingerprint_is_sha256_of_leaf_der_not_spki_or_pem(self):
        fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/tls/self-signed.pem"
        der = subprocess.check_output(["openssl", "x509", "-in", fixture, "-outform", "DER"], timeout=5)
        with patch.object(tls, "SUDO", ()):
            self.assertEqual(mihomo.leaf_digest(fixture, "generate"), hashlib.sha256(der).hexdigest())

    def test_replacement_leaves_change_only_the_intended_identity_and_restore(self):
        checked = tls.checked

        def local_command(args, phase, **kwargs):
            return "" if args[0] == "systemctl" else checked(args, phase, **kwargs)

        with (tempfile.TemporaryDirectory() as root, patch.object(tls, "CONFIG_DIR", Path(root)),
              patch.object(tls, "SUDO", ()), patch.object(tls, "checked", side_effect=local_command),
              patch.object(tls, "service_pid", return_value="101"), patch.object(tls, "wait_port")):
            profile = "00000000-0000-4000-8000-000000000001"
            node = tls.ManagedNode("anytls", tls.PROTOCOLS["anytls"], "probe", 12345, profile, "100")
            cert, key = tls.certificate_files(profile)
            checked(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                     "-config", "/dev/null", "-noenc", "-days", "1", "-subj", f"/CN={tls.SERVER_NAME}",
                     "-addext", f"subjectAltName=DNS:{tls.SERVER_NAME}", "-out", cert, "-keyout", key], "generate")
            original_cert, original_key = cert.read_bytes(), key.read_bytes()
            original_digest = mihomo.leaf_digest(cert, "generate")
            original_spki = tls.public_key_pin(cert, "generate")
            for case in ("different-key", "same-key-reissued", "mismatched-name"):
                with self.subTest(case=case), self.assertRaisesRegex(tls.Failure, "request"):
                    with mihomo.alternate_leaf(Path(root), node, case, original_digest) as (pid, pin):
                        observed_digest = mihomo.leaf_digest(cert, "generate")
                        self.assertNotEqual(observed_digest, original_digest)
                        self.assertEqual(pid, "101")
                        self.assertEqual(tls.public_key_pin(cert, "generate") == original_spki, case != "different-key")
                        self.assertEqual(pin, observed_digest if case == "mismatched-name" else original_digest)
                        mihomo.verify_leaf_name(cert, "generate", matches=case != "mismatched-name")
                        raise tls.Failure("request")
                self.assertEqual((cert.read_bytes(), key.read_bytes()), (original_cert, original_key))
                self.assertEqual(list(Path(root).glob("*.pin-test-original")), [])

    def test_probe_matrix_only_uses_live_controls_and_each_replacement_pin(self):
        slug = "tuic"
        protocol = tls.PROTOCOLS[slug]
        node = tls.ManagedNode(slug, protocol, "probe", 12345, "00000000-0000-4000-8000-000000000001", "100")
        digest, different_name_digest = "ab" * 32, "cd" * 32
        backend = Mock()

        def observe(case, config, work, label, server, pid):
            proxy, = config["proxies"]
            if case == "matching-leaf":
                if label.startswith("colon-upper-"):
                    return replace(self.connected, check_ok=False)
                self.assertEqual(proxy["fingerprint"].replace(":", "").lower(), digest)
                return self.connected
            if case == "no-pin":
                self.assertNotIn("fingerprint", proxy)
                return replace(self.rejected, rejection="certificate")
            pin = proxy["fingerprint"].replace(":", "").lower()
            self.assertEqual(pid, "100" if case == "wrong-pin" else "101")
            if case == "wrong-pin":
                self.assertNotEqual(pin, digest)
            else:
                self.assertEqual(pin, different_name_digest if case == "mismatched-name" else digest)
            return self.connected if case == "mismatched-name" else self.rejected

        @contextmanager
        def rotate(work, managed_node, case, original_digest):
            self.assertEqual(managed_node, node)
            self.assertEqual(original_digest, digest)
            yield "101", different_name_digest if case == "mismatched-name" else digest

        backend.observe.side_effect = observe
        with (tempfile.TemporaryDirectory() as root, patch.object(tls, "generate_node", return_value=node),
              patch.object(mihomo, "experimental_proxy", return_value={"name": "probe"}),
              patch.object(mihomo, "leaf_digest", return_value=digest), patch.object(mihomo, "verify_leaf_name"),
              patch.object(mihomo, "alternate_leaf", side_effect=rotate) as alternate):
            results = mihomo.Results(Path(root, "results.jsonl"))
            mihomo.run_protocol(slug, protocol, node.port, None, Path(root, "private"), backend, None, results)
            self.assertEqual(len(results.rows), 21)
            self.assertEqual({row["candidate"] for row in results.rows}, set(mihomo.CANDIDATES))
            self.assertEqual(alternate.call_count, 3)
            self.assertEqual(backend.observe.call_count, 17)
            blocked = [row["evidence"] for row in results.rows if row["candidate"].startswith("colon-upper/")]
            self.assertEqual(blocked, ["check"] + ["positive-control"] * 4)

    def test_missing_downloaded_binary_cannot_pass(self):
        with tempfile.TemporaryDirectory() as root, patch.object(tls, "checked") as command:
            with self.assertRaisesRegex(tls.Failure, "missing-binary"):
                mihomo.Mihomo.prepare(Path(root))
            self.assertEqual(command.call_args.args[0][2:], ["--download-mihomo-only", Path(root)])

    def test_download_only_uses_pinned_gzip_and_rejects_a_bad_digest(self):
        loader = Path(__file__).with_name("external-client-acceptance.sh")
        harness = r'''
set -eu
unset WORK RUNNER_TEMP
expected_archive="$2/mihomo.gz"
curl() {
    local output
    while [[ "$1" != --output ]]; do shift; done
    output=$2
    [[ "$3" == https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1-v1.19.33.gz ]]
    cp "$2.fixture" "$output"
}
if [[ "$3" == mock-digest ]]; then
    sha256sum() {
        [[ "$*" == '--check --strict' ]]
        local digest archive
        read -r digest archive
        [[ "$digest" == 8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524 ]]
        [[ "$archive" == "$expected_archive" ]]
    }
fi
source "$1" --download-mihomo-only "$2"
'''
        for mode, success in (("real-digest", False), ("mock-digest", True)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                work = Path(root)
                (work / "mihomo.gz.fixture").write_bytes(gzip.compress(b"not a real binary"))
                result = subprocess.run(["bash", "-c", harness, "test", loader, work, mode],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, int(not success), result.stderr)
                self.assertEqual({path.name for path in work.iterdir()},
                                 {"mihomo.gz.fixture", "mihomo.gz"} | ({"mihomo"} if success else set()))
                if success:
                    self.assertEqual((work / "mihomo").read_bytes(), b"not a real binary")
                else:
                    self.assertIn("FAILED", result.stdout)

    def test_results_only_write_allowlisted_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "results.jsonl")
            results = mihomo.Results(path)
            results.record("unknown-secret", "unknown-secret", "unknown-secret", "unknown-secret")
            self.assertEqual(json.loads(path.read_text()),
                             {"protocol": "-", "candidate": "-", "verdict": "fail", "evidence": "internal"})


if __name__ == "__main__":
    unittest.main()
