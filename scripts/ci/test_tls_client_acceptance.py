import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import tls_client_acceptance as acceptance


ENTRY = Path(__file__).with_name("tls-client-acceptance.sh")
PROTOCOLS = ["hysteria2", "tuic", "trojan-tls", "vless-tls", "vless-ws-tls", "vmess-ws-tls", "anytls"]
CASES = ["self-signed-pinned", "wrong-credentials", "untrusted-certificate", "different-key-certificate"]
PIN_FIELD = "certificate_public_key_sha256"
PIN = "D/lae0s9n5SmUSmF60tlNBHKv68taHjTkVQ53Wh8yxo="
SECRET = "injected-secret-must-not-be-public"


class TlsClientAcceptanceTests(unittest.TestCase):
    def test_entry_lists_exact_matrix(self):
        result = subprocess.run(["bash", ENTRY, "--list"], capture_output=True, check=True, text=True)
        self.assertEqual(json.loads(result.stdout), {protocol: CASES for protocol in PROTOCOLS})

    def test_wrap_and_negative_copies(self):
        exported = {"outbounds": [{
            "type": "tuic", "tag": "unique-node", "server": "127.0.0.1", "server_port": 12345,
            "uuid": "00000000-0000-4000-8000-000000000001", "password": SECRET,
            "tls": {"enabled": True, "server_name": "node.example.com", PIN_FIELD: [PIN], "alpn": ["h3"]},
        }]}
        original = copy.deepcopy(exported)
        wrapped = acceptance.wrap_export(exported, 12346)
        self.assertEqual(wrapped["outbounds"], original["outbounds"])
        self.assertEqual(wrapped["route"], {"final": "unique-node"})
        self.assertEqual(wrapped["inbounds"], [{"type": "socks", "listen": "127.0.0.1", "listen_port": 12346}])
        self.assertEqual(acceptance.PROTOCOLS["tuic"].auth_fields, ("password", "uuid"))
        for field in ("password", "uuid", "certificate"):
            with self.subTest(field=field):
                modified = acceptance.negative_copy(wrapped, field)["outbounds"][0]
                expected = copy.deepcopy(original["outbounds"][0])
                if field == "certificate":
                    del expected["tls"][PIN_FIELD]
                    expected["tls"]["insecure"] = False
                else:
                    self.assertNotEqual(modified[field], expected[field])
                    expected[field] = modified[field]
                self.assertEqual(modified, expected)
        self.assertEqual(exported, original)
        self.assertEqual(wrapped["outbounds"], original["outbounds"])

    def test_incomplete_or_duplicate_matrix_is_nonzero(self):
        complete = [
            {"protocol": protocol, "case": case, "verdict": "pass"}
            for protocol in PROTOCOLS for case in CASES
        ]
        self.assertEqual(acceptance.matrix_status(complete), 0)
        self.assertNotEqual(acceptance.matrix_status(complete[:-1]), 0)
        self.assertNotEqual(acceptance.matrix_status(complete[:-1] + complete[:1]), 0)

    def test_probe_rejects_false_positives(self):
        rejected = acceptance.Observation(curl_code=56, outbound_attempt=True, rejection="credentials")
        self.assertEqual(acceptance.verdict(CASES[1], rejected)[0], 0)
        for changes in (
            {"marker_received": True}, {"origin_hits": 1}, {"check_ok": False},
            {"curl_code": 28}, {"client_alive": False}, {"positive_ok": False},
            {"outbound_attempt": False}, {"rejection": None}, {"curl_code": 0},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(acceptance.verdict(CASES[1], replace(rejected, **changes))[0], 0)
        self.assertNotEqual(acceptance.verdict(CASES[2], rejected)[0], 0)
        tls_rejected = replace(rejected, rejection="certificate")
        self.assertEqual(acceptance.verdict(CASES[2], tls_rejected)[0], 0)
        self.assertNotEqual(acceptance.verdict(CASES[3], tls_rejected)[0], 0)
        pin_rejected = replace(rejected, rejection="pin-mismatch")
        self.assertEqual(acceptance.verdict(CASES[3], pin_rejected)[0], 0)
        self.assertNotEqual(acceptance.verdict(CASES[2], pin_rejected)[0], 0)
        for case, observation in zip(CASES[1:], (rejected, tls_rejected, pin_rejected)):
            for changes in ({"marker_received": True}, {"origin_hits": 1}):
                with self.subTest(case=case, changes=changes):
                    self.assertEqual(acceptance.verdict(case, replace(observation, **changes)),
                                     (1, "unexpected-traffic"))
        connected = acceptance.Observation(curl_code=0, outbound_attempt=True, marker_received=True, origin_hits=1)
        self.assertEqual(acceptance.verdict(CASES[0], connected)[0], 0)
        self.assertNotEqual(acceptance.verdict(CASES[0], replace(connected, origin_hits=0))[0], 0)

    def test_classifies_only_relevant_rejection_signals(self):
        self.assertEqual(acceptance.rejection_signal("tls: x509: certificate signed by unknown authority", ""), "certificate")
        self.assertEqual(acceptance.rejection_signal("tls: unmatched certificate public key SHA256", ""), "pin-mismatch")
        self.assertIsNone(acceptance.rejection_signal("certificate public key SHA256 configured", ""))
        self.assertEqual(acceptance.rejection_signal("authentication error, HTTP status code: 404", ""), "credentials")
        self.assertEqual(acceptance.rejection_signal("Application error 0x1 (remote)", ""), "credentials")
        self.assertEqual(acceptance.rejection_signal("", "curl: (52) Empty reply from server"), "credentials")
        self.assertIsNone(acceptance.rejection_signal("dial tcp: connect: connection refused", ""))
        self.assertIsNone(acceptance.rejection_signal("", "curl: (97) cannot complete SOCKS5 connection"))

    def test_recognizes_sing_box_v1_14_2_public_key_rejection(self):
        rejection = acceptance.rejection_signal(
            f"open outbound connection: unrecognized remote public key: {PIN}",
            "curl: (97) cannot complete SOCKS5 connection",
        )
        observation = acceptance.Observation(curl_code=97, outbound_attempt=True, rejection=rejection)
        self.assertEqual(acceptance.verdict(CASES[3], observation), (0, "acceptance"))
        self.assertEqual(acceptance.verdict(CASES[2], observation), (1, "rejection-unconfirmed"))
        self.assertIsNone(acceptance.rejection_signal("unrecognized remote public key: configured", ""))

    def test_wrong_credentials_requires_evidence_beyond_client_disconnect(self):
        for outbound, trace, curl_error in (
            ("trojan", "TLS handshake: EOF", "curl: (52) Empty reply from server"),
            ("vless", "websocket handshake: connection reset by peer", ""),
            ("vmess", "read response header: EOF", ""),
            ("anytls", "connection reset by peer", ""),
            ("tuic", "Application error 0x1 (remote)", ""),
            ("tuic", "Application error 0x0 (remote): auth timeout", ""),
            ("hysteria2", "authentication error: stream 4 canceled by remote", ""),
        ):
            with self.subTest(outbound=outbound, trace=trace):
                rejection = acceptance.sing_box_rejection(outbound, trace, curl_error)
                observed = acceptance.Observation(curl_code=52, outbound_attempt=True, rejection=rejection)
                self.assertEqual(acceptance.verdict(CASES[1], observed), (1, "rejection-unconfirmed"))

    def test_wrong_credentials_accepts_explicit_protocol_rejections(self):
        for outbound, trace in (
            ("hysteria2", "authentication error, HTTP status code: 404"),
            ("hysteria2", "authentication failed, status code: 404"),
            ("tuic", "Application error 0x0 (remote): auth failed"),
            ("tuic", "Application error 0x1 (remote): auth failed"),
        ):
            with self.subTest(outbound=outbound):
                self.assertEqual(acceptance.sing_box_rejection(outbound, trace, ""), "credentials")
        for outbound, message in (
            ("trojan", "Invalid password hash"),
            ("vless", "Unknown user id"),
            ("vmess", "AEAD authentication failed: checksum mismatch"),
            ("anytls", "authentication failed (prefix mismatch)"),
        ):
            with self.subTest(outbound=outbound):
                journal = f'127.0.0.1:12345 finished with error: Custom {{ error: "failed to setup server stream: {message}" }}'
                classifier = acceptance.sing_box_rejection
                self.assertEqual(classifier(outbound, "read: EOF", "", journal), "credentials")
                self.assertIsNone(classifier(outbound, "read: EOF", "", journal.replace("127.0.0.1", "203.0.113.5")))
                self.assertIsNone(classifier(outbound, "read: EOF", "", journal.replace(message, "unexpected EOF")))
                self.assertEqual(classifier(outbound, "x509: certificate signed by unknown authority", "", journal),
                                 "certificate")
        for reason in ("Invalid UUID", "Authentication token mismatch"):
            with self.subTest(reason=reason):
                self.assertEqual(acceptance.sing_box_rejection(
                    "tuic", "", "", f"Connection ended with error: {reason}",
                ), "credentials")
        self.assertIsNone(acceptance.sing_box_rejection(
            "tuic", "", "", "Connection ended with error: authentication timeout",
        ))

    def test_tuic_recognizes_unified_shoes_credential_rejection(self):
        journal = "Connection ended with error: incorrect credentials"
        for outbound, trace, evidence, expected in (
            ("tuic", "read: EOF", journal, (0, "acceptance")),
            ("tuic", "read: EOF", journal + " in configuration", (1, "rejection-unconfirmed")),
            ("tuic", "TLS handshake: EOF", journal, (1, "rejection-unconfirmed")),
            ("trojan", "read: EOF", journal, (1, "rejection-unconfirmed")),
        ):
            with self.subTest(outbound=outbound, trace=trace, evidence=evidence):
                rejection = acceptance.sing_box_rejection(outbound, trace, "", evidence)
                observed = acceptance.Observation(curl_code=52, outbound_attempt=True, rejection=rejection)
                self.assertEqual(acceptance.verdict(CASES[1], observed), expected)

    def test_backend_observations_cannot_bypass_shared_verdict(self):
        rejected = acceptance.Observation(curl_code=52, outbound_attempt=True, rejection="credentials")
        for changes, phase in (
            ({"marker_received": True}, "unexpected-traffic"),
            ({"origin_hits": 1}, "unexpected-traffic"),
            ({"curl_code": 28}, "request-timeout"),
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as root:
                work = Path(root)
                protocol = acceptance.PROTOCOLS["anytls"]
                node = acceptance.ManagedNode("anytls", protocol, "node", 12345, "profile", "100")
                config, wrong_auth, unpinned = object(), object(), object()
                backend = Mock(spec=acceptance.ClientBackend)
                backend.export.return_value = config
                backend.variant.side_effect = [wrong_auth, unpinned]
                backend.observe.side_effect = [
                    acceptance.Observation(curl_code=0, outbound_attempt=True, marker_received=True, origin_hits=1),
                    replace(rejected, **changes), replace(rejected, rejection="certificate"),
                    replace(rejected, rejection="pin-mismatch"),
                ]
                results = acceptance.Results(work / "results.jsonl")
                with (patch.object(acceptance, "generate_node", return_value=node),
                      patch.object(acceptance, "different_certificate") as rotate, patch("builtins.print")):
                    rotate.return_value.__enter__.return_value = "101"
                    acceptance.run_protocol("anytls", protocol, 12345, None, work / "private", backend, None, results)
                backend.export.assert_called_once_with(None, work / "private", node)
                self.assertEqual([call.args for call in backend.variant.call_args_list],
                                 [(config, "password"), (config, "certificate")])
                self.assertEqual([call.args[1] for call in backend.observe.call_args_list],
                                 [config, wrong_auth, unpinned, config])
                self.assertEqual([call.args[-1] for call in backend.observe.call_args_list],
                                 ["100", "100", "100", "101"])
                self.assertEqual([(row["verdict"], row["phase"]) for row in results.rows],
                                 [("pass", "acceptance"), ("fail", phase), ("pass", "acceptance"), ("pass", "acceptance")])

    def test_backend_missing_binary_does_not_run_negative_controls(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            protocol = acceptance.PROTOCOLS["anytls"]
            node = acceptance.ManagedNode("anytls", protocol, "node", 12345, "profile", "100")
            backend = Mock(spec=acceptance.ClientBackend)
            backend.observe.side_effect = acceptance.Failure("missing-binary")
            results = acceptance.Results(work / "results.jsonl")
            with (patch.object(acceptance, "generate_node", return_value=node),
                  patch.object(acceptance, "different_certificate") as rotate, patch("builtins.print")):
                acceptance.run_protocol("anytls", protocol, 12345, None, work / "private", backend, None, results)
            backend.observe.assert_called_once()
            backend.variant.assert_not_called()
            rotate.assert_not_called()
            self.assertEqual([row["verdict"] for row in results.rows], ["fail"] * 4)
            self.assertEqual([row["phase"] for row in results.rows], ["missing-binary"] + ["positive-control"] * 3)

    def test_sing_box_observe_uses_only_current_shoes_pid_and_request_window(self):
        outbound = {"type": "trojan", "tag": "node"}
        dispatch = "outbound/trojan[node]: outbound connection to 127.0.0.1:24860"
        auth_error = '127.0.0.1:12345 finished with error: Custom { error: "failed to setup server stream: Invalid password hash" }'
        for trace, journal, curl_code, expect_journal, expected in (
            (dispatch, auth_error, 52, True, (0, "acceptance")),
            (f"{dispatch}\nread: EOF", "", 52, True, (1, "rejection-unconfirmed")),
            (f"{dispatch}\nTLS handshake: EOF", auth_error, 52, False, (1, "rejection-unconfirmed")),
            ("read: EOF", auth_error, 52, False, (1, "rejection-unconfirmed")),
            (f"{dispatch}\nread: EOF", auth_error, 28, False, (1, "request-timeout")),
        ):
            with self.subTest(trace=trace, journal=bool(journal), curl_code=curl_code), tempfile.TemporaryDirectory() as root:
                work = Path(root)
                backend = acceptance.SingBox(work / "sing-box")
                server = SimpleNamespace(hits=[])
                client = Mock(pid=101)
                client.poll.return_value = None

                @contextmanager
                def running_client(args, log, env):
                    self.assertEqual(args, [backend.binary, "run", "-c", work / "auth.json"])
                    log.write_text(trace)
                    yield client

                with (patch.object(acceptance, "running_client", side_effect=running_client),
                      patch.object(acceptance, "require_free_ports"), patch.object(acceptance, "wait_port"),
                      patch.object(acceptance, "service_pid", return_value="100") as service_pid,
                      patch.object(acceptance.time, "time", return_value=12345.5),
                      patch.object(acceptance, "checked", side_effect=["", "", journal]) as checked,
                      patch.object(acceptance, "command", side_effect=[
                          subprocess.CompletedProcess([], 0, "", ""),
                          subprocess.CompletedProcess([], curl_code, "", ""),
                      ]) as command):
                    observed = backend.observe(CASES[1], {"outbounds": [outbound]}, work, "auth", server, "100")
                self.assertEqual(acceptance.verdict(CASES[1], observed), expected)
                self.assertEqual(service_pid.call_count, 2)
                self.assertEqual(command.call_args_list[0].args[0], [backend.binary, "check", "-c", work / "auth.json"])
                if expect_journal:
                    checked.assert_called_with(["sudo", "-n", "journalctl", "--boot", "--unit", "shoes.service",
                                                "_PID=100", "--since", "@12345.500000", "--output=cat", "--no-pager"],
                                               "rejection-unconfirmed")
                else:
                    checked.assert_called_once_with(["sudo", "-n", "journalctl", "--sync"], "rejection-unconfirmed")

    def test_sing_box_export_requires_exact_independent_pin(self):
        protocol = acceptance.PROTOCOLS["anytls"]
        profile = "00000000-0000-4000-8000-000000000001"
        node = acceptance.ManagedNode("anytls", protocol, "node", 12345, profile, "100")
        path = Path("private")
        backend = acceptance.SingBox(Path("sing-box"))
        for pins, valid in (([PIN], True), ([], False), ([PIN, PIN], False), (["different"], False)):
            with self.subTest(pins=pins):
                exported = {"outbounds": [{
                    "type": "anytls", "tag": "node", "server": "127.0.0.1", "server_port": 12345,
                    "password": SECRET, "tls": {"enabled": True, "server_name": "node.example.com", PIN_FIELD: pins},
                }]}
                with (patch.object(acceptance, "checked", return_value=json.dumps(exported)) as command,
                      patch.object(acceptance, "public_key_pin", return_value=PIN) as read_pin):
                    if valid:
                        self.assertEqual(backend.export("ping-rust", path, node)["outbounds"], exported["outbounds"])
                    else:
                        with self.assertRaisesRegex(acceptance.Failure, "export"):
                            backend.export("ping-rust", path, node)
                read_pin.assert_called_once_with(Path("/etc/shoes/cert-00000000.pem"), "export")
                command.assert_called_once_with(["sudo", "-n", "ping-rust", "export", "sing-box", "--profile", profile,
                                                 "--server", "127.0.0.1"], "export", log=path / "export")

    def test_tuic_credentials_require_both_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            config = {"outbounds": [{
                "password": SECRET, "uuid": "00000000-0000-4000-8000-000000000001", "tls": {PIN_FIELD: [PIN]},
            }]}
            results = acceptance.Results(work / "results.jsonl")
            protocol = acceptance.PROTOCOLS["tuic"]
            node = acceptance.ManagedNode("tuic", protocol, "node", 12345, "profile", "100")
            backend = Mock(spec=acceptance.ClientBackend)
            backend.export.return_value = config
            backend.variant.side_effect = acceptance.negative_copy
            rejected = acceptance.Observation(curl_code=97, outbound_attempt=True, rejection="credentials")
            backend.observe.side_effect = [
                acceptance.Observation(curl_code=0, outbound_attempt=True, marker_received=True, origin_hits=1),
                rejected, replace(rejected, curl_code=28),
                replace(rejected, rejection="certificate"), replace(rejected, rejection="pin-mismatch"),
            ]
            probe = backend.observe
            with (patch.object(acceptance, "generate_node", return_value=node),
                  patch.object(acceptance, "different_certificate") as rotate,
                  patch("builtins.print")):
                rotate.return_value.__enter__.return_value = "101"
                acceptance.run_protocol("tuic", acceptance.PROTOCOLS["tuic"], 12345, None,
                                        work / "private", backend, None, results)
            self.assertEqual([call.args[3] for call in probe.call_args_list], [
                CASES[0], f"{CASES[1]}-password", f"{CASES[1]}-uuid", f"{CASES[2]}-certificate", CASES[3],
            ])
            self.assertEqual(probe.call_args.args[1], config)
            self.assertEqual(probe.call_args.args[-1], "101")
            rotate.assert_called_once_with(work / "private", "profile", acceptance.PROTOCOLS["tuic"], 12345)
            self.assertEqual([row["case"] for row in results.rows], CASES)
            self.assertEqual([row["verdict"] for row in results.rows], ["pass", "fail", "pass", "pass"])

    def test_different_certificate_restores_original_when_probe_fails(self):
        checked = acceptance.checked

        def local_command(args, phase, **kwargs):
            if tuple(args[:2]) == acceptance.SUDO:
                args = args[2:]
            if args[0] == "systemctl":
                return ""
            return checked(args, phase, **kwargs)

        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            profile = "00000000-0000-4000-8000-000000000001"
            with (patch.object(acceptance, "CONFIG_DIR", work),
                  patch.object(acceptance, "checked", side_effect=local_command),
                  patch.object(acceptance, "service_pid", return_value="101"),
                  patch.object(acceptance, "wait_port") as wait_port):
                cert, key = acceptance.certificate_files(profile)
                fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/tls/self-signed.pem"
                cert.write_bytes(fixture.read_bytes())
                key.write_text("test-only original key placeholder")
                self.assertEqual(acceptance.public_key_pin(cert, "export"), PIN)
                with self.assertRaisesRegex(acceptance.Failure, "request"):
                    with acceptance.different_certificate(work, profile, acceptance.PROTOCOLS["tuic"], 12345) as pid:
                        self.assertEqual(pid, "101")
                        self.assertNotEqual(acceptance.public_key_pin(cert, "export"), PIN)
                        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                        raise acceptance.Failure("request")
                wait_port.assert_called_once_with("udp", 12345, "101", "server-ready", privileged=True)
                self.assertEqual(cert.read_bytes(), fixture.read_bytes())
                self.assertEqual(key.read_text(), "test-only original key placeholder")
                self.assertEqual(list(work.glob("*.pin-test-original")), [])

    def test_command_logs_are_private_and_public_labels_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            results = acceptance.Results(work / "results.jsonl")
            with self.assertRaisesRegex(acceptance.Failure, "check"):
                acceptance.checked([sys.executable, "-c", f"import sys; sys.exit({SECRET!r})"],
                                   "check", log=work / "private")
            self.assertIn(SECRET, (work / "private.stderr").read_text())
            with patch("builtins.print") as public_log:
                results.record(SECRET, SECRET, SECRET, 0, 1)
            self.assertNotIn(SECRET, (work / "results.jsonl").read_text())
            self.assertNotIn(SECRET, public_log.call_args.args[0])

    def test_listener_must_belong_to_expected_process(self):
        listing = "udp UNCONN 0 0 0.0.0.0:12345 0.0.0.0:* users:((\"shoes\",pid=100,fd=10))\n"
        with patch.object(acceptance, "checked", return_value=listing):
            acceptance.wait_port("udp", 12345, "100", "server-ready", privileged=True)
            with self.assertRaisesRegex(acceptance.Failure, "port-conflict"):
                acceptance.wait_port("udp", 12345, "101", "server-ready", privileged=True)
            with self.assertRaisesRegex(acceptance.Failure, "port-conflict"):
                acceptance.require_free_ports({12345})

    def test_restart_overlap_with_old_listener_is_not_a_conflict(self):
        both = ("udp UNCONN 0 0 0.0.0.0:12345 0.0.0.0:* users:((\"shoes\",pid=100,fd=10))\n"
                "udp UNCONN 0 0 0.0.0.0:12345 0.0.0.0:* users:((\"shoes\",pid=101,fd=10))\n")
        new_only = "udp UNCONN 0 0 0.0.0.0:12345 0.0.0.0:* users:((\"shoes\",pid=101,fd=10))\n"
        with patch.object(acceptance, "checked", side_effect=[both, both, new_only]) as listing, \
                patch.object(acceptance.time, "sleep"):
            acceptance.wait_port("udp", 12345, "101", "server-ready", privileged=True)
        self.assertEqual(listing.call_count, 3)

    def test_download_verifies_digest_before_extracting_binary(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            archive = work / "shoes.tar.gz"
            sample = b"test payload"
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo("./shoes")
                entry.size = len(sample)
                bundle.addfile(entry, io.BytesIO(sample))
            with patch.object(acceptance, "checked"):
                with self.assertRaisesRegex(acceptance.Failure, "download-shoes"):
                    acceptance.download(work, "shoes", "test", "shoes", "0" * 64)
                self.assertFalse((work / "shoes").exists())
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                binary = acceptance.download(work, "shoes", "test", "shoes", digest)
            self.assertEqual(binary.read_bytes(), sample)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)

    def test_missing_binary_is_nonzero_and_public_output_is_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            result = subprocess.run(
                ["bash", ENTRY], capture_output=True, text=True, timeout=10,
                env={**os.environ, "PING_RUST": str(root / SECRET),
                     "TLS_ACCEPTANCE_PRIVATE_DIR": str(root / "private"),
                     "TLS_ACCEPTANCE_RESULTS_DIR": str(root / "results")},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list((root / "results").iterdir()), [root / "results/results.jsonl"])
            public = (root / "results/results.jsonl").read_text()
            self.assertNotIn(SECRET, public + result.stdout + result.stderr)
            record = json.loads(public)
            self.assertEqual(record["phase"], "missing-binary")
            self.assertEqual(record["verdict"], "fail")
            self.assertEqual(set(record), {"protocol", "case", "shoes_version", "sing_box_version", "phase", "elapsed_ms", "verdict"})
            self.assertEqual((root / "private").stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
