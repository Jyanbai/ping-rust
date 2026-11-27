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
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

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

    def test_tuic_credentials_require_both_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            config = {"outbounds": [{
                "password": SECRET, "uuid": "00000000-0000-4000-8000-000000000001", "tls": {PIN_FIELD: [PIN]},
            }]}
            results = acceptance.Results(work / "results.jsonl")
            with (patch.object(acceptance, "managed_export", return_value=(config, "100", "profile")),
                  patch.object(acceptance, "different_certificate") as rotate,
                  patch.object(acceptance, "probe", side_effect=[
                      (0, "acceptance"), (0, "acceptance"), (1, "request-timeout"),
                      (0, "acceptance"), (0, "acceptance"),
                  ]) as probe,
                  patch("builtins.print")):
                rotate.return_value.__enter__.return_value = "101"
                acceptance.run_protocol("tuic", acceptance.PROTOCOLS["tuic"], 12345, None,
                                        work / "private", None, None, results)
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
