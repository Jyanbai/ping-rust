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
CASES = ["self-signed-insecure", "wrong-credentials", "untrusted-certificate"]
SECRET = "injected-secret-must-not-be-public"


class TlsClientAcceptanceTests(unittest.TestCase):
    def test_entry_lists_exact_matrix(self):
        result = subprocess.run(["bash", ENTRY, "--list"], capture_output=True, check=True, text=True)
        self.assertEqual(json.loads(result.stdout), {protocol: CASES for protocol in PROTOCOLS})

    def test_wrap_and_negative_copies(self):
        exported = {"outbounds": [{
            "type": "tuic", "tag": "unique-node", "server": "127.0.0.1", "server_port": 12345,
            "uuid": "00000000-0000-4000-8000-000000000001", "password": SECRET,
            "tls": {"enabled": True, "server_name": "node.example.com", "insecure": True, "alpn": ["h3"]},
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
        connected = acceptance.Observation(curl_code=0, outbound_attempt=True, marker_received=True, origin_hits=1)
        self.assertEqual(acceptance.verdict(CASES[0], connected)[0], 0)
        self.assertNotEqual(acceptance.verdict(CASES[0], replace(connected, origin_hits=0))[0], 0)

    def test_classifies_only_relevant_rejection_signals(self):
        self.assertEqual(acceptance.rejection_signal("tls: x509: certificate signed by unknown authority", ""), "certificate")
        self.assertEqual(acceptance.rejection_signal("authentication error, HTTP status code: 404", ""), "credentials")
        self.assertEqual(acceptance.rejection_signal("Application error 0x1 (remote)", ""), "credentials")
        self.assertEqual(acceptance.rejection_signal("", "curl: (52) Empty reply from server"), "credentials")
        self.assertIsNone(acceptance.rejection_signal("dial tcp: connect: connection refused", ""))
        self.assertIsNone(acceptance.rejection_signal("", "curl: (97) cannot complete SOCKS5 connection"))

    def test_tuic_credentials_require_both_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            config = {"outbounds": [{
                "password": SECRET, "uuid": "00000000-0000-4000-8000-000000000001", "tls": {"insecure": True},
            }]}
            results = acceptance.Results(work / "results.jsonl")
            with (patch.object(acceptance, "managed_export", return_value=(config, "100")),
                  patch.object(acceptance, "probe", side_effect=[
                      (0, "acceptance"), (0, "acceptance"), (1, "request-timeout"), (0, "acceptance"),
                  ]) as probe,
                  patch("builtins.print")):
                acceptance.run_protocol("tuic", acceptance.PROTOCOLS["tuic"], 12345, None,
                                        work / "private", None, None, results)
            self.assertEqual([call.args[3] for call in probe.call_args_list], [
                CASES[0], f"{CASES[1]}-password", f"{CASES[1]}-uuid", f"{CASES[2]}-certificate",
            ])
            self.assertEqual([row["case"] for row in results.rows], CASES)
            self.assertEqual([row["verdict"] for row in results.rows], ["pass", "fail", "pass"])

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
