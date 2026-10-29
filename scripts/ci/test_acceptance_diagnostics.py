import secrets
import unittest
import tempfile
import json
import contextlib
import importlib.util
import io
import os
import subprocess
from unittest.mock import patch
from pathlib import Path

from acceptance_diagnostics import failure_summary, preserve_failure_stderr
from harness_diagnostics import failure_details


class FailureDiagnosticsTest(unittest.TestCase):
    def test_source_matrix_socks_generation_failure_prints_stderr(self):
        spec = importlib.util.spec_from_file_location(
            "source_matrix", Path(__file__).with_name("shoes-source-matrix.py"))
        matrix = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(matrix)

        def run(command, **kwargs):
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, "test runtime", "")
            if command[2] == "socks5":
                return subprocess.CompletedProcess(
                    command, 1, b"", f"SOCKS generation cause: {matrix.h2.SOCKS_PASSWORD}".encode())
            return subprocess.CompletedProcess(command, 0, b"", b"")

        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as root, \
                patch.dict(os.environ, {"SHOES_BIN": "shoes", "PING_RUST_BIN": "ping-rust"}), \
                patch("sys.argv", ["matrix", "--source", "verified-pin", "--output", str(Path(root) / "out.json")]), \
                patch.object(matrix.subprocess, "run", side_effect=run), \
                patch.object(matrix, "dry_run", return_value=0), \
                patch.object(matrix.h2, "free_port", return_value=12345), \
                contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(AssertionError, "socks5: generation failed"):
                matrix.main()
        self.assertIn("SOCKS generation cause", stderr.getvalue())
        self.assertNotIn(matrix.h2.SOCKS_PASSWORD, stderr.getvalue())

    def test_harness_redacts_json_strings_and_multiline_yaml_keys(self):
        secret = secrets.token_urlsafe(32) + ",suffix"
        config = json.dumps([{"protocol": {"password": secret, "type": "socks"}}])
        details = failure_details(f"rejected {secret}", config)
        self.assertNotIn(secret, details)
        self.assertNotIn("suffix", details)
        self.assertIn("socks", details)
        key = secrets.token_urlsafe(32)
        config = f"protocol:\n  private_key: |\n    {key}\n  type: reality\n"
        details = failure_details(f"invalid key {key}", config)
        self.assertNotIn(key, details)
        self.assertIn("reality", details)

    def test_harness_details_keep_cause_and_redact_before_truncation(self):
        secret = secrets.token_urlsafe(32)
        config = f"protocol:\n  type: socks\n  password: {secret}\n"
        details = failure_details(f"schema rejected: {secret}\n" + "x" * 20000, config)
        self.assertIn("schema rejected", details)
        self.assertIn("type: socks", details)
        self.assertIn("[REDACTED]", details)
        self.assertIn("[truncated]", details)
        self.assertNotIn(secret, details)
        self.assertLess(len(details), 18000)

    def test_stderr_is_preserved_privately_and_artifact_is_allowlisted(self):
        private = secrets.token_urlsafe(32)
        stderr = f"Error: GitHub API 网络请求失败\nHTTP status 403\nprivate credential: {private}\n"
        with tempfile.TemporaryDirectory() as root:
            preserve_failure_stderr(Path(root), "bootstrap", stderr, 1)
            self.assertEqual((Path(root) / "private" / "bootstrap.stderr").read_text(encoding="utf-8"), stderr)
            artifact = (Path(root) / "redacted" / "bootstrap.stderr.log").read_text(encoding="utf-8")
            self.assertIn("GitHub API 网络请求失败", artifact)
            self.assertIn("HTTP 403", artifact)
            self.assertIn("line 3", artifact)
            self.assertNotIn(private, artifact)

    def test_http_status_and_operation_survive_without_private_output(self):
        private = secrets.token_urlsafe(32)
        text = f"Error: shoes 安装失败，原二进制状态已恢复\nCaused by:\nGitHub Release API 返回错误\nHTTP status client error (403 Forbidden) for url (https://api.github.com/repos/cfal/shoes/releases/latest?token={private})"
        self.assertEqual(failure_summary(text), "shoes 安装失败，原二进制状态已恢复; GitHub Release API 返回错误; HTTP 403")
        self.assertNotIn(private, failure_summary(text))

    def test_transient_transport_failure(self):
        self.assertEqual(failure_summary("请求 shoes 最新 Release 失败: operation timed out"), "请求 shoes 最新 Release 失败; operation timed out")

    def test_unknown_output_is_never_echoed(self):
        self.assertEqual(failure_summary(secrets.token_hex(64)), "cause unavailable; private output suppressed")


if __name__ == "__main__":
    unittest.main()
