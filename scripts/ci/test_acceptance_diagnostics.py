import secrets
import unittest

from acceptance_diagnostics import failure_summary


class FailureDiagnosticsTest(unittest.TestCase):
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
