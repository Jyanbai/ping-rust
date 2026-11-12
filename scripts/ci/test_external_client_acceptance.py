"""Exercise XHTTP client preparation without external binaries or sockets."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class XhttpClientPreparationTest(unittest.TestCase):
    def test_custom_output_needs_no_managed_state(self):
        script = Path(__file__).with_name("external-client-acceptance.sh").read_text()
        function = script.split("run_xhttp_reality() {", 1)[1].split("\nxhttp_results=()", 1)[0]
        fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/yaml/vless-xhttp-reality/state.json"
        credentials = json.loads(fixture.read_text())["profiles"][0]["credentials"]["VlessXhttpReality"]
        generated = "\n".join([
            "协议：VLESS-XHTTP-REALITY",
            f'UUID：{credentials["user_id"]}',
            f'SNI：{credentials["server_name"]}',
            f'Short ID：{credentials["short_id"]}',
            f'Reality 公钥：{credentials["public_key"]}',
            "传输：XHTTP（path /0123456789abcdef，mode auto）",
        ])
        # Stop at Xray's schema check, before any server/client can start.
        harness = """
set -euo pipefail
PING_RUST=generate_fixture
SHOES=check_fixture
XRAY_26=check_client
generate_fixture() { printf '%s\\n' "$GENERATED"; }
check_fixture() { test "$1" = --dry-run; }
check_client() {
  test "$1" = run && test "$2" = -test && test "$3" = -c || exit 2
  touch "$WORK/client-checked"
  return 1
}
mkdir -p "$WORK/logs"
run_xhttp_reality() {""" + function + """
run_xhttp_reality "$MODE" "$CASE_NAME" 25211
"""
        for mode in ("auto", "packet-up"):
            for case in ("valid", "wrong-short-id", "wrong-path"):
                with self.subTest(mode=mode, case=case), tempfile.TemporaryDirectory() as root:
                    result = subprocess.run(
                        ["bash", "-c", harness], capture_output=True, text=True, timeout=10,
                        env={**os.environ, "WORK": root, "GENERATED": generated,
                             "MODE": mode, "CASE_NAME": case},
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertTrue(Path(root, "client-checked").exists(), result.stderr)
                    self.assertEqual(list(Path(root).rglob("ping-rust-state.json")), [])
                    client = json.loads(Path(root, "logs", f"xhttp-{mode}-{case}-xray.json").read_text())
                    outbound = client["outbounds"][0]
                    self.assertEqual(outbound["settings"]["vnext"][0]["users"], [
                        {"id": credentials["user_id"], "encryption": "none"},
                    ])
                    stream = outbound["streamSettings"]
                    self.assertEqual(stream["network"], "xhttp")
                    self.assertEqual(stream["security"], "reality")
                    reality = stream["realitySettings"]
                    self.assertEqual(reality["serverName"], credentials["server_name"])
                    self.assertEqual(reality["publicKey"], credentials["public_key"])
                    self.assertEqual(reality["password"], credentials["public_key"])
                    expected_short_id = credentials["short_id"]
                    if case == "wrong-short-id":
                        expected_short_id = ("0" if expected_short_id[0] != "0" else "1") + expected_short_id[1:]
                    self.assertEqual(reality["shortId"], expected_short_id)
                    self.assertEqual(stream["xhttpSettings"], {
                        "path": "/0123456789abcdef" + ("-wrong" if case == "wrong-path" else ""),
                        "mode": mode,
                    })
                    self.assertEqual(Path(root, "logs", f"xhttp-{mode}-{case}-xray.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
