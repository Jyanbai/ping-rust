"""Exercise the legacy CLI contracts without downloads, shoes or systemd."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("socks5-secure-acceptance.sh")


class Socks5SecureAcceptanceTest(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)

    def run_section(self, start, end, setup):
        script = SCRIPT.read_text(encoding="utf-8")
        run_command = script[script.index("run_command() {"):script.index("main_pid()")]
        section = script[script.index(start):script.index(end, script.index(start))]
        harness = """
set -euo pipefail
work=$PWD
auth_node=legacy-socks-auth
auth_port=24451
local_node=legacy-socks-local
local_port=24452
record() { printf '%s\\n' "$*"; }
"""
        return subprocess.run(
            ["bash", "-c", harness + run_command + setup + section], cwd=self.work,
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )

    def test_v032_creates_both_nodes_with_generate(self):
        result = self.run_section('for spec in "$auth_node:', "\nassert_active", """
old=legacy_cli
legacy_cli() {
  [[ $# == 7 && "$1 $2 $3 $4 $6" == 'generate socks5 --no-auth --name --port' ]] || return 2
  printf '%s:%s\\n' "$5" "$7" >> calls
}
""")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.work / "calls").read_text().splitlines(), [
            "legacy-socks-auth:24451", "legacy-socks-local:24452",
        ])

    def test_v021_info_credentials_must_match_state(self):
        username, password = "fixture-user", "fixture-password"
        (self.work / "state.json").write_text(json.dumps({"profiles": [{
            "name": "legacy-socks-auth",
            "credentials": {"Socks5": {"username": username, "password": password}},
        }]}), encoding="utf-8")
        compat = self.work / "compat" / "ping-rust"
        compat.parent.mkdir()
        compat.write_text('''#!/usr/bin/env bash
test "$1" = info || exit 2
if [[ "$2" == legacy-socks-auth ]]; then cat info; fi
''', encoding="utf-8")
        compat.chmod(0o700)
        for output, expected in (
            (f"  用户名：{username}\n  密码：{password}\n", 0),
            (f"  用户名：{username}-other\n  密码：{password}\n", 1),
            (f"  用户名：{username}\n  密码：{password}-other\n", 1),
            (f"  用户名：{username}\n", 1),
        ):
            with self.subTest(expected=expected, lines=len(output.splitlines())):
                (self.work / "info").write_text(output, encoding="utf-8")
                result = self.run_section('fetch_release "$compat_tag"', '\nrecord "SOCKS5', """
compat_tag=v0.2.1
state_file=$work/state.json
fetch_release() { :; }
""")
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertNotIn(username, result.stdout + result.stderr)
                self.assertNotIn(password, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
