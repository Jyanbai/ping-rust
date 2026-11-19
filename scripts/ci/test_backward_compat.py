"""Check the inline SOCKS5 menu driver's decoding without shoes or a PTY."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class Socks5MenuEncodingTest(unittest.TestCase):
    def test_inline_driver_matches_utf8_prompt_with_c_or_utf8_parent_locale(self):
        script = Path(__file__).with_name("backward-compat.sh").read_text(encoding="utf-8")
        function = script.split("edit_anonymous_socks5_address() {", 1)[1].split("\nTCL\n}", 1)[0] + "\nTCL"
        # Tcl uses the same stdin decoding as inline Expect. Unicode escapes keep
        # the expected characters independent of the probe file's own decoding.
        # Stop at the first match: no menu process, sockets or system files.
        probe = r'''
proc log_user {args} {}
proc spawn {args} {}
proc expect {args} {
    set pattern [uplevel 1 {set pattern}]
    set prompt "\u8bf7\u9009\u62e9 \u005b0-10\u005d: "
    if {![regexp -- $pattern $prompt]} {
        puts stderr "inline driver did not decode the Chinese menu prompt as UTF-8"
        exit 1
    }
    set results [list "\u5148\u542f\u7528\u8ba4\u8bc1" "\u914d\u7f6e\u66f4\u6539\u6210\u529f\u3002"]
    if {$::env(SOCKS5_EDIT_RESULT) ni $results} {
        puts stderr "inline driver did not decode the Chinese result environment as UTF-8"
        exit 1
    }
    exit 0
}
eval [read stdin]
'''
        harness = r'''
set -euo pipefail
NEW=unused
socks5_index=5
expect() { tclsh "$TCL_PROBE"; }
edit_anonymous_socks5_address() {''' + function + r'''
}
edit_anonymous_socks5_address "$ADDRESS" "$RESULT"
'''
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "probe.tcl")
            path.write_text(probe, encoding="utf-8")
            for locale in ("C", "C.UTF-8"):
                for address, expected in (
                    ("203.0.113.10", "先启用认证"),
                    ("127.0.0.2", "配置更改成功。"),
                ):
                    with self.subTest(locale=locale, result=expected):
                        result = subprocess.run(
                            ["bash", "-c", harness], capture_output=True, timeout=10,
                            env={**os.environ, "LANG": locale, "LC_ALL": locale,
                                 "TCL_PROBE": str(path), "ADDRESS": address,
                                 "RESULT": expected},
                        )
                        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
