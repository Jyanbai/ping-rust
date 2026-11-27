"""Exercise the legacy install retry policy without downloads or systemd."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("legacy-upgrade.sh")
RATE_LIMIT = (
    "HTTP status client error (403 rate limit exceeded) for url (https://example.com/release)"
)
CLEAN_INSTALL_PATHS = (
    "/usr/local/bin/shoes",
    "/var/lib/ping-rust/shoes-install.json",
    "/etc/shoes",
    "/etc/systemd/system/shoes.service",
)


class LegacyUpgradeTest(unittest.TestCase):
    def check_install(self, outcomes, *, exit_code, rate_limits, trace, residue=""):
        script = SCRIPT.read_text(encoding="utf-8")
        preflight_start = 'test "$(uname -m)" = x86_64\n'
        preflight = script.split(preflight_start, 1)[1].split("export NO_COLOR", 1)[0]
        for path in CLEAN_INSTALL_PATHS:
            preflight = preflight.replace(path, f'"$work{path}"')
        record = script[script.index("record() {"):script.index('record "###')]
        trap = script[script.index("trap 'status="):script.index('for name in "$asset"')]
        functions = script[script.index("run_command() {"):script.index("assert_runtime() {")]
        install_start = script.index("\n}\n", script.index("assert_recorded() {")) + 3
        install = script[install_start:script.index("# The old installer may resolve")]
        harness = """
set -euo pipefail
work=$PWD
summary=${GITHUB_STEP_SUMMARY:?}
old=legacy_cli
fake_attempt=0
residue=$1
legacy_cli() {
  [[ $# == 3 && "$*" == 'install --method release' ]] || return 2
  fake_attempt=$((fake_attempt + 1))
  printf 'install\\n' >> trace
  printf 'attempt %s\\n' "$fake_attempt"
  cat "stderr.$fake_attempt" >&2
  if [[ -n "$residue" ]]; then
    mkdir -p "$(dirname "$residue")"
    touch "$residue"
  fi
  return "$(cat "status.$fake_attempt")"
}
sleep() { printf 'sleep %s\\n' "$1" >> trace; }
"""
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for attempt, (status, stderr) in enumerate(outcomes, 1):
                (work / f"stderr.{attempt}").write_text(stderr, encoding="utf-8")
                (work / f"status.{attempt}").write_text(str(status), encoding="utf-8")
            result = subprocess.run(
                ["bash", "-c", harness + preflight + record + trap + functions + install,
                 "legacy-upgrade-test", residue], cwd=work,
                env={"GITHUB_STEP_SUMMARY": str(work / "summary")},
                capture_output=True, text=True, encoding="utf-8", timeout=10,
            )
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, exit_code, output)
            self.assertEqual((work / "trace").read_text().splitlines(), trace)
            summary = (work / "summary").read_text(encoding="utf-8")
            self.assertEqual(
                [line for line in summary.splitlines() if line.startswith("install-old: attempt=")],
                [f"install-old: attempt={attempt}; rate-limit={limited}"
                 for attempt, limited in enumerate(rate_limits, 1)],
            )
            self.assertEqual(
                (work / "install-old.stdout").read_text(), f"attempt {len(rate_limits)}\n",
            )
            self.assertNotIn("https://example.com/release", output + summary)
            return output

    def test_rate_limit_stops_after_four_attempts(self):
        output = self.check_install(
            [(1, RATE_LIMIT)] * 4, exit_code=1, rate_limits=["true"] * 4,
            trace=["install", "sleep 30", "install", "sleep 60", "install", "sleep 120", "install"],
        )
        self.assertIn("[redacted-link]", output)

    def test_non_rate_limit_failures_do_not_retry(self):
        for stderr in ("403 Forbidden", "429 rate limit exceeded", "1403 rate limit exceeded"):
            with self.subTest(stderr=stderr):
                self.check_install([(1, stderr)], exit_code=1, rate_limits=["false"], trace=["install"])

    def test_second_attempt_succeeds(self):
        self.check_install(
            [(1, RATE_LIMIT), (0, "")], exit_code=0,
            rate_limits=["true", "false"], trace=["install", "sleep 30", "install"],
        )

    def test_non_rate_limit_failure_after_retry_stops(self):
        self.check_install(
            [(1, RATE_LIMIT), (1, "403 Forbidden")], exit_code=1,
            rate_limits=["true", "false"], trace=["install", "sleep 30", "install"],
        )

    def test_rate_limit_does_not_retry_if_install_left_residue(self):
        for path in CLEAN_INSTALL_PATHS:
            residue = path.lstrip("/")
            with self.subTest(residue=residue):
                self.check_install(
                    [(1, RATE_LIMIT)], exit_code=1, rate_limits=["true"],
                    trace=["install"], residue=residue,
                )


if __name__ == "__main__":
    unittest.main()
