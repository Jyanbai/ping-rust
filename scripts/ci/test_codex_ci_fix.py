"""Codex CI Fix 汇总失败日志时，摘录不能因为 gh 拒绝输出带颜色的日志而变空。

runner 上的新版 gh 读 Actions 日志时，不加 --allow-escape-sequences 就报
"the response contains terminal escape sequences" 并退出（main-watch 的 run 42617338982 实测；
codex-ci-fix 的 dry-run 42636341128 里每个 job 都只剩"（日志下载失败）"）。

1. 直接运行 workflow 里 "Collect failures and dispatch Codex" 步骤的脚本（dry-run），用假 gh
   模拟新版 gh 的行为，检查任务描述里有报错前的日志；
2. job_log_excerpt.py 的下载失败说明、代码块转义。

需要 bash 和 jq；不访问网络：python3 scripts/ci/test_codex_ci_fix.py
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import job_log_excerpt as jle  # noqa: E402
import main_watch as mw  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "codex-ci-fix.yml"
STEP_NAME = "Collect failures and dispatch Codex"
REPO = "Jyanbai/ping-rust"
OWNER = "Jyanbai"
BRANCH = "codex/issue-1-1"
SHA = "0" * 39 + "1"
TS = "2026-11-03T15:40:01.1234567Z "
ESCAPE_REFUSAL = "the response contains terminal escape sequences; pass --allow-escape-sequences to output it anyway"

# 模拟 runner 上的新版 gh：读日志时不带 --allow-escape-sequences 就拒绝。--jq 交给真的 jq。
FAKE_GH = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DIR/calls.log"
[ "$1" = api ] || { echo "unexpected gh call: $*" >&2; exit 9; }
shift
path='' jq_expr='' allow=0
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --jq) jq_expr="$2"; shift ;;
    -X) shift ;;
    --allow-escape-sequences) allow=1 ;;
    -*) echo "unexpected flag: $1" >&2; exit 9 ;;
    *) path="$1" ;;
  esac
  shift
done
emit() { if [ -n "$jq_expr" ]; then jq -r "$jq_expr" "$1"; else cat "$1"; fi; }
case "$path" in
  "repos/$REPO/pulls?"*) emit "$FAKE_DIR/pulls.json" ;;
  "repos/$REPO/actions/runs?head_sha="*) emit "$FAKE_DIR/runs.json" ;;
  "repos/$REPO/issues/"*"/comments?"*) emit "$FAKE_DIR/comments.json" ;;
  "repos/$REPO/actions/runs/"*"/jobs?"*) emit "$FAKE_DIR/jobs.json" ;;
  "repos/$REPO/actions/jobs/"*"/logs")
    if [ "$allow" != 1 ]; then
      echo "$ESCAPE_REFUSAL" >&2
      exit 1
    fi
    cat "$FAKE_DIR/job.log" ;;
  *) echo "unexpected gh path: $path" >&2; exit 9 ;;
esac
"""

# 按真实 CI 日志的格式：BOM、时间戳、青色脚本回显、##[group]/##[endgroup]、##[error]。
JOB_LOG = "﻿" + "".join(
    TS + line + "\n"
    for line in [
        "##[group]Run cargo test --locked",
        "\x1b[36;1mcargo test --locked\x1b[0m",
        "##[endgroup]",
        "running 3 tests",
        "test config::tests::keeps_port ... \x1b[31mFAILED\x1b[0m",
        "thread 'config::tests::keeps_port' panicked at src/config.rs:10:5:",
        "assertion `left == right` failed",
        "##[error]Process completed with exit code 101.",
        "##[group]Run actions/upload-artifact",
        "after the error",
    ]
)


def step_script(name):
    """取出 workflow 里指定步骤的 run 脚本（不依赖 PyYAML）。"""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


class WorkflowDryRunTest(unittest.TestCase):
    def run_step(self):
        # Ubuntu 22.04 自带 Python 3.10，没有 TestCase.enterContext。
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        fake = work / "fake"
        bin_dir = work / "bin"
        runner_temp = work / "runner-temp"
        for directory in (fake, bin_dir, runner_temp):
            directory.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)
        (fake / "pulls.json").write_text(
            json.dumps([{"number": 7, "head": {"sha": SHA}, "labels": []}]), encoding="utf-8"
        )
        (fake / "runs.json").write_text(
            json.dumps(
                {
                    "workflow_runs": [
                        {
                            "id": 11,
                            "name": "CI",
                            "event": "pull_request",
                            "status": "completed",
                            "conclusion": "failure",
                            "created_at": "2026-11-03T15:38:30Z",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (fake / "comments.json").write_text("[]", encoding="utf-8")
        (fake / "jobs.json").write_text(
            json.dumps(
                {
                    "jobs": [
                        {
                            "id": 22,
                            "name": "AlmaLinux 9",
                            "conclusion": "failure",
                            "steps": [{"name": "Unit and integration tests", "conclusion": "failure"}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (fake / "job.log").write_text(JOB_LOG, encoding="utf-8")
        env = dict(
            os.environ,
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            FAKE_DIR=str(fake),
            ESCAPE_REFUSAL=ESCAPE_REFUSAL,
            GH_TOKEN="test-token",
            REPO=REPO,
            OWNER=OWNER,
            BRANCH=BRANCH,
            INPUT_SHA=SHA,
            DRY_RUN="1",
            MAX_ATTEMPTS="2",
            RUN_URL=f"https://github.com/{REPO}/actions/runs/1",
            WATCHED="CI",
            EXCERPT_LINES="60",
            PROMPT_LIMIT="20000",
            RUNNER_TEMP=str(runner_temp),
        )
        env.pop("GITHUB_STEP_SUMMARY", None)
        result = subprocess.run(
            ["bash", "-c", step_script(STEP_NAME)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        calls = (fake / "calls.log").read_text(encoding="utf-8")
        return result, calls

    def test_dry_run_prompt_contains_log_excerpt_despite_escape_sequences(self):
        result, calls = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = result.stdout
        self.assertIn("[dry-run] 会在 PR #7 派发第 1/2 次", prompt)
        self.assertIn("- CI / AlmaLinux 9（失败步骤：Unit and integration tests）", prompt)
        self.assertNotIn("日志下载失败", prompt)
        self.assertIn("### CI / AlmaLinux 9", prompt)
        self.assertIn("thread 'config::tests::keeps_port' panicked at src/config.rs:10:5:", prompt)
        self.assertIn("test config::tests::keeps_port ... FAILED", prompt)
        self.assertIn("##[error]Process completed with exit code 101.", prompt)
        self.assertNotIn("after the error", prompt)
        self.assertNotIn("\x1b", prompt)
        self.assertNotIn("2026-11-03T15:40:01", prompt)
        self.assertIn("--allow-escape-sequences", calls)

    def test_dry_run_prompt_requires_regression_test_on_same_pr(self):
        result, _ = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = result.stdout
        self.assertIn("不删除、不放宽已有断言", prompt)
        self.assertIn("先补能在修复前失败的回归测试再改代码", prompt)
        self.assertIn("只修同一个 PR", prompt)


class ExcerptSectionTest(unittest.TestCase):
    class FakeGh:
        def __init__(self, log=None, error=None):
            self.log, self.error, self.paths = log, error, []

        def get_text(self, path):
            self.paths.append(path)
            if self.error:
                raise mw.GitHubError(self.error)
            return self.log

    def test_download_failure_keeps_reason(self):
        gh = self.FakeGh(error="GET repos/a/b/actions/jobs/5/logs 失败：gh: Not Found (HTTP 404)")
        out = io.StringIO()
        self.assertEqual(jle.main(["--repo", "a/b", "--job-id", "5", "--title", "CI / x"], gh=gh, stream=out), 0)
        self.assertEqual(gh.paths, ["repos/a/b/actions/jobs/5/logs"])
        self.assertIn("### CI / x", out.getvalue())
        self.assertIn("（日志下载失败：GET repos/a/b/actions/jobs/5/logs 失败：gh: Not Found (HTTP 404)）", out.getvalue())

    def test_log_text_cannot_escape_code_block(self):
        log = "".join(TS + line + "\n" for line in ["##[group]Run x", "```", "echo hi", "##[error]boom"])
        section = jle.excerpt_section(self.FakeGh(log=log), "a/b", "5", "CI / `x`", 60)
        self.assertIn("### CI / 'x'", section)
        self.assertIn("````text\n", section)
        self.assertTrue(section.endswith("\n````\n"))

    def test_limit_and_redaction_follow_main_watch(self):
        log = "".join(TS + line + "\n" for line in ["##[group]Run x", *[f"line {i}" for i in range(10)],
                                                     "connect 198.51.100.7 vs 8.8.8.8", "##[error]boom"])
        section = jle.excerpt_section(self.FakeGh(log=log), "a/b", "5", "t", 3)
        self.assertNotIn("line 7", section)
        self.assertIn("line 8", section)
        self.assertIn("line 9", section)
        self.assertIn("[redacted-address]", section)
        self.assertNotIn("8.8.8.8", section)

    def test_rejects_bad_arguments(self):
        err = io.StringIO()
        sys.stderr, saved = err, sys.stderr
        try:
            self.assertEqual(jle.main(["--repo", "bad", "--job-id", "5", "--title", "t"], gh=self.FakeGh()), 2)
            self.assertEqual(jle.main(["--repo", "a/b", "--job-id", "5;x", "--title", "t"], gh=self.FakeGh()), 2)
        finally:
            sys.stderr = saved


if __name__ == "__main__":
    unittest.main()
