"""直接执行 Codex 审查 workflow 的脚本，验证准入、去重、脱敏和过期提交处理。

只使用临时目录和假 gh，不联网、不调用模型：python3 scripts/ci/test_codex_review.py
"""

import copy
import io
import json
import os
import re
import subprocess
import tempfile
import tarfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/codex-code-review.yml"
REPO = "owner/example"
HEAD = "a" * 40
BASE = "b" * 40
READ_CHECK = "e" * 64
MARKER = f"<!-- codex-review sha={HEAD} base={BASE} status=complete -->"
PR = {
    "number": 7,
    "state": "open",
    "draft": False,
    "user": {"login": "owner"},
    "author_association": "OWNER",
    "head": {"sha": HEAD, "repo": {"full_name": REPO}},
    "base": {"sha": BASE, "ref": "main"},
    "title": "修复一个问题",
    "body": "只改要求的行为",
    "labels": [],
}

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a") as log:
    log.write(json.dumps(args) + "\n")
assert args[0] == "api", args
route = args[1]
if "--input" in args:
    Path(os.environ["FAKE_POST"]).write_text(
        Path(args[args.index("--input") + 1]).read_text())
    print('{"id": 123}')
    sys.exit(0)
data = json.loads(Path(os.environ["FAKE_API"]).read_text())[route]
payload = json.dumps(data)
if "--jq" in args:
    result = subprocess.run(["jq", "-r", args[args.index("--jq") + 1]],
                            input=payload, text=True, check=True, capture_output=True)
    print(result.stdout, end="")
else:
    print(payload)
'''


def step_script(name, workflow=WORKFLOW):
    lines = workflow.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


class WorkflowMigrationTest(unittest.TestCase):
    def test_codex_replaces_claude(self):
        self.assertTrue(WORKFLOW.is_file(), "缺少 Codex 自动审查 workflow")
        self.assertFalse((ROOT / ".github/workflows/claude-code-review.yml").exists())
        self.assertFalse((ROOT / ".github/workflows/claude.yml").exists())

    def test_review_workflow_runs_trusted_code_and_has_no_push_permission(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_run:", workflow)
        self.assertIn("workflows: [CI]", workflow)
        self.assertIn("environment: codex", workflow)
        self.assertIn("ref: main", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("actions: write", workflow)
        for action in re.findall(r"uses: (\S+)", workflow):
            self.assertRegex(action, r"@\w{40}$")

    def test_inline_shell_scripts_parse(self):
        for name in (
            "Select PR", "Install pinned Codex CLI", "Restore review auth",
            "Verify read-only sandbox", "Run Codex review", "Render review", "Publish review",
            "Persist refreshed auth", "Queue review fixes", "Report review failure", "Remove local credentials",
        ):
            with self.subTest(step=name):
                result = subprocess.run(
                    ["bash", "-n", "-c", step_script(name)],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


class ReviewScriptsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)
        self.api = {
            f"repos/{REPO}/pulls/7": copy.deepcopy(PR),
            f"repos/{REPO}/commits/{HEAD}/pulls": [copy.deepcopy(PR)],
            f"repos/{REPO}/issues/7/comments": [],
        }
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.work),
            "GITHUB_WORKSPACE": str(self.work / "workspace"),
            "GITHUB_OUTPUT": str(self.work / "output"),
            "GITHUB_STEP_SUMMARY": str(self.work / "summary"),
            "GITHUB_EVENT_PATH": str(self.work / "event.json"),
            "REPO": REPO,
            "OWNER": "owner",
            "EVENT_NAME": "workflow_run",
            "EVENT_SHA": HEAD,
            "PR_INPUT": "",
            "NUMBER": "7",
            "HEAD_SHA": HEAD,
            "BASE_SHA": BASE,
            "RUN_URL": "https://example.com/run/1",
            "FAKE_API": str(self.work / "api.json"),
            "FAKE_GH_LOG": str(self.work / "gh.log"),
            "FAKE_POST": str(self.work / "posted.json"),
            "CODEX_HOME": str(self.work / "codex-home"),
            "MAX_ATTEMPTS": "2",
        }
        (self.work / "codex-home").mkdir()
        (self.work / "workspace").mkdir()
        (self.work / "workspace/review-read-check.txt").write_text(READ_CHECK)
        self.write_event()

    def write_event(self, **overrides):
        run = {"event": "pull_request", "head_repository": {"full_name": REPO}}
        run.update(overrides)
        (self.work / "event.json").write_text(json.dumps({"workflow_run": run}))

    def run_step(self, name):
        (self.work / "api.json").write_text(json.dumps(self.api))
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step_script(name)],
            env=self.env, text=True, capture_output=True, check=False,
        )

    def mock_command(self, name, script):
        path = self.work / "bin" / name
        path.write_text("#!/usr/bin/env bash\n" + script, encoding="utf-8")
        path.chmod(0o755)

    def output(self):
        path = self.work / "output"
        return path.read_text() if path.exists() else ""

    def prepare_review(self, text="未发现有充分证据的代码问题。", tokens=(), findings=()):
        (self.work / "review.md").write_text(text, encoding="utf-8")
        (self.work / "review.json").write_text(
            json.dumps({"summary": text, "findings": list(findings),
                        "review_complete": True, "read_check": READ_CHECK}), encoding="utf-8"
        )
        (self.work / "seed-tokens.txt").write_text("\n".join(tokens))
        (self.work / "codex-home/auth.json").write_text(json.dumps({"tokens": {}}))

    def test_legacy_unfinished_review_does_not_suppress_retry(self):
        self.api[f"repos/{REPO}/issues/7/comments"] = [{
            "user": {"login": "github-actions[bot]"},
            "body": MARKER.replace(" status=complete", ""),
        }]
        self.assertEqual(self.run_step("Select PR").returncode, 0)
        self.assertIn("review=true", self.output())

    def test_owner_pr_is_selected_with_exact_head_and_base(self):
        result = self.run_step("Select PR")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review=true", self.output())
        self.assertIn(f"head_sha={HEAD}", self.output())
        self.assertIn(f"base_sha={BASE}", self.output())

    def test_fork_nonowner_draft_closed_and_old_ci_are_skipped(self):
        cases = (
            {"head": {"sha": HEAD, "repo": {"full_name": "outside/fork"}}},
            {"user": {"login": "someone-else"}},
            {"author_association": "NONE"},
            {"draft": True},
            {"state": "closed"},
            {"head": {"sha": "c" * 40, "repo": {"full_name": REPO}}},
        )
        for change in cases:
            with self.subTest(change=change):
                self.api[f"repos/{REPO}/pulls/7"] = {**PR, **change}
                result = self.run_step("Select PR")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("review=true", self.output())

    def test_push_ci_and_fork_workflow_are_skipped_before_api(self):
        for change in ({"event": "push"}, {"head_repository": {"full_name": "outside/fork"}}):
            with self.subTest(change=change):
                self.write_event(**change)
                result = self.run_step("Select PR")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("review=true", self.output())
                self.assertFalse((self.work / "gh.log").exists())

    def test_success_marker_skips_duplicate_but_outside_comment_does_not(self):
        comments = self.api[f"repos/{REPO}/issues/7/comments"]
        comments.append({"user": {"login": "someone-else"}, "body": MARKER})
        result = self.run_step("Select PR")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review=true", self.output())
        (self.work / "output").unlink()
        comments.append({"user": {"login": "github-actions[bot]"}, "body": MARKER})
        result = self.run_step("Select PR")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("review=true", self.output())

    def test_manual_review_can_recheck_existing_pr(self):
        self.env.update(EVENT_NAME="workflow_dispatch", PR_INPUT="7")
        self.api[f"repos/{REPO}/issues/7/comments"] = [
            {"user": {"login": "github-actions[bot]"}, "body": MARKER}
        ]
        result = self.run_step("Select PR")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("review=true", self.output())

    def test_invalid_manual_input_does_not_reach_api(self):
        self.env.update(EVENT_NAME="workflow_dispatch", PR_INPUT="7; echo injected")
        result = self.run_step("Select PR")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "gh.log").exists())

    def test_review_is_posted_with_commit_and_success_marker(self):
        self.prepare_review()
        result = self.run_step("Publish review")
        self.assertEqual(result.returncode, 0, result.stderr)
        posted = json.loads((self.work / "posted.json").read_text())["body"]
        self.assertIn("Codex Code Review", posted)
        self.assertIn("未发现有充分证据", posted)
        self.assertIn(MARKER, posted)

    def test_updated_head_base_and_closed_pr_are_not_posted(self):
        for change in (
            {"head": {"sha": "c" * 40, "repo": {"full_name": REPO}}},
            {"base": {"sha": "c" * 40}},
            {"state": "closed"},
        ):
            with self.subTest(change=change):
                self.api[f"repos/{REPO}/pulls/7"] = {**PR, **change}
                self.prepare_review()
                result = self.run_step("Publish review")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.work / "posted.json").exists())

    def test_seed_and_refreshed_credentials_are_never_posted(self):
        secret = "fake-secret-for-regression-test"
        for refreshed in (False, True):
            with self.subTest(refreshed=refreshed):
                self.prepare_review(f"不能发布这个值：{secret}", () if refreshed else (secret,))
                if refreshed:
                    (self.work / "codex-home/auth.json").write_text(
                        json.dumps({"tokens": {"access_token": secret}})
                    )
                result = self.run_step("Publish review")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertFalse((self.work / "posted.json").exists())

    def test_probe_rejects_readable_auth_even_if_network_is_blocked(self):
        workspace = self.work / "workspace"
        (workspace / "work").mkdir(parents=True)
        (workspace / "work/Cargo.toml").write_text("[package]\nname = 'example'\n")
        self.env["GITHUB_WORKSPACE"] = str(workspace)
        self.prepare_review()
        # 模拟一个没有文件隔离但网络已关闭的沙箱；探针必须失败，不能只看最后一条命令。
        self.mock_command("sudo", "exit 0\n")
        self.mock_command("getent", "echo '203.0.113.10 STREAM github.com'\n")
        self.mock_command("curl", 'test "${PROBE_INSIDE:-0}" != 1\n')
        self.mock_command("codex", '''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -C) cd "$2"; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
export PROBE_INSIDE=1
exec "$@"
''')
        result = self.run_step("Verify read-only sandbox")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_review_is_not_published(self):
        self.prepare_review("")
        result = self.run_step("Publish review")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "posted.json").exists())

    def test_installer_preserves_runtime_helpers_and_resources(self):
        # 裸二进制能启动 CLI，却无法读取代码；移动它时必须保留同包的相邻依赖。
        executable = b'''#!/usr/bin/env bash
set -euo pipefail
directory="$(dirname "$(readlink -f "$0")")"
test -x "$directory/codex-code-mode-host"
test -f "$directory/../codex-package.json"
test -x "$directory/../codex-path/rg"
echo 'codex-cli 0.166.0'
'''
        archive = self.work / "runtime.tar.gz"
        with tarfile.open(archive, "w:gz") as package:
            for name, content, mode in (
                ("bin/codex", executable, 0o755),
                ("codex-x86_64-unknown-linux-musl", executable, 0o755),
                ("bin/codex-code-mode-host", b"helper", 0o755),
                ("codex-package.json", b"{}", 0o644),
                ("codex-path/rg", b"search", 0o755),
            ):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(content), mode
                package.addfile(entry, io.BytesIO(content))
        self.env.update({
            "HOME": str(self.work / "home"),
            "GITHUB_PATH": str(self.work / "github-path"),
            "FAKE_CODEX_ARCHIVE": str(archive),
        })
        self.mock_command("curl", '''
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then output="$2"; shift 2; else shift; fi
done
cp "$FAKE_CODEX_ARCHIVE" "$output"
''')
        # 真实发布包的校验和由 Actions 中的 runtime smoke 验证；这里验证安装布局。
        self.mock_command("sha256sum", "cat >/dev/null\n")
        result = self.run_step("Install pinned Codex CLI")
        self.assertEqual(result.returncode, 0, result.stderr)
        runtime_bin = Path((self.work / "github-path").read_text().strip())
        result = subprocess.run([str(runtime_bin / "codex"), "--version"],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, "CLI 丢失同包 helper 或资源目录")

    def test_result_without_completion_evidence_is_rejected(self):
        self.prepare_review("读取工具缺少 codex-code-mode-host，审查未完成。")
        (self.work / "review.json").write_text(json.dumps({
            "summary": "读取工具缺少 codex-code-mode-host，审查未完成。", "findings": [],
        }))
        self.assertNotEqual(self.run_step("Render review").returncode, 0)

    def test_model_reported_incomplete_review_is_rejected(self):
        self.prepare_review()
        result = json.loads((self.work / "review.json").read_text())
        result.update(review_complete=False, read_check=READ_CHECK)
        (self.work / "review.json").write_text(json.dumps(result))
        self.assertNotEqual(self.run_step("Render review").returncode, 0)

    def test_completion_claim_without_successful_file_read_is_rejected(self):
        self.prepare_review()
        result = json.loads((self.work / "review.json").read_text())
        result.update(review_complete=True, read_check="not-read")
        (self.work / "review.json").write_text(json.dumps(result))
        self.assertNotEqual(self.run_step("Render review").returncode, 0)

    def test_completed_review_with_file_read_evidence_is_rendered(self):
        self.prepare_review()
        result = json.loads((self.work / "review.json").read_text())
        result.update(review_complete=True, read_check=READ_CHECK)
        (self.work / "review.json").write_text(json.dumps(result))
        rendered = self.run_step("Render review")
        self.assertEqual(rendered.returncode, 0, rendered.stderr)

    def prepare_findings(self):
        self.prepare_review("发现一个可复现问题", findings=[{
            "priority": 1, "title": "错误路径没有回滚", "body": "端口占用时会留下错误配置",
            "file": "src/example.rs", "line": 42,
        }])

    def test_findings_queue_codex_on_same_pr(self):
        self.prepare_findings()
        rendered = self.run_step("Render review")
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        result = self.run_step("Queue review fixes")
        self.assertEqual(result.returncode, 0, result.stderr)
        posted = json.loads((self.work / "posted.json").read_text())["body"]
        self.assertTrue(posted.startswith("/codex "))
        self.assertIn(f"<!-- codex-review-fix sha={HEAD} -->", posted)
        calls = (self.work / "gh.log").read_text()
        self.assertIn(f"repos/{REPO}/issues/7/comments", calls)

    def test_queued_findings_reach_existing_offline_dispatch_prompt(self):
        self.prepare_findings()
        self.assertEqual(self.run_step("Render review").returncode, 0)
        self.assertEqual(self.run_step("Queue review fixes").returncode, 0)
        posted = json.loads((self.work / "posted.json").read_text())["body"]
        event = {
            "comment": {"body": posted, "id": 123, "html_url": "https://example.com/comment/123"},
            "issue": {"number": 7, "pull_request": {}},
        }
        (self.work / "event.json").write_text(json.dumps(event))
        self.env["EVENT_NAME"] = "issue_comment"
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c",
             step_script("Parse request", ROOT / ".github/workflows/codex-dispatch.yml")],
            env=self.env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        instruction = (self.work / "instruction.txt").read_text()
        self.assertIn("src/example.rs:42", instruction)
        self.assertIn("端口占用时会留下错误配置", instruction)
        self.assertIn("mode=pr", self.output())

    def test_no_findings_does_not_queue_or_call_api(self):
        self.prepare_review()
        result = self.run_step("Queue review fixes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.work / "posted.json").exists())
        self.assertFalse((self.work / "gh.log").exists())

    def test_no_auto_fix_label_and_changed_commit_do_not_queue(self):
        for change in ({"labels": [{"name": "no-auto-fix"}]},
                       {"head": {"sha": "c" * 40, "repo": {"full_name": REPO}}}):
            with self.subTest(change=change):
                self.api[f"repos/{REPO}/pulls/7"] = {**PR, **change}
                self.prepare_findings()
                result = self.run_step("Queue review fixes")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.work / "posted.json").exists())

    def test_fix_queue_is_idempotent_for_same_commit(self):
        self.prepare_findings()
        self.api[f"repos/{REPO}/issues/7/comments"] = [{
            "user": {"login": "owner"}, "author_association": "OWNER",
            "body": f"<!-- codex-review-fix sha={HEAD} -->",
        }]
        result = self.run_step("Queue review fixes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.work / "posted.json").exists())

    def test_fix_budget_posts_human_handoff_instead_of_another_task(self):
        self.prepare_findings()
        self.api[f"repos/{REPO}/issues/7/comments"] = [{
            "user": {"login": "owner"}, "author_association": "OWNER",
            "body": f"<!-- codex-review-fix sha={value * 40} -->",
        } for value in ("c", "d")]
        result = self.run_step("Queue review fixes")
        self.assertEqual(result.returncode, 0, result.stderr)
        posted = json.loads((self.work / "posted.json").read_text())["body"]
        self.assertFalse(posted.startswith("/codex"))
        self.assertIn("人工", posted)
        self.assertIn("<!-- codex-review-fix-stop -->", posted)

    def test_render_rejects_invalid_model_result(self):
        (self.work / "review.json").write_text('{"summary": "看起来没问题"}')
        result = self.run_step("Render review")
        self.assertNotEqual(result.returncode, 0)

    def test_render_preserves_actionable_file_line_and_priority(self):
        self.prepare_findings()
        result = self.run_step("Render review")
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = (self.work / "review.md").read_text()
        self.assertIn("[P1]", rendered)
        self.assertIn("src/example.rs:42", rendered)
        self.assertIn("端口占用", rendered)

    def test_failed_review_reports_handoff_without_raw_model_logs(self):
        secret = "fake-secret-for-regression-test"
        (self.work / "codex-stderr.log").write_text(secret)
        result = self.run_step("Report review failure")
        self.assertEqual(result.returncode, 0, result.stderr)
        posted = json.loads((self.work / "posted.json").read_text())["body"]
        self.assertIn("人工", posted)
        self.assertIn(HEAD, posted)
        self.assertNotIn(secret, posted + result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
