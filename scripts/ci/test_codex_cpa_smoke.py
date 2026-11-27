"""Codex CPA 自检工作流的准入、回复判定和失败分类回归。

只使用临时目录和假 codex，不联网、不调用模型：python3 scripts/ci/test_codex_cpa_smoke.py
"""

import os
import shutil
import subprocess
import tempfile
import re
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "codex-cpa-smoke.yml"
OWNER = "Jyanbai"
COLLABORATOR = "collaborator"

FAKE_CODEX = r"""#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = features ]; then
  printf 'shell_tool                               stable             %s\n' "${FAKE_CODEX_SHELL_TOOL:-false}"
  exit 0
fi
if [ -n "${FAKE_CODEX_ARGS:-}" ]; then
  printf '%s\n' "$*" >> "${FAKE_CODEX_ARGS}"
fi
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "${out}" ] && [ -n "${FAKE_CODEX_LAST:-}" ] && [ -f "${FAKE_CODEX_LAST}" ]; then
  cat "${FAKE_CODEX_LAST}" > "${out}"
fi
if [ -n "${FAKE_CODEX_EVENTS:-}" ] && [ -f "${FAKE_CODEX_EVENTS}" ]; then
  cat "${FAKE_CODEX_EVENTS}"
fi
if [ -n "${FAKE_CODEX_STDERR:-}" ] && [ -f "${FAKE_CODEX_STDERR}" ]; then
  cat "${FAKE_CODEX_STDERR}" >&2
fi
exit "${FAKE_CODEX_EXIT:-0}"
"""


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


def job_if_expression(text=None):
    lines = (text or WORKFLOW.read_text(encoding="utf-8")).splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("    if:"):
            continue
        rest = line[len("    if:") :].strip()
        if rest in (">", ">-", "|", "|-"):
            continued = []
            for follow in lines[index + 1 :]:
                if follow.startswith("      "):
                    continued.append(follow.strip())
                else:
                    break
            return " ".join(continued)
        return rest
    raise AssertionError("job if 条件不存在")


def evaluate_gha_and_equals(expression, context):
    """计算仅含 && 与 == 的 GitHub Actions 表达式。"""
    clauses = [part.strip() for part in expression.split("&&")]
    if not clauses or any(not clause for clause in clauses):
        raise ValueError(expression)

    def resolve(token):
        token = token.strip()
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
            return token[1:-1]
        if token not in context:
            raise KeyError(token)
        return context[token]

    result = True
    for clause in clauses:
        if "==" not in clause:
            raise ValueError(clause)
        left, right = clause.split("==", 1)
        result = result and resolve(left) == resolve(right)
    return result


def admit(event_name, actor, triggering_actor, owner=OWNER):
    return evaluate_gha_and_equals(
        job_if_expression(),
        {
            "github.event_name": event_name,
            "github.actor": actor,
            "github.triggering_actor": triggering_actor,
            "github.repository_owner": owner,
        },
    )


class WorkflowPolicyTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_only_manual_dispatch(self):
        on = self.text[self.text.index("\non:\n") : self.text.index("\npermissions:\n")]
        self.assertIn("  workflow_dispatch:", on)
        for trigger in (
            "push:",
            "pull_request",
            "issue_comment:",
            "issues:",
            "schedule:",
            "workflow_run:",
            "repository_dispatch:",
        ):
            with self.subTest(trigger=trigger):
                self.assertNotIn(trigger, on)

    def test_concurrency_is_scoped_to_admitted_job(self):
        # 工作流级并发组会让未获准的运行先取消所有者的自检，再在作业级被跳过。
        top = self.text[: self.text.index("\njobs:\n")]
        self.assertNotIn("concurrency:", top)
        self.assertNotIn("cancel-in-progress", top)
        lines = self.text.splitlines()
        job = lines.index("  smoke:")
        steps = lines.index("    steps:", job)
        job_header = "\n".join(lines[job:steps])
        self.assertIn("    concurrency:", job_header)
        self.assertIn("      group: codex-cpa-smoke", job_header)
        self.assertIn("github.triggering_actor == github.repository_owner", job_header)
        # 准入条件必须写在并发组之前所属的同一个作业里。
        self.assertLess(job_header.index("    if:"), job_header.index("    concurrency:"))

    def test_provider_is_ci_cpa_not_desktop_id(self):
        self.assertIn('model_provider = "cpa"', self.text)
        self.assertIn("[model_providers.cpa]", self.text)
        self.assertIn('env_key = "CODEX_API_KEY"', self.text)
        self.assertIn('wire_api = "responses"', self.text)
        self.assertNotIn('model_provider = "OpenAI"', self.text)
        self.assertNotIn("[model_providers.OpenAI]", self.text)
        # 只在注释里提到不读写 CODEX_AUTH_JSON，不得写回该 secret。
        self.assertIn("不写、不读、不回写 CODEX_AUTH_JSON", self.text)
        self.assertNotIn("gh secret set CODEX_AUTH_JSON", self.text)
        self.assertNotIn("secrets.CODEX_AUTH_JSON", self.text)
        self.assertNotIn("secrets.CODEX_BOT_TOKEN", self.text)
        self.assertIn("secrets.CODEX_CPA_API_KEY", self.text)
        self.assertNotIn("secrets.CODEX_API_KEY", self.text)
        self.assertEqual(self.text.count("secrets.CODEX_CPA_API_KEY"), 3)
        hint = "CODEX_CPA_API_KEY 必须只在 environment codex 中设置；不要在仓库或组织级创建同名 secret"
        self.assertIn(hint, self.text)
        docs = (ROOT / "docs" / "CODEX_DISPATCH.md").read_text(encoding="utf-8")
        self.assertIn("请**只**在 environment `codex` 里设置", docs)
        self.assertIn("不要在仓库或组织级创建同名 secret", docs)
        self.assertIn("工作流无法分辨来源", docs)


class CiWiringTest(unittest.TestCase):
    def test_pr_ci_runs_this_regression(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("run: python3 scripts/ci/test_codex_cpa_smoke.py", ci)
        # 不需要 CPA 密钥。
        self.assertNotIn("CODEX_API_KEY", ci)


class AdmissionTest(unittest.TestCase):
    def test_expression_requires_triggering_actor(self):
        expression = job_if_expression()
        self.assertIn("github.triggering_actor == github.repository_owner", expression)
        self.assertIn("github.actor == github.repository_owner", expression)
        self.assertIn("github.event_name == 'workflow_dispatch'", expression)

    def test_owner_initiator_and_owner_rerun_are_admitted(self):
        self.assertTrue(admit("workflow_dispatch", OWNER, OWNER))

    def test_owner_run_rerun_by_collaborator_is_denied(self):
        # 重跑时 actor 仍是原始发起人（所有者），triggering_actor 是点击重跑的协作者。
        self.assertFalse(admit("workflow_dispatch", OWNER, COLLABORATOR))

    def test_non_owner_initiator_is_denied(self):
        self.assertFalse(admit("workflow_dispatch", COLLABORATOR, COLLABORATOR))
        self.assertFalse(admit("workflow_dispatch", COLLABORATOR, OWNER))

    def test_non_dispatch_is_denied(self):
        self.assertFalse(admit("push", OWNER, OWNER))

    def test_blank_triggering_actor_is_denied(self):
        self.assertFalse(admit("workflow_dispatch", OWNER, ""))

    def run_admit(self, event_name, actor, triggering_actor, owner=OWNER):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step_script("Admit owner operator")],
            env={
                **os.environ,
                "EVENT_NAME": event_name,
                "ACTOR": actor,
                "TRIGGERING_ACTOR": triggering_actor,
                "OWNER": owner,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        return result

    def test_admit_step_allows_owner_operator(self):
        result = self.run_admit("workflow_dispatch", OWNER, OWNER)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_admit_step_denies_collaborator_rerun(self):
        result = self.run_admit("workflow_dispatch", OWNER, COLLABORATOR)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("只允许仓库所有者启动或重跑此自检", result.stdout)


COMPLETE_OK_EVENTS = """{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"OK"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}
"""


class ReplyAndFailureTest(unittest.TestCase):
    def run_smoke(self, last_message, *, exit_code=0, stderr="", events="", key="test-cpa-key-not-real", git_status_fail=False, shell_tool_state="false"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        workspace = work / "workspace"
        runner_temp = work / "runner-temp"
        workspace.mkdir()
        runner_temp.mkdir()
        last = runner_temp / "fake-last.md"
        last.write_bytes(last_message if isinstance(last_message, bytes) else last_message.encode("utf-8"))
        events_file = runner_temp / "fake-events.jsonl"
        events_file.write_text(events, encoding="utf-8")
        stderr_file = runner_temp / "fake-stderr.log"
        stderr_file.write_text(stderr, encoding="utf-8")
        codex = bin_dir / "codex"
        codex.write_text(FAKE_CODEX, encoding="utf-8")
        codex.chmod(0o755)
        if git_status_fail:
            real_git = shutil.which("git")
            if not real_git:
                self.fail("test host has no git")
            git_wrapper = bin_dir / "git"
            git_wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'if [ "${FAKE_GIT_STATUS_FAIL:-}" = 1 ]; then\n'
                '  for arg in "$@"; do\n'
                '    if [ "$arg" = status ]; then\n'
                '      echo "fatal: index file corrupt" >&2\n'
                "      exit 1\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "exec %s \"$@\"\n" % real_git,
                encoding="utf-8",
            )
            git_wrapper.chmod(0o755)
        summary = runner_temp / "summary.md"
        summary.touch()
        args_file = runner_temp / "fake-codex-args.log"
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_STEP_SUMMARY": str(summary),
            "CODEX_API_KEY": key,
            "CODEX_CPA_API_KEY": key,
            "CPA_MODEL": "gpt-6.2-sol",
            "CPA_EFFORT": "high",
            "FAKE_CODEX_LAST": str(last),
            "FAKE_CODEX_EVENTS": str(events_file),
            "FAKE_CODEX_STDERR": str(stderr_file),
            "FAKE_CODEX_EXIT": str(exit_code),
            "FAKE_GIT_STATUS_FAIL": "1" if git_status_fail else "0",
            "FAKE_CODEX_SHELL_TOOL": shell_tool_state,
            "FAKE_CODEX_ARGS": str(args_file),
        }
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", step_script("Run CPA smoke")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        result.codex_calls = args_file.read_text(encoding="utf-8").splitlines() if args_file.exists() else []
        return result, summary.read_text(encoding="utf-8")

    def error_lines(self, result):
        return [line for line in result.stdout.splitlines() if line.startswith("::error::")]

    def test_single_line_ok_succeeds(self):
        for payload in (b"OK", b"OK\n", b"OK\r\n"):
            with self.subTest(payload=payload):
                result, summary = self.run_smoke(payload, events=COMPLETE_OK_EVENTS)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertTrue(any("Responses 调用成功" in line for line in result.stdout.splitlines()))
                self.assertIn("CPA 自检通过", summary)

    def test_success_reports_requested_model_without_claiming_availability(self):
        result, summary = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        for text in (result.stdout, summary):
            with self.subTest(text=text[:30]):
                self.assertIn("CPA 返回了", text)
                self.assertIn("请求的模型：gpt-6.2-sol", text)
                self.assertIn("实际处理请求的模型未核实", text)
                self.assertNotIn("请求的模型已跑通", text)
                self.assertNotIn("请求的模型可用", text)
                self.assertNotIn("模型可用", text)

    def test_success_does_not_claim_authentication(self):
        result, summary = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        for text in (result.stdout, summary):
            with self.subTest(text=text[:40]):
                self.assertIn("Responses 调用成功", text)
                self.assertIn("请求的模型：gpt-6.2-sol", text)
                self.assertIn("实际处理请求的模型未核实", text)
                self.assertNotIn("认证成功", text)
                self.assertNotIn("认证与", text)
                self.assertNotIn("CPA 认证", text)
                self.assertNotRegex(text, r"(?i)authentication")

    def test_rejection_text_containing_ok_fails(self):
        result, _ = self.run_smoke("无法按要求回复 OK。\n")
        self.assertNotEqual(result.returncode, 0)
        errors = self.error_lines(result)
        self.assertTrue(any("不是单独一行 OK" in line for line in errors), result.stdout)
        self.assertFalse(any("CPA 认证、Responses 接口与请求的模型已跑通" in line for line in result.stdout.splitlines()))

    def test_multiline_output_fails(self):
        result, _ = self.run_smoke("OK\n额外一行\n")
        self.assertNotEqual(result.returncode, 0)
        errors = self.error_lines(result)
        self.assertTrue(any("不是单独一行 OK" in line for line in errors), result.stdout)

    def test_ok_reply_still_fails_if_event_stream_ran_a_command(self):
        events = """{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"pwd","aggregated_output":"","status":"in_progress"}}
{"type":"item.completed","item":{"id":"item_1","type":"command_execution","command":"pwd","aggregated_output":"/workspace/cpa-smoke\\n","exit_code":0,"status":"completed"}}
{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"OK"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}
"""
        result, summary = self.run_smoke(b"OK\n", events=events)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("执行了命令", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))
        self.assertNotIn("认证成功", result.stdout + summary)
        for text in (result.stdout, result.stderr, summary):
            self.assertNotIn("pwd", text)
            self.assertNotIn("/workspace/cpa-smoke", text)

    def test_ok_reply_with_agent_message_events_succeeds(self):
        result, summary = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("CPA 自检通过", summary)

    def test_ok_reply_with_empty_event_stream_fails(self):
        result, summary = self.run_smoke(b"OK\n", events="")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("事件流为空", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))
        self.assertNotIn("认证成功", result.stdout + summary)

    def test_ok_reply_with_incomplete_event_stream_fails(self):
        events = """{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"item_2","type":"agent_message","text":"OK"}}
"""
        result, summary = self.run_smoke(b"OK\n", events=events)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("缺少完成事件", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))
        self.assertNotIn("认证成功", result.stdout + summary)

    def test_git_status_failure_is_not_reported_as_success(self):
        result, summary = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS, git_status_fail=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("无法确认自检工作区状态", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))
        self.assertNotIn("认证成功", result.stdout + summary)
        for text in (result.stdout, summary):
            self.assertNotIn("index file corrupt", text)

    def test_exec_call_disables_shell_tool(self):
        result, _ = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        exec_calls = [call for call in result.codex_calls if call.startswith("exec ")]
        self.assertEqual(len(exec_calls), 1, result.codex_calls)
        self.assertIn("features.shell_tool=false", exec_calls[0])

    def test_shell_tool_not_confirmed_off_stops_before_model_call(self):
        for state in ("true", "unknown"):
            with self.subTest(state=state):
                result, summary = self.run_smoke(b"OK\n", events=COMPLETE_OK_EVENTS, shell_tool_state=state)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                errors = "\n".join(self.error_lines(result))
                self.assertIn("shell/命令工具", errors)
                self.assertEqual([c for c in result.codex_calls if c.startswith("exec ")], [])
                self.assertNotIn("CPA 自检通过", summary)

    def test_generated_config_disables_shell_tool(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        runner_temp = work / "runner-temp"
        runner_temp.mkdir()
        files = {name: work / name for name in ("env", "output", "summary")}
        for path in files.values():
            path.touch()
        env = {
            **os.environ,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_ENV": str(files["env"]),
            "GITHUB_OUTPUT": str(files["output"]),
            "GITHUB_STEP_SUMMARY": str(files["summary"]),
            "CODEX_CPA_API_KEY": "test-cpa-key-not-real",
            "CODEX_API_BASE_URL": "https://cpa.invalid/v1",
            "CODEX_MODEL": "",
            "CODEX_REASONING_EFFORT": "",
        }
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", step_script("Prepare CPA config")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        raw = (runner_temp / "codex-home" / "config.toml").read_text(encoding="utf-8")
        # CI 的 Ubuntu 22.04 是 Python 3.10，没有 tomllib；features 表是生成文件末尾的独立表。
        self.assertRegex(raw, r"(?m)^\[features\]\nshell_tool = false$")
        self.assertNotRegex(raw, r"(?m)^shell_tool = true")
        self.assertRegex(raw, r'(?m)^model_provider = "cpa"$')
        self.assertNotIn("test-cpa-key-not-real", raw)

    def prepare(self, **overrides):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        runner_temp = work / "runner-temp"
        runner_temp.mkdir()
        for name in ("env", "output", "summary"):
            (work / name).touch()
        env = {
            **os.environ,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_ENV": str(work / "env"),
            "GITHUB_OUTPUT": str(work / "output"),
            "GITHUB_STEP_SUMMARY": str(work / "summary"),
            "CODEX_CPA_API_KEY": "test-cpa-key-not-real",
            "CODEX_API_BASE_URL": "https://cpa.invalid/v1",
            "CODEX_MODEL": "",
            "CODEX_REASONING_EFFORT": "",
            **overrides,
        }
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", step_script("Prepare CPA config")],
            env=env, capture_output=True, text=True, check=False,
        )
        summary = (work / "summary").read_text(encoding="utf-8")
        return result, summary, runner_temp

    def test_base_url_is_a_secret_without_default_and_never_printed(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        # 工作流里没有任何内置的 CPA 基址：除 github.com 和 base_re 正则外不出现 https:// 地址。
        hosts = [m for m in re.findall(r"https://[^\s'\"\\^]+", text) if not m.startswith("https://github.com")]
        self.assertEqual(hosts, [], hosts)
        self.assertIn("CODEX_API_BASE_URL: ${{ secrets.CODEX_API_BASE_URL }}", text)
        self.assertNotIn("vars.CODEX_API_BASE_URL", text)
        for missing in ("", "   "):
            with self.subTest(missing=repr(missing)):
                result, summary, runner_temp = self.prepare(CODEX_API_BASE_URL=missing)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("secret CODEX_API_BASE_URL", result.stdout)
                self.assertFalse((runner_temp / "codex-home/config.toml").exists())
        url = "https://cpa.invalid/v1"
        result, summary, runner_temp = self.prepare()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("cpa.invalid", result.stdout + result.stderr + summary)
        self.assertIn(f'base_url = "{url}"', (runner_temp / "codex-home/config.toml").read_text())
        for bad in ("http://cpa.invalid/v1", 'https://x"\nmodel = "evil'):
            with self.subTest(bad=bad):
                result, _, runner_temp = self.prepare(CODEX_API_BASE_URL=bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("evil", result.stdout + result.stderr)
                self.assertFalse((runner_temp / "codex-home/config.toml").exists())

    def test_repo_level_api_key_is_not_accepted_without_env_scoped_secret(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        runner_temp = work / "runner-temp"
        runner_temp.mkdir()
        files = {name: work / name for name in ("env", "output", "summary")}
        for path in files.values():
            path.touch()
        leaked = "test-cpa-key-not-real"
        env = {
            **os.environ,
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_ENV": str(files["env"]),
            "GITHUB_OUTPUT": str(files["output"]),
            "GITHUB_STEP_SUMMARY": str(files["summary"]),
            "CODEX_API_KEY": leaked,
            "CODEX_CPA_API_KEY": "",
            "CODEX_API_BASE_URL": "",
            "CODEX_MODEL": "",
            "CODEX_REASONING_EFFORT": "",
        }
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", step_script("Prepare CPA config")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        combined = result.stdout + result.stderr
        self.assertIn("CODEX_CPA_API_KEY", combined)
        self.assertIn("environment codex", combined)
        self.assertNotIn("ok=true", files["output"].read_text(encoding="utf-8"))
        self.assertFalse((runner_temp / "codex-home" / "config.toml").exists())
        for text in (combined, files["env"].read_text(encoding="utf-8"), files["summary"].read_text(encoding="utf-8")):
            self.assertNotIn(leaked, text)

    def test_ok_reply_with_non_event_json_in_stream_fails(self):
        events = COMPLETE_OK_EVENTS.replace(
            '{"type":"turn.started"}\n',
            '{"type":"turn.started"}\n0\n',
            1,
        )
        self.assertIn("\n0\n", events)
        result, summary = self.run_smoke(b"OK\n", events=events)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("非事件记录", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))

    def test_ok_reply_with_completion_only_truncated_stream_fails(self):
        events = """{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"OK"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}
"""
        result, summary = self.run_smoke(b"OK\n", events=events)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("缺少起始事件", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))

    def test_ok_reply_without_turn_started_fails(self):
        events = """{"type":"thread.started","thread_id":"t1"}
{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"OK"}}
{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1,"reasoning_output_tokens":0}}
"""
        self.assertNotIn("turn.started", events)
        result, summary = self.run_smoke(b"OK\n", events=events)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("缺少回合起始事件", errors)
        self.assertNotIn("CPA 自检通过", summary)
        self.assertFalse(any("Responses 调用成功" in line for line in result.stdout.splitlines()))

    def test_http_401_reports_key_category(self):



        raw = (
            'api error 401 Unauthorized: invalid_api_key raw payload={"error":"nope","token":"secret-token-value"}\n'
        )
        result, summary = self.run_smoke("unused\n", exit_code=1, stderr=raw)
        self.assertEqual(result.returncode, 1)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("密钥无效或被拒绝", errors)
        self.assertIn("HTTP 状态：401", errors)
        self.assertIn("CODEX_CPA_API_KEY", errors)
        self.assertNotIn("的 CODEX_API_KEY", errors)
        self.assertNotIn("接口不存在", errors)
        self.assertNotIn("secret-token-value", errors)
        self.assertNotIn("invalid_api_key", errors)
        self.assertNotIn("raw payload", errors)
        self.assertNotIn("secret-token-value", summary)
        self.assertIn("HTTP 状态：401", summary)

    def test_http_404_reports_base_url_category(self):
        raw = 'api error 404: The requested URL /v1/responses was not found raw={"path":"/v1/responses"}\n'
        result, summary = self.run_smoke("unused\n", exit_code=1, stderr=raw)
        self.assertEqual(result.returncode, 1)
        errors = "\n".join(self.error_lines(result))
        self.assertIn("接口不存在", errors)
        self.assertIn("HTTP 状态：404", errors)
        self.assertIn("CODEX_API_BASE_URL", errors)
        self.assertNotIn("密钥无效或被拒绝", errors)
        self.assertNotIn("/v1/responses was not found", errors)
        self.assertNotIn("raw=", errors)
        self.assertNotIn("was not found", summary)

    def test_http_404_model_not_found_points_at_model_not_base_url(self):
        cases = (
            'api error 404: model_not_found raw={"error":{"code":"model_not_found","message":"gpt-6.2-sol is not deployed","leak":"leak-me-model"}}\n',
            'unexpected status 404 Not Found: The model gpt-6.2-sol does not exist leak-me-model\n',
            "unexpected status 404 Not Found: The model 'gpt-6.2-sol' was not found leak-me-model\n",
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                result, summary = self.run_smoke("x", exit_code=1, stderr=raw)
                self.assertEqual(result.returncode, 1)
                errors = "\n".join(self.error_lines(result))
                self.assertIn("请求的模型不可用", errors)
                self.assertIn("HTTP 状态：404", errors)
                self.assertIn("CODEX_MODEL", errors)
                self.assertIn("gpt-6.2-sol", errors)
                self.assertNotIn("接口不存在", errors)
                self.assertNotIn("CODEX_API_BASE_URL", errors)
                for text in (result.stdout, result.stderr, summary):
                    self.assertNotIn("leak-me-model", text)
                    self.assertNotIn("is not deployed", text)
                    self.assertNotIn("was not found", text)
                    self.assertNotIn("does not exist", text)

    def test_unexpected_status_form_is_classified(self):
        cases = (
            ("unexpected status 401 Unauthorized: {\"error\":\"bad key\",\"token\":\"leak-me-401\"}\n",
             "401", "密钥无效或被拒绝", "CODEX_CPA_API_KEY", "leak-me-401"),
            ("unexpected status 404 Not Found: <html>route /v1/responses missing leak-me-404</html>\n",
             "404", "接口不存在", "CODEX_API_BASE_URL", "leak-me-404"),
        )
        for raw, status, category, hint, leak in cases:
            with self.subTest(status=status):
                result, summary = self.run_smoke("x", exit_code=1, stderr=raw)
                self.assertEqual(result.returncode, 1)
                errors = "\n".join(self.error_lines(result))
                self.assertIn(category, errors)
                self.assertIn(f"HTTP 状态：{status}", errors)
                self.assertIn(hint, errors)
                self.assertNotIn("其他调用失败", errors)
                for text in (result.stdout, result.stderr, summary):
                    self.assertNotIn(leak, text)
                    self.assertNotIn("unexpected status", text)

    def test_401_and_404_diagnostics_differ(self):
        unauthorized, _ = self.run_smoke("x", exit_code=1, stderr="api error 401: unauthorized\n")
        missing, _ = self.run_smoke("x", exit_code=1, stderr="api error 404: missing route\n")
        self.assertIn("HTTP 状态：401", "\n".join(self.error_lines(unauthorized)))
        self.assertIn("HTTP 状态：404", "\n".join(self.error_lines(missing)))
        self.assertNotEqual(
            "\n".join(self.error_lines(unauthorized)),
            "\n".join(self.error_lines(missing)),
        )


class SandboxProbeDnsTest(unittest.TestCase):
    """沙箱探测步骤：沙箱外 DNS/出网失败必须给出可定位的中文诊断。"""

    def run_probe(self, getent_script):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        workspace = work / "workspace"
        runner_temp = work / "runner-temp"
        codex_home = runner_temp / "codex-home"
        for path in (workspace, runner_temp, codex_home):
            path.mkdir()
        (codex_home / "config.toml").write_text("", encoding="utf-8")
        calls = work / "calls.log"
        output = work / "output"
        output.touch()
        fakes = {
            "getent": getent_script,
            "sudo": "exit 0",
            "curl": "exit 0",
            "codex": f'echo "codex $1" >> "{calls}"\nexit 0',
        }
        for name, body in fakes.items():
            path = bin_dir / name
            path.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
            path.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(output),
            "CODEX_HOME": str(codex_home),
            "CODEX_CPA_API_KEY": "test-cpa-key-not-real",
        }
        result = subprocess.run(
            ["bash", "-o", "pipefail", "-c", step_script("Verify read-only sandbox")],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        sandbox_ran = calls.exists() and "codex sandbox" in calls.read_text(encoding="utf-8")
        return result, output.read_text(encoding="utf-8"), sandbox_ran

    def test_dns_failure_reports_outside_sandbox_diagnostic(self):
        cases = {
            "getent 非零退出": "exit 2",
            "getent 零退出但无输出": "exit 0",
        }
        for label, script in cases.items():
            with self.subTest(label):
                result, output, sandbox_ran = self.run_probe(script)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("沙箱外访问不了 github.com", result.stdout)
                self.assertNotIn("ok=true", output)
                self.assertFalse(sandbox_ran)

    def test_resolvable_host_reaches_sandbox_probe(self):
        result, output, sandbox_ran = self.run_probe('echo "192.0.2.1 STREAM github.com"')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(sandbox_ran)
        self.assertIn("ok=true", output)


if __name__ == "__main__":
    unittest.main()
