"""Codex Dispatch / Code Review / Plan 的模型通道切换（CODEX_PROVIDER=cpa / chatgpt）。

直接执行三条 workflow 里恢复凭据的步骤和共用脚本 scripts/ci/codex_provider_config.py，
只用临时目录和假密钥，不联网、不调用模型：python3 scripts/ci/test_codex_provider_config.py
"""

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import codex_hardening

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/codex_provider_config.py"
WORKFLOWS = ROOT / ".github/workflows"
BASE_URL = "https://cpa.invalid/v1"
CPA_KEY = "fake-cpa-key-0123456789abcdef"
CHATGPT_TOKEN = "fake-chatgpt-refresh-token-0123456789"
AUTH_JSON = json.dumps({"auth_mode": "chatgpt", "tokens": {"refresh_token": CHATGPT_TOKEN}})

# 流程 → (workflow 文件, 恢复步骤名, 共用脚本相对工作目录的位置, 模型变量, 运行步骤名)
FLOWS = {
    "review": ("codex-code-review.yml", "Restore review auth", "codex-policy", "CODEX_REVIEW_MODEL", "Run Codex review"),
    "plan": ("codex-plan.yml", "Restore plan auth", "work", "CODEX_PLAN_MODEL", "Run Codex plan"),
    "dispatch": ("codex-dispatch.yml", "Restore Codex auth", "codex-policy", "CODEX_DISPATCH_MODEL", "Run Codex"),
}


def step_block(workflow, name):
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    start = text.index(f"      - name: {name}\n")
    end = text.find("\n      - name: ", start + 1)
    return text[start:] if end < 0 else text[start:end]


def step_script(workflow, name):
    lines = (WORKFLOWS / workflow).read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


def legacy_config(flow, runner_temp, home):
    """切换前三条流程逐字生成的 config.toml；chatgpt 分支必须保持不变。"""
    if flow == "dispatch":
        return (
            'cli_auth_credentials_store = "file"\n'
            'default_permissions = "ci"\n\n'
            '[permissions.ci]\nextends = ":workspace"\n\n'
            "[permissions.ci.filesystem]\n"
            f'"{runner_temp}" = "deny"\n'
            f'"{home}/.cargo" = "write"\n\n'
            "[permissions.ci.network]\nenabled = false\n"
        )
    return (
        'cli_auth_credentials_store = "file"\n'
        'approval_policy = "never"\nweb_search = "disabled"\nproject_doc_max_bytes = 0\n'
        f'default_permissions = "{flow}"\n\n'
        f'[permissions.{flow}]\nextends = ":read-only"\n\n'
        f'[permissions.{flow}.filesystem]\n"{runner_temp}" = "deny"\n\n'
        f"[permissions.{flow}.network]\nenabled = false\n"
    )


class RestoreStepTest(unittest.TestCase):
    """每条流程在 cpa 和 chatgpt 两种取值下各跑一次真实的恢复步骤，检查生成的配置。"""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.home = self.work / "home"
        self.home.mkdir()

    def restore(self, flow, provider, **extra):
        workflow, step, script_dir, _, _ = FLOWS[flow]
        target = self.work / script_dir / "scripts/ci/codex_provider_config.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.symlink_to(SCRIPT)
        for name in ("output", "github_env"):
            (self.work / name).write_text("")
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "RUNNER_TEMP": str(self.work),
            "GITHUB_WORKSPACE": str(self.work),
            "GITHUB_OUTPUT": str(self.work / "output"),
            "GITHUB_ENV": str(self.work / "github_env"),
            "HAS_BOT_TOKEN": "true",
            "ALLOW_REFRESH": "true",
            "REFRESH_GUARD_SECONDS": "604800",
            "CODEX_PROVIDER": provider,
            # 与 workflow 的表达式一致：只有 chatgpt 拿到登录，只有 cpa 拿到 CPA 密钥。
            "CODEX_AUTH_JSON": AUTH_JSON if provider == "chatgpt" else "",
            "CODEX_CPA_API_KEY": CPA_KEY if provider in ("", "cpa") else "",
            # 基址是 secret，只在 cpa 时传入。
            "CODEX_API_BASE_URL": BASE_URL if provider in ("", "cpa") else "",
            "CODEX_MODEL": f"gpt-test-{flow}",
            "CODEX_REASONING_EFFORT": "high",
            **extra,
        }
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step_script(workflow, step)],
            cwd=self.work, env=env, text=True, capture_output=True, check=False,
        )
        config_path = self.work / "codex-home/config.toml"
        config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        return result, config

    def output(self):
        return (self.work / "output").read_text()

    def assert_cpa(self, flow, provider):
        result, config = self.restore(flow, provider)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("provider=cpa", self.output())
        self.assertIn("ok=true", self.output())
        self.assertIn("CODEX_PROVIDER_RESOLVED=cpa", (self.work / "github_env").read_text())
        # 与 codex-cpa-smoke.yml 相同的 provider 段：cpa、Responses API、密钥只走 env_key。
        self.assertIn(
            '[model_providers.cpa]\nname = "CPA"\n'
            f'base_url = "{BASE_URL}"\nenv_key = "CODEX_CPA_API_KEY"\nwire_api = "responses"\n',
            config,
        )
        self.assertTrue(config.startswith(
            f'model = "gpt-test-{flow}"\nmodel_provider = "cpa"\nmodel_reasoning_effort = "high"\n'))
        self.assertIn("ignore_default_excludes = false", config)
        self.assertIn('"CODEX_CPA_API_KEY"', config.split("[shell_environment_policy]")[1])
        self.assertNotIn("cli_auth_credentials_store", config)
        # 走 cpa 时不读、不写 CODEX_AUTH_JSON，密钥不进文件但会登记遮蔽。
        self.assertFalse((self.work / "codex-home/auth.json").exists())
        self.assertNotIn(CPA_KEY, config)
        self.assertEqual((self.work / "seed-tokens.txt").read_text(), "")
        self.assertIn(f"::add-mask::{CPA_KEY}", result.stdout)
        self.assertNotIn(BASE_URL, result.stdout + result.stderr)
        # 权限配置（沙箱）与切换前完全相同。
        legacy = legacy_config(flow, self.work, self.home)
        self.assertIn(legacy.split("\n\n", 1)[1], config)

    def assert_chatgpt(self, flow):
        result, config = self.restore(flow, "chatgpt")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("provider=chatgpt", self.output())
        self.assertIn("ok=true", self.output())
        self.assertEqual(config, legacy_config(flow, self.work, self.home))
        self.assertEqual(json.loads((self.work / "codex-home/auth.json").read_text())["auth_mode"], "chatgpt")
        self.assertTrue((self.work / "auth.seed.sha256").read_text().strip())
        self.assertIn(f"::add-mask::{CHATGPT_TOKEN}", result.stdout)
        self.assertNotIn("model_providers", config)

    def test_review_cpa(self):
        self.assert_cpa("review", "cpa")

    def test_review_chatgpt(self):
        self.assert_chatgpt("review")

    def test_plan_cpa(self):
        self.assert_cpa("plan", "cpa")

    def test_plan_chatgpt(self):
        self.assert_chatgpt("plan")

    def test_dispatch_cpa(self):
        self.assert_cpa("dispatch", "cpa")

    def test_dispatch_chatgpt(self):
        self.assert_chatgpt("dispatch")

    def test_unset_provider_defaults_to_cpa(self):
        for flow in FLOWS:
            with self.subTest(flow=flow):
                self.assert_cpa(flow, "")

    def test_unknown_provider_is_rejected_before_any_file(self):
        for flow in FLOWS:
            with self.subTest(flow=flow):
                result, config = self.restore(flow, "openai")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(config, "")
                self.assertNotIn("ok=true", self.output())

    def test_cpa_without_key_base_url_or_model_stops(self):
        for flow in FLOWS:
            for missing in ("CODEX_CPA_API_KEY", "CODEX_API_BASE_URL", "CODEX_MODEL"):
                with self.subTest(flow=flow, missing=missing):
                    result, config = self.restore(flow, "cpa", **{missing: ""})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(config, "")
                    self.assertNotIn("ok=true", self.output())
                    self.assertIn("::error::", result.stdout)

    def test_cpa_rejects_reasoning_effort_with_whitespace_before_launch(self):
        for flow in FLOWS:
            for effort in ("high ", " high", "high\n", "\t"):
                with self.subTest(flow=flow, effort=effort):
                    result, config = self.restore(flow, "cpa", CODEX_REASONING_EFFORT=effort)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(config, "")
                    self.assertNotIn("ok=true", self.output())
                    self.assertIn("::error::CODEX_REASONING_EFFORT", result.stdout)

    def test_chatgpt_without_login_stops(self):
        for flow in FLOWS:
            with self.subTest(flow=flow):
                result, _ = self.restore(flow, "chatgpt", CODEX_AUTH_JSON="")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("ok=true", self.output())


class ScriptValidationTest(unittest.TestCase):
    def render(self, *, flow="review", provider="cpa", **env):
        with tempfile.TemporaryDirectory() as temporary:
            full_env = {
                "PATH": os.environ["PATH"],
                "CODEX_API_BASE_URL": BASE_URL,
                "CODEX_MODEL": "gpt-test",
                "CODEX_REASONING_EFFORT": "high",
                "CODEX_CPA_API_KEY": CPA_KEY,
                **env,
            }
            result = subprocess.run(
                ["python3", str(SCRIPT), "--flow", flow, "--provider", provider, "--home", temporary,
                 "--runner-temp", "/tmp/rt", "--cargo-home", "/home/runner/.cargo"],
                env=full_env, text=True, capture_output=True, check=False,
            )
            path = Path(temporary) / "config.toml"
            return result, path.read_text() if path.exists() else ""

    def test_base_url_must_be_plain_https(self):
        for bad in ("http://cpa.invalid/v1", 'https://x"\nmodel = "evil', "https://x/v1?a=b", "ftp://x"):
            with self.subTest(bad=bad):
                result, config = self.render(CODEX_API_BASE_URL=bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(config, "")
                self.assertNotIn(bad, result.stdout + result.stderr)

    def test_model_and_effort_cannot_inject_toml(self):
        for env in ({"CODEX_MODEL": 'x"\nmodel_provider = "openai'}, {"CODEX_REASONING_EFFORT": 'high"'}):
            with self.subTest(env=env):
                result, config = self.render(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(config, "")

    def test_model_with_trailing_newline_is_rejected(self):
        result, config = self.render(CODEX_MODEL="gpt-test\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, "")
        self.assertIn("::error::模型变量不是合法的模型名", result.stdout)

    def test_empty_effort_is_omitted(self):
        result, config = self.render(CODEX_REASONING_EFFORT="")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("model_reasoning_effort", config)

    def test_key_never_reaches_config_or_output(self):
        result, config = self.render(CODEX_CPA_API_KEY="gpt-test")
        # 密钥恰好出现在配置中（这里与模型名相同）时必须拒绝写入。
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config, "")
        result, config = self.render()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(CPA_KEY, config + result.stdout + result.stderr)
        self.assertNotIn(BASE_URL, result.stdout + result.stderr)

    def test_flows_read_base_url_only_from_secret_and_have_no_url_literal(self):
        for workflow in ("codex-code-review.yml", "codex-dispatch.yml", "codex-plan.yml", "codex-cpa-smoke.yml"):
            text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
            with self.subTest(workflow=workflow):
                self.assertNotIn("vars.CODEX_API_BASE_URL", text)
                self.assertIn("secrets.CODEX_API_BASE_URL", text)
        for path in (SCRIPT, ROOT / "docs/CODEX_DISPATCH.md"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"https://[A-Za-z0-9-]+\.(cn|com|io|net|ai)/v1")
        # 基址为空或未设置时清楚报错，且不打印任何地址。
        for value in ("", "  "):
            result, config = ScriptValidationTest.render(self, CODEX_API_BASE_URL=value)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("secret CODEX_API_BASE_URL", result.stdout)
            self.assertNotIn("https://", result.stdout + result.stderr)
            self.assertEqual(config, "")

    def test_no_hardcoded_model_or_base_url(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"https://[a-z0-9-]+\.[a-z]")
        self.assertNotIn("gpt-", text)


class ConfigurationGuideTest(unittest.TestCase):
    def test_setup_lists_provider_requirements_before_self_check(self):
        guide = (ROOT / "docs/CODEX_DISPATCH.md").read_text(encoding="utf-8")
        setup = guide.split("\n## 一次性配置\n", 1)[1].split("\n### 4. 自检\n", 1)[0]
        for setting in (
            "CODEX_PROVIDER=cpa", "CODEX_CPA_API_KEY", "CODEX_API_BASE_URL", "CODEX_MODEL",
            "CODEX_DISPATCH_MODEL", "CODEX_REVIEW_MODEL", "CODEX_PLAN_MODEL",
            "CODEX_PROVIDER=chatgpt", "CODEX_AUTH_JSON",
        ):
            with self.subTest(setting=setting):
                self.assertIn(f"`{setting}`", setup)

    def test_switching_back_to_chatgpt_mentions_codex_model(self):
        guide = (ROOT / "docs/CODEX_DISPATCH.md").read_text(encoding="utf-8")
        setup = guide.split("\n## 一次性配置\n", 1)[1].split("\n### 4. 自检\n", 1)[0]
        chatgpt = next(p for p in setup.split("\n\n") if "`CODEX_PROVIDER=chatgpt`" in p)
        # 切回 chatgpt 时 CODEX_MODEL 可能仍是 CPA 专用模型名：必须改成 ChatGPT 支持的模型或清空。
        self.assertIn("切回 chatgpt 时还要同时检查 `CODEX_MODEL`", chatgpt)
        self.assertIn("ChatGPT 登录支持的模型", chatgpt)
        self.assertIn("清空它", chatgpt)


class WorkflowWiringTest(unittest.TestCase):
    def test_secrets_only_reach_their_provider(self):
        for flow, (workflow, restore, _, model_var, run) in FLOWS.items():
            text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
            with self.subTest(flow=flow):
                # CODEX_AUTH_JSON 只在 chatgpt 时传入；任何地方都不再无条件引用。
                self.assertEqual(
                    re.findall(r"\$\{\{[^}]*secrets\.CODEX_AUTH_JSON[^}]*\}\}", text),
                    ["${{ vars.CODEX_PROVIDER == 'chatgpt' && secrets.CODEX_AUTH_JSON || '' }}"],
                )
                for expression in re.findall(r"\$\{\{[^}]*secrets\.CODEX_CPA_API_KEY[^}]*\}\}", text):
                    self.assertIn(expression, (
                        "${{ (vars.CODEX_PROVIDER || 'cpa') == 'cpa' && secrets.CODEX_CPA_API_KEY || '' }}",
                        "${{ steps.auth.outputs.provider == 'cpa' && secrets.CODEX_CPA_API_KEY || '' }}",
                    ))
                block = step_block(workflow, restore)
                # chatgpt 时不使用流程专用变量（它可能是只有 CPA 认识的别名），回到原来的 CODEX_MODEL。
                self.assertIn(
                    f"CODEX_MODEL: ${{{{ vars.CODEX_PROVIDER != 'chatgpt' && vars.{model_var} || vars.CODEX_MODEL }}}}", block)
                self.assertIn(
                    f"CODEX_MODEL: ${{{{ steps.auth.outputs.provider != 'chatgpt' && vars.{model_var} || vars.CODEX_MODEL }}}}",
                    step_block(workflow, run))
                self.assertEqual(text.count(model_var), 2)
                # 基址是 secret，只在 cpa 时传入；不再有同名变量。
                self.assertIn(
                    "CODEX_API_BASE_URL: ${{ (vars.CODEX_PROVIDER || 'cpa') == 'cpa' && secrets.CODEX_API_BASE_URL || '' }}", block)
                self.assertNotIn("vars.CODEX_API_BASE_URL", text)
                # 另一处是发布 / 收集结果前的泄露检查，同样只在 cpa 时传入。
                scan = {"review": "Publish review", "plan": "Publish plan", "dispatch": "Collect diff"}[flow]
                self.assertIn(
                    "CODEX_API_BASE_URL: ${{ steps.auth.outputs.provider == 'cpa' && secrets.CODEX_API_BASE_URL || '' }}",
                    step_block(workflow, scan))
                self.assertEqual(text.count("secrets.CODEX_API_BASE_URL"), 2)
                self.assertIn(f"codex_provider_config.py --flow {flow}", block)
                self.assertNotIn("cli_auth_credentials_store", text)

    def test_cpa_key_is_masked_before_codex_starts(self):
        for flow, (workflow, _, _, _, run) in FLOWS.items():
            with self.subTest(flow=flow):
                script = step_script(workflow, run)
                mask = script.index("printf '::add-mask::%s\\n' \"$CODEX_CPA_API_KEY\"")
                start = re.search(r'^codex "\$\{args\[@\]\}"', script, re.M).start()
                self.assertLess(mask, start)

    def test_auth_write_back_runs_only_for_chatgpt(self):
        for flow, (workflow, _, _, _, _) in FLOWS.items():
            with self.subTest(flow=flow):
                block = step_block(workflow, "Persist refreshed auth")
                self.assertIn("steps.auth.outputs.provider == 'chatgpt'", block.split("run:")[0])
                self.assertIn("gh secret set CODEX_AUTH_JSON --env codex", block)

    def test_provider_script_comes_from_trusted_checkout(self):
        dispatch = step_block("codex-dispatch.yml", "Checkout Codex provider script")
        self.assertIn("ref: ${{ github.workflow_sha }}", dispatch)
        self.assertIn("sparse-checkout: scripts/ci/codex_provider_config.py", dispatch)
        self.assertIn("persist-credentials: false", dispatch)
        for workflow in ("codex-code-review.yml", "codex-dispatch.yml"):
            block = step_block(workflow, "Checkout Codex provider script")
            self.assertIn("ref: ${{ github.workflow_sha }}", block)
            self.assertIn("path: codex-policy", block)
        # 审查规则仍取 main，不随共用脚本改变。
        self.assertIn("ref: main", step_block("codex-code-review.yml", "Checkout review policy"))

    def run_self_check(self, provider, shell_tool_state="false", reply=None, record_codex=True):
        if reply is None:
            reply = "OK\n" if provider == "cpa" else "SECRET-REPLY-FRAGMENT-" + "x" * 40
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        (work / "bin").mkdir()
        log = work / "codex.log"
        codex = work / "bin/codex"
        codex.write_text(
            '#!/usr/bin/env bash\n'
            'printf "%s\\n" "$*" >> "$CODEX_LOG"\n'
            'if printf "%s " "$@" | grep -q "features list"; then\n'
            '  if printf "%s " "$@" | grep -q "features.shell_tool=false"; then\n'
            '    echo "shell_tool                               stable             $SHELL_TOOL"\n'
            '  else echo "shell_tool                               stable             true"; fi\n'
            '  exit 0\nfi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  if [ "$1" = -o ]; then printf %s "$REPLY_TEXT" > "$2"; fi; shift\ndone\n')
        codex.chmod(0o755)
        workspace = work / "workspace"
        workspace.mkdir()
        # 沙箱可写的 ~/.cargo/bin 排在最前面，里面放同名假程序；自检只能用记录下的绝对路径。
        home = work / "home"
        hijack_log = work / "hijack.log"
        hijack = codex_hardening.install_hijack_bin(home / ".cargo/bin", hijack_log)
        env = {"PATH": f"{hijack}{os.pathsep}{work / 'bin'}{os.pathsep}{os.environ['PATH']}",
               "HOME": str(home),
               "RUNNER_TEMP": str(work), "GITHUB_WORKSPACE": str(workspace),
               "CODEX_HOME": str(work / "codex-home"), "CODEX_LOG": str(log),
               "CODEX_PROVIDER_RESOLVED": provider, "REPLY_TEXT": reply, "SHELL_TOOL": shell_tool_state,
               "CODEX_CPA_API_KEY": CPA_KEY if provider == "cpa" else ""}
        if record_codex:
            # Install Codex CLI 记录的绝对路径：node 解释器和 Codex 入口脚本（这里用 bash 跑假 codex）。
            env.update({"CODEX_NODE_BIN": "/usr/bin/bash", "CODEX_JS": str(codex)})
        result = subprocess.run(
            ["/usr/bin/bash", "-c", step_script("codex-dispatch.yml", "Self-check (auth and write-back)")],
            env=env, text=True, capture_output=True, check=False)
        self.assertEqual(hijack_log.read_text() if hijack_log.exists() else "", "")
        calls = log.read_text().splitlines() if log.exists() else []
        return result, calls, workspace

    def test_dispatch_self_check_does_not_print_cpa_reply(self):
        reply = "SECRET-REPLY-FRAGMENT-" + "x" * 40
        result, _, _ = self.run_self_check("chatgpt", reply=reply)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SECRET-REPLY", result.stdout)
        # cpa：回复不是 OK 时失败，且不打印回复内容。
        result, _, _ = self.run_self_check("cpa", reply=reply)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("SECRET-REPLY", result.stdout + result.stderr)
        self.assertNotIn(CPA_KEY, result.stdout.replace(f"::add-mask::{CPA_KEY}", ""))

    def test_dispatch_cpa_self_check_requires_exactly_ok(self):
        # 与独立冒烟测试一致：整段回复必须恰好是一行 OK（可带 LF / CRLF 结尾）。
        for reply in ("OK", "OK\n", "OK\r\n"):
            with self.subTest(reply=reply):
                result, _, _ = self.run_self_check("cpa", reply=reply)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("回复为 OK", result.stdout)
        for reply in ("", "ok\n", "OK.\n", " OK\n", "OK\n\n", "OK\nOK\n", "OK, done\n", "NOT OK\n", "OKAY\n"):
            with self.subTest(reply=reply):
                result, _, _ = self.run_self_check("cpa", reply=reply)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("不是单独一行 OK", result.stdout)
                self.assertNotIn("✅", result.stdout)

    def test_dispatch_self_check_needs_recorded_codex_path(self):
        for provider in ("cpa", "chatgpt"):
            with self.subTest(provider=provider):
                result, calls, _ = self.run_self_check(provider, record_codex=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_dispatch_self_check_uses_ci_sandbox_and_disables_shell_tool(self):
        # 手动空白派发和 3 天定时自检都走这一步；两种 provider 一样。
        for provider in ("cpa", "chatgpt"):
            with self.subTest(provider=provider):
                result, calls, workspace = self.run_self_check(provider)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(calls), 2, calls)
                features, run = calls
                self.assertIn("features.shell_tool=false features list", features)
                self.assertTrue(run.startswith("exec "), run)
                self.assertIn("features.shell_tool=false", run)
                self.assertNotRegex(run, r"(^| )(-s|--sandbox)( |$)")
                self.assertIn("approval_policy=\"never\"", run)
                # 工作目录在 GITHUB_WORKSPACE 下（ci 配置允许写），用完即删。
                self.assertIn(f"-C {workspace}/selfcheck-work", run)
                self.assertFalse((workspace / "selfcheck-work").exists())

    def test_dispatch_self_check_stops_if_shell_tool_cannot_be_confirmed_off(self):
        for state in ("true", ""):
            with self.subTest(state=state):
                result, calls, _ = self.run_self_check("cpa", shell_tool_state=state)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 1, calls)
                self.assertTrue(calls[0].find("features list") >= 0)

    def test_chatgpt_ignores_per_flow_model_vars_and_cpa_uses_them(self):
        def evaluate(expression, variables):
            # 只实现这里用到的写法：A != 'x' && V || F，按 Actions 的真假值规则求值。
            match = re.fullmatch(
                r"\$\{\{ (?:vars\.CODEX_PROVIDER|steps\.auth\.outputs\.provider) != 'chatgpt' && "
                r"vars\.(\w+) \|\| vars\.(\w+) \}\}", expression)
            self.assertIsNotNone(match, expression)
            provider = variables.get("provider", "")
            first, fallback = variables.get(match.group(1), ""), variables.get(match.group(2), "")
            value = first if provider != "chatgpt" else False
            return (value or fallback)
        for flow, (workflow, restore, _, model_var, run) in FLOWS.items():
            text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
            expressions = re.findall(r"CODEX_MODEL: (\$\{\{[^\n]*\}\})", text)
            self.assertEqual(len(expressions), 2, expressions)
            for expression in expressions:
                for provider, expected in (("chatgpt", "gpt-original"), ("cpa", "cpa-only-alias"), ("", "cpa-only-alias")):
                    with self.subTest(flow=flow, provider=provider):
                        got = evaluate(expression, {"provider": provider, model_var: "cpa-only-alias",
                                                    "CODEX_MODEL": "gpt-original"})
                        self.assertEqual(got, expected)
                # 专用变量未设置时两种 provider 都回退到 CODEX_MODEL。
                self.assertEqual(evaluate(expression, {"provider": "cpa", "CODEX_MODEL": "m"}), "m")
                self.assertEqual(evaluate(expression, {"provider": "chatgpt", "CODEX_MODEL": ""}), "")


class PostCodexHardeningTest(unittest.TestCase):
    """Codex 运行时沙箱可写 ~/.cargo/bin（PATH 里排在 /usr/bin 前）：之后带密钥的步骤不能调用那里的同名程序。"""

    def all_steps(self):
        for workflow in codex_hardening.FLOWS:
            for step in codex_hardening.run_steps(workflow):
                yield workflow, step

    def test_every_post_codex_step_is_covered(self):
        names = {wf: [s["name"] for s in codex_hardening.run_steps(wf)] for wf in codex_hardening.FLOWS}
        self.assertEqual(names["codex-dispatch.yml"], [
            "Run Codex", "Collect diff", "Self-check (auth and write-back)", "Check write-back permission",
            "Persist refreshed auth", "Remove local credentials", "Report (no change or failure)"])
        self.assertEqual(names["codex-code-review.yml"], [
            "Run Codex review", "Render review", "Publish review", "Persist refreshed auth",
            "Queue review fixes", "Report review failure", "Remove local credentials"])
        self.assertEqual(names["codex-plan.yml"], [
            "Run Codex plan", "Render plan", "Publish plan", "Persist refreshed auth",
            "Report plan failure", "Remove local credentials"])

    def test_steps_use_absolute_shell_and_fix_path_first(self):
        for workflow, step in self.all_steps():
            with self.subTest(workflow=workflow, step=step["name"]):
                first = codex_hardening.FLOWS[workflow][1]
                if step["name"] == first:
                    # Codex 本身需要原来的 PATH（cargo 等）；它一返回就立刻固定 PATH。
                    script = step["run"]
                    call = re.search(r'^codex "\$\{args\[@\]\}".*\n.*\|\| rc=\$\?\n', script, re.M)
                    self.assertIsNotNone(call)
                    after = script[call.end():]
                    after = re.sub(r"^#.*\n", "", after, count=1)
                    self.assertTrue(after.startswith(codex_hardening.PATH_RESET), after[:120])
                    self.assertEqual(script.count('codex "${args[@]}"'), 1)
                    continue
                self.assertEqual(step["shell"], codex_hardening.HARDENED_SHELL)
                body = re.sub(r"^#.*\n", "", step["run"], count=1)
                self.assertTrue(body.startswith(codex_hardening.PATH_RESET), body[:120])
                self.assertEqual(step["run"].count("PATH="), 1)

    def test_steps_call_external_commands_by_absolute_path(self):
        for workflow, step in self.all_steps():
            with self.subTest(workflow=workflow, step=step["name"]):
                words = codex_hardening.command_words(codex_hardening.hardened_part(workflow, step))
                bare = sorted({w for w in words if w in codex_hardening.PINNED or w in codex_hardening.HIJACK_NAMES
                               and w not in ("echo", "printf", "test", "true")})
                self.assertEqual(bare, [])
                for word in words:
                    if "/" in word:
                        self.assertRegex(word, r"^/usr/bin/[a-z0-9]+$")
        # 词法检查本身能发现裸命令（含 $(...)、if !、管道）。
        self.assertEqual(
            [w for w in codex_hardening.command_words(
                "if ! jq . f; then x=\"$(git log | grep a)\"; fi\ncat <<'E'\ngh x\nE\n'sort\nsort'\n")
             if w in codex_hardening.PINNED], ["jq", "git", "grep", "cat"])

    def test_absolute_commands_exist_on_runner(self):
        used = set()
        for workflow, step in self.all_steps():
            used |= {w for w in codex_hardening.command_words(codex_hardening.hardened_part(workflow, step)) if "/" in w}
        used.add(codex_hardening.HARDENED_SHELL.split()[0])
        self.assertIn("/usr/bin/gh", used)
        on_actions = os.environ.get("GITHUB_ACTIONS") == "true"
        for path in sorted(used):
            with self.subTest(path=path):
                if not on_actions and not os.path.exists(path):
                    self.skipTest(f"本机没有 {path}；GitHub ubuntu runner 上必须存在（CI 里会检查）")
                self.assertTrue(os.path.isfile(path) and os.access(path, os.X_OK), path)

    def hijack_env(self, work):
        log = work / "hijack.log"
        hijack = codex_hardening.install_hijack_bin(work / "home/.cargo/bin", log)
        trusted = work / "trusted"
        trusted.mkdir()
        (trusted / "gh").write_text("#!/bin/sh\necho \"$*\" >> \"$TRUSTED_LOG\"\necho '{}'\n", encoding="utf-8")
        (trusted / "codex").write_text(
            'echo "$*" >> "$TRUSTED_LOG"\n'
            'case "$*" in *"features list"*) echo "shell_tool  stable  false"; exit 0;; esac\n'
            'while [ "$#" -gt 0 ]; do [ "$1" = -o ] && printf OK > "$2"; shift; done\n', encoding="utf-8")
        for name in ("gh", "codex"):
            (trusted / name).chmod(0o755)
        for name in ("workspace/work", "codex-home", "codex-result"):
            (work / name).mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", str(work / "pristine.git")], check=True)
        for name, text in (("review.md", "ok\n"), ("plan.md", "ok\n"), ("review.json", "{}"), ("plan.json", "{}"),
                           ("seed-tokens.txt", ""), ("new-tokens.txt", ""), ("last-message.md", "done\n"),
                           ("auth.seed.sha256", "0" * 64), ("codex-home/auth.json", AUTH_JSON),
                           ("codex-stderr.log", "401 Unauthorized\n"), ("codex-events.jsonl", "{}\n"),
                           ("workspace/review-read-check.txt", "e" * 64)):
            (work / name).write_text(text, encoding="utf-8")
        env = {
            "PATH": f"{hijack}{os.pathsep}{os.environ['PATH']}", "HOME": str(work / "home"),
            "RUNNER_TEMP": str(work), "GITHUB_WORKSPACE": str(work / "workspace"),
            "GITHUB_OUTPUT": str(work / "output"), "GITHUB_ENV": str(work / "github_env"),
            "GITHUB_STEP_SUMMARY": str(work / "summary"), "CODEX_HOME": str(work / "codex-home"),
            "TRUSTED_LOG": str(work / "trusted.log"), "CODEX_NODE_BIN": "/usr/bin/bash",
            "CODEX_JS": str(trusted / "codex"), "GH_TOKEN": "fake-gh-token", "REPO": "owner/example",
            "OWNER": "owner", "NUMBER": "7", "HEAD_SHA": "a" * 40, "BASE_SHA": "b" * 40, "MAIN_SHA": "c" * 40,
            "RUN_URL": "https://example.com/run/1", "CODEX_CPA_API_KEY": CPA_KEY, "CODEX_API_BASE_URL": BASE_URL,
            "MAX_ATTEMPTS": "2", "MODE": "task", "RESULT": "failure", "REVIEW_RUN_ID": "1", "REVIEW_RUN_ATTEMPT": "1",
            "PLAN_RUN_ID": "1", "PLAN_RUN_ATTEMPT": "1", "HAS_DIFF": "false", "COMMENT_ID": "5",
        }
        return env, log, trusted

    def run_hardened(self, script, provider):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        env, log, trusted = self.hijack_env(work)
        env["CODEX_PROVIDER_RESOLVED"] = provider
        script = script.replace("/usr/bin/gh ", f"{trusted / 'gh'} ")
        result = subprocess.run(["/usr/bin/bash", "-e", "-o", "pipefail", "-c", script], cwd=work,
                                env=env, text=True, capture_output=True, check=False, timeout=60)
        return result, (log.read_text() if log.exists() else "")

    def test_no_post_codex_step_runs_programs_planted_in_path(self):
        # 每一步按真实脚本运行（只有 gh 换成路径固定的假 gh，避免联网），两种 provider 各一次。
        for workflow, step in self.all_steps():
            script = codex_hardening.hardened_part(workflow, step)
            if step["name"] == codex_hardening.FLOWS[workflow][1]:
                script = "rc=1\n" + script  # Codex 返回失败：走失败归类分支
            for provider in ("cpa", "chatgpt"):
                with self.subTest(workflow=workflow, step=step["name"], provider=provider):
                    result, calls = self.run_hardened(script, provider)
                    self.assertEqual(calls, "", result.stdout + result.stderr)

    def test_hijack_check_detects_unhardened_script(self):
        result, calls = self.run_hardened("jq -n . >/dev/null || :; git --version || :\n", "cpa")
        self.assertIn("/jq ", calls)
        self.assertIn("/git ", calls)


class DispatchCollectTest(unittest.TestCase):
    """Collect diff 必须按原始内容检查暂存文件，二进制补丁不能绕过 CPA 密钥检查。"""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        workspace = self.work / "workspace"
        tree = workspace / "work"
        tree.mkdir(parents=True)
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.test"]
        subprocess.run(["git", "init", "-q", str(tree)], check=True)
        (tree / "README.md").write_text("base\n")
        subprocess.run([*git, "-C", str(tree), "add", "-A"], check=True)
        subprocess.run([*git, "-C", str(tree), "commit", "-q", "-m", "base"], check=True)
        subprocess.run(["cp", "-a", str(tree / ".git"), str(self.work / "pristine.git")], check=True)
        self.tree = tree
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.work),
            "RUNNER_TEMP": str(self.work),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(self.work / "output"),
            "GITHUB_STEP_SUMMARY": str(self.work / "summary"),
            "CODEX_CPA_API_KEY": CPA_KEY,
            "CODEX_API_BASE_URL": BASE_URL,
        }
        (self.work / "seed-tokens.txt").write_text("")
        (self.work / "new-tokens.txt").write_text("")
        (self.work / "last-message.md").write_text("done\n")

    def collect(self):
        # 沙箱可写的 ~/.cargo/bin 排在 PATH 最前面，里面的同名 git / grep 等不能被调用。
        log = self.work / "hijack.log"
        hijack = codex_hardening.install_hijack_bin(self.work / ".cargo/bin", log)
        env = {**self.env, "PATH": f"{hijack}{os.pathsep}{self.env['PATH']}"}
        result = subprocess.run(
            ["/usr/bin/bash", "-e", "-o", "pipefail", "-c", step_script("codex-dispatch.yml", "Collect diff")],
            cwd=self.work, env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(log.read_text() if log.exists() else "", "")
        return result

    def test_base_url_or_host_in_change_is_rejected(self):
        for leaked, binary in (("https://cpa.invalid/v1", False), ("cpa.invalid", False), ("cpa.invalid", True)):
            with self.subTest(leaked=leaked, binary=binary):
                target = self.tree / ("blob.bin" if binary else "notes.txt")
                if binary:
                    target.write_bytes(b"\x00\x01" + leaked.encode() + b"\x00\xff")
                else:
                    target.write_text(f"base={leaked}\n")
                result = self.collect()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("CPA 地址", result.stdout)
                self.assertNotIn("cpa.invalid", result.stdout + result.stderr)
                self.assertFalse((self.work / "codex-result").exists())
                target.unlink()

    def test_base_url_in_summary_is_rejected(self):
        (self.tree / "notes.txt").write_text("ok\n")
        (self.work / "last-message.md").write_text("连到了 cpa.invalid\n")
        result = self.collect()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.work / "codex-result").exists())

    def test_chatgpt_collect_has_no_cpa_needles(self):
        self.env.update({"CODEX_CPA_API_KEY": "", "CODEX_API_BASE_URL": ""})
        (self.tree / "notes.txt").write_text("ok\n")
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_key_inside_binary_file_is_rejected(self):
        (self.tree / "blob.bin").write_bytes(b"\x00\x01\x02" + CPA_KEY.encode() + b"\x00\xff")
        result = self.collect()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("CPA 密钥", result.stdout)
        self.assertFalse((self.work / "codex-result").exists())
        self.assertNotIn(CPA_KEY, result.stdout + result.stderr)

    def test_key_inside_text_file_is_rejected(self):
        (self.tree / "notes.txt").write_text(f"key={CPA_KEY}\n")
        result = self.collect()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.work / "codex-result").exists())

    def test_clean_change_is_collected(self):
        (self.tree / "notes.txt").write_text("ok\n")
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("has_diff=true", (self.work / "output").read_text())


if __name__ == "__main__":
    unittest.main()
