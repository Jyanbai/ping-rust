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

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/codex_provider_config.py"
WORKFLOWS = ROOT / ".github/workflows"
BASE_URL = "https://cpa.example.test/v1"
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
            "CODEX_API_BASE_URL": BASE_URL,
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
        self.assertIn(f"::add-mask::{BASE_URL}", result.stdout)
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
        for bad in ("http://cpa.example.test/v1", 'https://x"\nmodel = "evil', "https://x/v1?a=b", "ftp://x"):
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

    def test_no_hardcoded_model_or_base_url(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"https://[a-z0-9-]+\.[a-z]")
        self.assertNotIn("gpt-", text)


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
                self.assertIn(f"CODEX_MODEL: ${{{{ vars.{model_var} || vars.CODEX_MODEL }}}}", block)
                self.assertIn(f"CODEX_MODEL: ${{{{ vars.{model_var} || vars.CODEX_MODEL }}}}", step_block(workflow, run))
                self.assertIn("CODEX_API_BASE_URL: ${{ vars.CODEX_API_BASE_URL }}", block)
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

    def test_dispatch_self_check_does_not_print_cpa_reply(self):
        reply = "SECRET-REPLY-FRAGMENT-" + "x" * 40
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "bin").mkdir()
            codex = work / "bin/codex"
            codex.write_text('#!/usr/bin/env bash\nwhile [ "$#" -gt 0 ]; do\n'
                             '  if [ "$1" = -o ]; then printf %s "$REPLY_TEXT" > "$2"; fi; shift\ndone\n')
            codex.chmod(0o755)
            for provider, printed in (("cpa", False), ("chatgpt", True)):
                with self.subTest(provider=provider):
                    env = {"PATH": f"{work / 'bin'}{os.pathsep}{os.environ['PATH']}",
                           "RUNNER_TEMP": str(work), "CODEX_HOME": str(work / "codex-home"),
                           "CODEX_PROVIDER_RESOLVED": provider, "REPLY_TEXT": reply,
                           "CODEX_CPA_API_KEY": CPA_KEY if provider == "cpa" else ""}
                    result = subprocess.run(
                        ["bash", "-c", step_script("codex-dispatch.yml", "Self-check (auth and write-back)")],
                        env=env, text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual("SECRET-REPLY" in result.stdout, printed)
                    self.assertNotIn(CPA_KEY, result.stdout.replace(f"::add-mask::{CPA_KEY}", ""))


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
        }
        (self.work / "seed-tokens.txt").write_text("")
        (self.work / "new-tokens.txt").write_text("")
        (self.work / "last-message.md").write_text("done\n")

    def collect(self):
        return subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step_script("codex-dispatch.yml", "Collect diff")],
            cwd=self.work, env=self.env, text=True, capture_output=True, check=False,
        )

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
