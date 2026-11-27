#!/usr/bin/env python3
"""为 Codex Dispatch / Code Review / Plan 生成 CI 专用的 $CODEX_HOME/config.toml。

CODEX_PROVIDER=cpa（默认）：沿用 codex-cpa-smoke.yml 已验证的写法，provider 名为 cpa，
走 Responses API，密钥只通过 env_key=CODEX_CPA_API_KEY 从环境变量读取，不写进任何文件，
也不读、不写 CODEX_AUTH_JSON。模型名和 base_url 只来自 environment 变量，没有内置默认值。
CODEX_PROVIDER=chatgpt：生成与切换前逐字相同的配置，auth.json 由工作流里原有的逻辑负责。

用法：codex_provider_config.py --flow review|plan|dispatch --provider cpa|chatgpt \
        --home DIR --runner-temp DIR [--cargo-home DIR]
读取的环境变量（仅 cpa）：CODEX_API_BASE_URL、CODEX_MODEL、CODEX_REASONING_EFFORT、
CODEX_CPA_API_KEY（只检查是否为空，以及生成的文件里没有它）。
出错时只输出 ::error:: 说明，不打印密钥、base_url 或模型返回。
"""

import argparse
import os
import re
import sys
from pathlib import Path

PROVIDERS = ("cpa", "chatgpt")
FLOWS = ("review", "plan", "dispatch")
KEY_ENV = "CODEX_CPA_API_KEY"
# 与 codex-cpa-smoke.yml 相同的校验：只接受 https 基址，避免写入 config.toml 时注入其他配置。
BASE_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
EFFORT_RE = re.compile(r"[a-z]+")
# Codex 默认 ignore_default_excludes = true，命令会继承 *KEY* / *TOKEN* 变量；cpa 时必须关掉。
SHELL_POLICY = (
    "[shell_environment_policy]\n"
    'inherit = "all"\n'
    "ignore_default_excludes = false\n"
    'exclude = ["CODEX_CPA_API_KEY", "CODEX_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"]\n'
)


class ConfigError(Exception):
    pass


def toml_path(value):
    if '"' in value or "\\" in value or "\n" in value:
        raise ConfigError("路径里含有不能写进 config.toml 的字符")
    return value


def top_level(flow):
    """各流程原有的顶层设置（不含 cli_auth_credentials_store）。"""
    if flow == "dispatch":
        return 'default_permissions = "ci"\n'
    return (
        'approval_policy = "never"\nweb_search = "disabled"\nproject_doc_max_bytes = 0\n'
        f'default_permissions = "{flow}"\n'
    )


def permissions(flow, runner_temp, cargo_home):
    """各流程原有的沙箱权限配置，cpa 与 chatgpt 完全相同。"""
    temp = toml_path(runner_temp)
    if flow == "dispatch":
        cargo = toml_path(cargo_home)
        return (
            '[permissions.ci]\nextends = ":workspace"\n\n'
            "[permissions.ci.filesystem]\n"
            f'"{temp}" = "deny"\n'
            f'"{cargo}" = "write"\n\n'
            "[permissions.ci.network]\nenabled = false\n"
        )
    return (
        f'[permissions.{flow}]\nextends = ":read-only"\n\n'
        f'[permissions.{flow}.filesystem]\n"{temp}" = "deny"\n\n'
        f"[permissions.{flow}.network]\nenabled = false\n"
    )


def cpa_settings(env):
    base = (env.get("CODEX_API_BASE_URL") or "").strip()
    if not base:
        raise ConfigError("CODEX_PROVIDER=cpa 需要 environment codex 的变量 CODEX_API_BASE_URL（https 基址），当前未设置")
    if not BASE_RE.match(base):
        raise ConfigError("CODEX_API_BASE_URL 必须是 https 基址（主机名、可选端口和路径）")
    model = (env.get("CODEX_MODEL") or "").strip()
    if not model:
        raise ConfigError("CODEX_PROVIDER=cpa 需要设置本流程的模型变量（或回退用的 CODEX_MODEL），当前未设置")
    if not MODEL_RE.match(model):
        raise ConfigError("模型变量不是合法的模型名")
    # 启动步骤校验原始环境变量，恢复时也按原值校验。
    effort = env.get("CODEX_REASONING_EFFORT", "")
    if effort and not EFFORT_RE.fullmatch(effort):
        raise ConfigError("CODEX_REASONING_EFFORT 只能是小写字母（如 high），当前值无效")
    if not env.get(KEY_ENV):
        raise ConfigError(
            "environment codex 里没有环境级密钥 CODEX_CPA_API_KEY，已停止，不调用模型。"
            "请在本机执行 gh secret set CODEX_CPA_API_KEY --env codex（密钥粘贴给 gh，不要发到聊天里），"
            "不要在仓库或组织级创建同名 secret。"
        )
    return base, model, effort


def render(flow, provider, runner_temp, cargo_home, env):
    if flow not in FLOWS:
        raise ConfigError("未知的 Codex 流程")
    if provider not in PROVIDERS:
        raise ConfigError("CODEX_PROVIDER 只能是 cpa 或 chatgpt")
    perms = permissions(flow, runner_temp, cargo_home)
    if provider == "chatgpt":
        return 'cli_auth_credentials_store = "file"\n' + top_level(flow) + "\n" + perms
    base, model, effort = cpa_settings(env)
    head = f'model = "{model}"\nmodel_provider = "cpa"\n'
    if effort:
        head += f'model_reasoning_effort = "{effort}"\n'
    provider_block = (
        "[model_providers.cpa]\n"
        'name = "CPA"\n'
        f'base_url = "{base}"\n'
        f'env_key = "{KEY_ENV}"\n'
        'wire_api = "responses"\n'
    )
    return head + top_level(flow) + "\n" + provider_block + "\n" + perms + "\n" + SHELL_POLICY


def main(argv=None, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--flow", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--runner-temp", required=True)
    parser.add_argument("--cargo-home", default="")
    args = parser.parse_args(argv)
    try:
        if args.flow == "dispatch" and not args.cargo_home:
            raise ConfigError("dispatch 需要 --cargo-home")
        text = render(args.flow, args.provider, args.runner_temp, args.cargo_home, env)
        key = env.get(KEY_ENV) or ""
        if args.provider == "cpa" and key and key in text:
            raise ConfigError("生成的 config.toml 含有 API 密钥，已停止")
    except ConfigError as error:
        print(f"::error::{error}")
        return 1
    home = Path(args.home)
    home.mkdir(parents=True, exist_ok=True)
    target = home / "config.toml"
    old_umask = os.umask(0o077)
    try:
        target.write_text(text, encoding="utf-8")
    finally:
        os.umask(old_umask)
    print(f"已生成 CI 专用 config.toml：流程 {args.flow}，provider={args.provider}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
