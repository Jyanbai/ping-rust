#!/usr/bin/env python3
"""下载一个失败 job 的日志，打印一段 Markdown 日志摘录（codex-ci-fix.yml 用）。

读取和摘录复用 main_watch.py：gh api 带 --allow-escape-sequences（runner 上的新版 gh 不加就拒绝
输出带 ANSI 颜色的日志；旧版 gh 没有这个参数时自动去掉重试），去掉 BOM、时间戳和颜色，取失败步骤
里第一条 ##[error] 前的若干行，并脱敏。

  REPO=owner/name python3 scripts/ci/job_log_excerpt.py --job-id 123 --title 'CI / Debian 12' --lines 60

日志下载失败时也打印一段说明（带失败原因）并以 0 退出，不中断汇总。

只用标准库，兼容 Python 3.10。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Any, TextIO

import main_watch as mw


def render(title: str, lines: list[str] | None, error: str = "") -> str:
    heading = f"\n### {mw.inline(title)}\n\n"
    if lines is None:
        return heading + f"（日志下载失败：{mw.inline(error)}）\n"
    if not lines:
        return heading + "（日志里没有可摘录的输出）\n"
    body = "\n".join(lines)
    fence = mw.fence_for(body)
    return heading + f"{fence}text\n{body}\n{fence}\n"


def excerpt_section(gh: Any, repo: str, job_id: str, title: str, limit: int) -> str:
    try:
        raw = gh.get_text(f"repos/{repo}/actions/jobs/{job_id}/logs")
    except mw.GitHubError as error:
        return render(title, None, str(error))
    return render(title, mw.excerpt(mw.parse_log(raw), limit))


def main(
    argv: list[str] | None = None,
    gh: Any = None,
    stream: TextIO | None = None,
    environ: dict | None = None,
) -> int:
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=environ.get("REPO", ""))
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--lines", type=int, default=60)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo or ""):
        print("REPO 必须是 owner/name", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[0-9]{1,20}", args.job_id):
        print("job id 必须是数字", file=sys.stderr)
        return 2
    if args.lines < 1:
        print("--lines 必须是正整数", file=sys.stderr)
        return 2
    (stream or sys.stdout).write(excerpt_section(gh or mw.GhCli(), args.repo, args.job_id, args.title, args.lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
