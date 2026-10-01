"""Allowlisted diagnostics: never echo arbitrary credential-bearing process output."""

import re
import os
from datetime import datetime, timezone
from pathlib import Path


def preserve_failure_stderr(root, operation, stderr, exit_code):
    """Keep exact stderr private; only allowlisted per-line evidence is uploadable."""
    root = Path(root)
    label = re.sub(r"[^A-Za-z0-9_-]", "_", operation)
    private = root / "private"
    redacted = root / "redacted"
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    redacted.mkdir(parents=True, exist_ok=True)
    os.chmod(private, 0o700)
    raw = private / f"{label}.stderr"
    raw.write_text(stderr, encoding="utf-8")
    os.chmod(raw, 0o600)
    lines = [f"timestamp_utc={datetime.now(timezone.utc).isoformat()}",
             f"operation={label}; exit={exit_code}"]
    lines.extend(f"line {i}: {failure_summary(line)}" for i, line in enumerate(stderr.splitlines(), 1))
    (redacted / f"{label}.stderr.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def failure_summary(output):
    markers = (
        "shoes 安装失败，原二进制状态已恢复",
        "请求 shoes 最新 Release 失败",
        "GitHub Release API 返回错误",
        "GitHub API 网络请求失败",
        "GitHub API JSON 响应无效或读取失败",
        "GITHUB_TOKEN / GH_TOKEN",
        "解析 GitHub Release 信息失败",
        "Release 资产未提供 SHA-256 digest",
        "SHA-256 校验失败",
        "下载流中断",
        "shoes 激活失败",
        "配置验证失败",
        "operation timed out",
        "connection refused",
        "dns error",
        "invalid peer certificate",
        "No space left on device",
        "Permission denied",
    )
    found = [marker for marker in markers if marker in output]
    statuses = re.findall(r"\((\d{3}) [A-Za-z]|HTTP(?: status)?[ :]+(\d{3})", output)
    found += ["HTTP " + status for status in sorted({value for pair in statuses for value in pair if value})]
    return "; ".join(found) or "cause unavailable; private output suppressed"
