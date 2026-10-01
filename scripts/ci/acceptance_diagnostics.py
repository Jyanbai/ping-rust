"""Allowlisted diagnostics: never echo arbitrary credential-bearing process output."""

import re


def failure_summary(output):
    markers = (
        "shoes 安装失败，原二进制状态已恢复",
        "请求 shoes 最新 Release 失败",
        "GitHub Release API 返回错误",
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
