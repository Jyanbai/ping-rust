#!/usr/bin/env python3
"""main 分支看门狗：被监视的 workflow 在 main 的 push 上失败时开或更新 main-red issue。

由 .github/workflows/main-watch.yml 调用。规则：

1. 每个提交一个 issue（正文里的隐藏标记 <!-- main-watch sha=… --> 识别，只认 github-actions[bot]
   写的）；每次失败的运行（run id + 第几次尝试）一条评论，写明失败的 job、步骤、判定依据、
   报错前若干行日志（总长有上限）和运行链接。
2. 失败步骤的日志只命中基础设施模式、且是该运行的第 1 次尝试时，rerun failed jobs 一次。
   命中代码失败模式（测试失败、panic、编译错误、断言）或什么都没命中的，不重跑。
3. 这个提交上被监视的运行全部成功后评论并关闭 issue。

手动 dry-run 只打印分类结果和会写的 issue 内容，不写入、不重跑：

  REPO=owner/name WATCHED=$'CI\\n…' python3 scripts/ci/main_watch.py --run-id 123 --dry-run

只用标准库，兼容 Python 3.10（Ubuntu 22.04 runner 自带的版本）。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, TextIO
from urllib.parse import urlencode, urlsplit

BOT_LOGIN = "github-actions[bot]"
LABEL = "main-red"
LABEL_COLOR = "b60205"
LABEL_DESCRIPTION = "main 上 push 触发的检查失败（main-watch 自动维护）"

FAILED = ("failure", "timed_out")
GREEN = ("success", "skipped", "neutral")

ISSUE_MARKER = re.compile(r"<!-- main-watch sha=([0-9a-f]{40}) -->")
RUN_MARKER = re.compile(
    r"<!-- main-watch run=(\d+) attempt=(\d+) verdict=(infra|code) rerun=(yes|no|failed) -->"
)
CLOSE_MARKER = "<!-- main-watch closed -->"

INFRA, CODE, SECONDARY, UNKNOWN = "infra", "code", "secondary", "unknown"
KIND_TEXT = {INFRA: "基础设施", CODE: "代码", SECONDARY: "连带失败", UNKNOWN: "未识别"}
VERDICT_TEXT = {INFRA: "基础设施失败", CODE: "代码失败"}

# 分类只看失败步骤里报错前的这么多行有效输出；评论里每个 job 附这么多行。
CLASSIFY_LINES = 120
DOWNLOAD_CONTEXT_LINES = 40
MAX_LINE_CHARS = 500
MAX_TABLE_JOBS = 30

# ---------------------------------------------------------------------------
# 日志解析
# ---------------------------------------------------------------------------

TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# GitHub 回显 run 脚本时每行以青色开头；这些是脚本源码，不是输出。
COMMAND_COLOR = "\x1b[36;1m"
CURL_PROGRESS = re.compile(
    r"^\s*% Total\s+% Received % Xferd"
    r"|^\s+Dload\s+Upload\s+Total\s+Spent"
    r"|^\s*(?:\d+(?:\.\d+)?[kMGTP]?\s+){8}(?:--:--:--|\d+:\d{2}:\d{2})"
)
CURL_RETRY = re.compile(r"^Warning: (?:Problem : |Transient problem: ).*Will retry in")


@dataclass
class LogLine:
    text: str
    # output | command（脚本回显）| progress（curl 进度条）| step（##[group]Run …）| error（##[error]…）
    kind: str = "output"


def parse_log(raw: str) -> list[LogLine]:
    """去掉 BOM、时间戳和 ANSI 颜色，标出每行的种类。"""
    lines: list[LogLine] = []
    for index, original in enumerate(raw.splitlines()):
        line = original.lstrip("﻿") if index == 0 else original
        line = TIMESTAMP.sub("", line, count=1)
        is_command = line.startswith(COMMAND_COLOR)
        text = ANSI.sub("", line).rstrip()
        if text.startswith("##[endgroup]"):
            continue
        if text.startswith("##[group]"):
            text = text[len("##[group]") :]
            kind = "step" if text.startswith("Run ") else "output"
        elif text.startswith("##[error]"):
            kind = "error"
        elif is_command:
            kind = "command"
        elif CURL_PROGRESS.search(text):
            kind = "progress"
        else:
            kind = "output"
        lines.append(LogLine(text, kind))
    return lines


def failing_step(lines: list[LogLine]) -> tuple[list[LogLine], LogLine | None]:
    """第一条 ##[error] 所在步骤（从它前面最近的 "Run …" 开始）和这条 error。"""
    error_index = next((i for i, line in enumerate(lines) if line.kind == "error"), None)
    end = len(lines) if error_index is None else error_index
    start = 0
    for i in range(end - 1, -1, -1):
        if lines[i].kind == "step":
            start = i
            break
    return lines[start:end], (None if error_index is None else lines[error_index])


# ---------------------------------------------------------------------------
# 分类
# ---------------------------------------------------------------------------

DOWNLOAD_HOSTS = (
    "github.com",
    "githubusercontent.com",
    "static.rust-lang.org",
    "sh.rustup.rs",
    "crates.io",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "deb.debian.org",
    "security.debian.org",
    "rockylinux.org",
    "almalinux.org",
    "docker.io",
    "ghcr.io",
)
GITHUB_HOSTS = ("github.com", "githubusercontent.com")
URL = re.compile(r"https?://[^\s\"'`<>)\]]+")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def host_matches(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


@dataclass
class Pattern:
    label: str
    regex: re.Pattern
    # "" 无条件；download：附近有 curl 进度条/重试提示，或步骤脚本里有下载域名；
    # url / github_url：第 1 个分组里的 URL 指向下载域名 / GitHub。
    context: str = ""


def _p(label: str, regex: str, context: str = "") -> Pattern:
    return Pattern(label, re.compile(regex), context)


INFRA_PATTERNS = [
    # 测试里也有 curl --fail 经本地代理访问的场景（代理坏了会得到 502），所以 curl 的 HTTP 错误
    # 必须能看出是在下载：带进度条或重试提示的 curl，或者步骤脚本里写着下载地址。
    _p("下载返回 HTTP 5xx", r"curl: \(22\) The requested URL returned error: 5\d\d\b", "download"),
    _p("下载被限流（HTTP 403/429）", r"curl: \(22\) The requested URL returned error: (?:403|429)\b", "download"),
    _p("下载返回 HTTP 5xx", r"HTTP status server error \(5\d\d\b[^)]*\) for url \((https?://[^\s)]+)", "url"),
    _p("GitHub 限流", r"HTTP status client error \((?:403|429)\b[^)]*\) for url \((https?://[^\s)]+)", "github_url"),
    _p("GitHub 限流", r"(?i)\brate limit exceeded\b|\bsecondary rate limit\b"),
    _p("GitHub API 限流或服务端错误", r"GitHub (?:Release )?API HTTP (?:403|429|5\d\d)\b"),
    _p("GitHub API 服务端错误", r"\bHTTP 5\d\d: .*\(https://api\.github\.com/"),
    _p("GitHub 服务端错误", r"Response status code does not indicate success: (?:5\d\d|429)\b"),
    _p("rustup 下载失败", r"could not download file from '?https?://|component download failed for "),
    _p(
        "crates.io / cargo 网络错误",
        r"failed to download from `https?://[^`]*crates\.io"
        r"|Unable to update registry `crates-io`"
        r"|failed to query replaced source registry `crates-io`"
        r"|network failure seems to have happened",
    ),
    _p(
        "cargo 网络错误",
        r"\[(?:6|7|28|35|52|55|56)\] .*(?:crates\.io|github\.com|githubusercontent\.com|static\.rust-lang\.org)",
    ),
    _p(
        "apt 源网络错误",
        r"^[EW]: Failed to fetch https?://|^E: Unable to fetch some archives"
        r"|^E: Some index files failed to download|Temporary failure resolving '"
        r"|^Err:\d+ https?://\S+.*(?:Connection|Could not|timed out|Temporary failure|\b50\d\b)"
        r"|Hash Sum mismatch",
    ),
    _p(
        "dnf 源网络错误",
        r"Curl error \(\d+\): .* for https?://|Cannot download repomd\.xml"
        r"|Failed to download metadata for repo|Errors during downloading metadata for repository"
        r"|No URLs in mirrorlist are available|Librepo error",
    ),
    _p(
        "容器镜像拉取失败",
        r"toomanyrequests|pull rate limit|received unexpected HTTP status: 5\d\d"
        r"|net/http: TLS handshake timeout|net/http: request canceled while waiting for connection",
    ),
    _p(
        "GitHub 托管 runner 故障",
        r"The hosted runner (?:lost communication|encountered an error)"
        r"|The runner has received a shutdown signal",
    ),
]

CODE_PATTERNS = [
    _p(
        "Rust 测试失败",
        r"^test .+ \.\.\. FAILED$|^test result: FAILED\b|^failures:$"
        r"|error: test failed, to rerun pass|error: \d+ targets? failed",
    ),
    _p("panic", r"panicked at "),
    _p("Rust 编译错误", r"^error\[E\d{4}\]|^error: could not compile|^error: aborting due to"),
    _p("clippy", r"implied by `-D warnings`"),
    _p("rustfmt 差异", r"^Diff in \S+(?: at line \d+)?:"),
    _p(
        "断言失败",
        r"AssertionError|assertion failed|assertion `[^`]*` failed"
        r"|^FAIL: |^ERROR: test|^FAILED \((?:failures|errors)=",
    ),
    _p("校验和不匹配", r"computed checksums? did NOT match"),
]

# 上游 job 失败、没有上传 artifact 时，下游 job 的连带失败。
SECONDARY_PATTERNS = [
    _p("缺少上游 job 的 artifact", r"Unable to download artifact\(s\): Artifact not found for name"),
]


@dataclass
class Hit:
    kind: str
    label: str
    line: str


@dataclass
class JobVerdict:
    kind: str
    hits: list[Hit]


def _has_download_context(window: list[LogLine], index: int) -> bool:
    low = max(0, index - DOWNLOAD_CONTEXT_LINES)
    high = min(len(window), index + 3)
    return any(
        window[k].kind == "progress" or CURL_RETRY.search(window[k].text)
        for k in range(low, high)
        if k != index
    )


def _match_line(text: str, download_context: Callable[[], bool]) -> list[Hit]:
    hits: list[Hit] = []
    for pattern in INFRA_PATTERNS:
        match = pattern.regex.search(text)
        if not match:
            continue
        if pattern.context == "download" and not download_context():
            continue
        if pattern.context == "url" and not host_matches(host_of(match.group(1)), DOWNLOAD_HOSTS):
            continue
        if pattern.context == "github_url" and not host_matches(host_of(match.group(1)), GITHUB_HOSTS):
            continue
        hits.append(Hit(INFRA, pattern.label, text.strip()))
        break
    for kind, patterns in ((CODE, CODE_PATTERNS), (SECONDARY, SECONDARY_PATTERNS)):
        for pattern in patterns:
            if pattern.regex.search(text):
                hits.append(Hit(kind, pattern.label, text.strip()))
                break
    return hits


def classify_job(lines: list[LogLine]) -> JobVerdict:
    """只看失败步骤：有代码失败模式就是代码失败；否则命中基础设施模式才算基础设施失败。"""
    window, error = failing_step(lines)
    script_downloads = any(
        host_matches(host_of(url), DOWNLOAD_HOSTS)
        for line in window
        if line.kind in ("command", "step")
        for url in URL.findall(line.text)
    )
    candidates = [i for i, line in enumerate(window) if line.kind == "output" and line.text.strip()]
    hits: list[Hit] = []
    for i in candidates[-CLASSIFY_LINES:]:
        hits.extend(
            _match_line(
                window[i].text,
                lambda i=i: script_downloads or _has_download_context(window, i),
            )
        )
    if error is not None:
        hits.extend(_match_line(error.text[len("##[error]") :], lambda: script_downloads))
    kinds = {hit.kind for hit in hits}
    for kind in (CODE, INFRA, SECONDARY):
        if kind in kinds:
            return JobVerdict(kind, hits)
    return JobVerdict(UNKNOWN, hits)


@dataclass
class JobResult:
    name: str
    steps: list[str]
    kind: str
    hits: list[Hit] = field(default_factory=list)
    excerpt: list[str] | None = None
    note: str = ""

    def evidence(self) -> str:
        decisive = [hit for hit in self.hits if hit.kind == self.kind]
        if decisive:
            return f"{decisive[0].label}：{decisive[0].line}"
        return self.note or "没有命中任何已知模式"


@dataclass
class RunAnalysis:
    verdict: str
    reason: str
    jobs: list[JobResult]


def classify_run(jobs: list[JobResult]) -> tuple[str, str]:
    """全部失败的 job 都是基础设施失败（或其连带失败）时才算基础设施失败。"""
    if not jobs:
        return CODE, "没有找到失败的 job，无法确认是基础设施问题。"
    kinds = [job.kind for job in jobs]
    if CODE in kinds:
        return CODE, "有 job 命中代码失败模式。"
    if UNKNOWN in kinds:
        return CODE, "有 job 没有命中任何基础设施模式，无法确认是基础设施问题。"
    if INFRA in kinds:
        return INFRA, "所有失败的 job 都只命中基础设施模式。"
    return CODE, "只有连带失败的 job，找不到源头。"


# ---------------------------------------------------------------------------
# 日志摘录与脱敏
# ---------------------------------------------------------------------------

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
UUID = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
SHARE_LINK = re.compile(
    r"\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls|snell|naive\+https)://\S+"
)


def _redact_ip(match: re.Match) -> str:
    try:
        address = ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)
    return "[redacted-address]" if address.is_global else match.group(0)


def redact(text: str) -> str:
    """公网地址、UUID、分享链接不写进 issue（测试保留地址和回环地址保留）。"""
    text = SHARE_LINK.sub("[redacted-link]", text)
    text = UUID.sub("[redacted-id]", text)
    return IPV4.sub(_redact_ip, text)


def clip(text: str, limit: int = MAX_LINE_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def excerpt(lines: list[LogLine], limit: int) -> list[str]:
    """失败步骤里报错前最后 limit 行（去掉 curl 进度条、合并空行）加上报错那一行。"""
    window, error = failing_step(lines)
    shown: list[str] = []
    for line in window:
        if line.kind == "progress":
            continue
        if not line.text.strip() and (not shown or not shown[-1].strip()):
            continue
        shown.append(line.text)
    shown = shown[-limit:]
    if error is not None:
        shown.append(error.text)
    return [clip(redact(text)) for text in shown]


def inline(text: str) -> str:
    """放进行内代码或表格前去掉反引号、换行和竖线，日志内容不能跳出代码格式。"""
    return text.replace("`", "'").replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def fence_for(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


# ---------------------------------------------------------------------------
# GitHub 访问
# ---------------------------------------------------------------------------


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GhCli:
    """通过 gh api 访问 GitHub（token 由 gh 从 GH_TOKEN 读取），每次调用都有超时。"""

    def __init__(self, timeout: int = 90):
        self.timeout = timeout

    def _call(self, method: str, path: str, payload: Any = None, has_body: bool = False) -> bytes:
        command = ["gh", "api", "-X", method, path]
        data = None
        if has_body:
            command += ["--input", "-"]
            data = json.dumps(payload).encode("utf-8")
        try:
            proc = subprocess.run(
                command, input=data, capture_output=True, timeout=self.timeout, check=False
            )
        except subprocess.TimeoutExpired as error:
            raise GitHubError(f"{method} {path} 超时（{self.timeout} 秒）") from error
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            status = re.search(r"\(HTTP (\d{3})\)", stderr)
            raise GitHubError(
                f"{method} {path} 失败：{clip(stderr, 300)}",
                int(status.group(1)) if status else None,
            )
        return proc.stdout

    def get(self, path: str, params: dict | None = None) -> Any:
        url = path + ("?" + urlencode(params) if params else "")
        out = self._call("GET", url)
        return json.loads(out) if out.strip() else None

    def get_text(self, path: str) -> str:
        return self._call("GET", path).decode("utf-8", "replace")

    def post(self, path: str, payload: Any = None) -> Any:
        out = self._call("POST", path, payload, has_body=payload is not None)
        return json.loads(out) if out.strip() else None

    def patch(self, path: str, payload: Any) -> Any:
        out = self._call("PATCH", path, payload, has_body=True)
        return json.loads(out) if out.strip() else None


def get_pages(gh: Any, path: str, params: dict, key: str | None = None, max_pages: int = 10) -> list:
    items: list = []
    for page in range(1, max_pages + 1):
        data = gh.get(path, {**params, "per_page": 100, "page": page}) or ({} if key else [])
        batch = data.get(key, []) if key else data
        items.extend(batch)
        if len(batch) < 100:
            break
    return items


# ---------------------------------------------------------------------------
# 输出（日志 + job summary）
# ---------------------------------------------------------------------------


def _annotation_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class Output:
    """日志摘录和提交说明来自外部，打印期间暂停 workflow 命令解析（::stop-commands::），
    避免其中的 ##[error]、::add-mask:: 之类被当成命令。"""

    def __init__(self, stream: TextIO, summary_path: str | None = None):
        self.stream = stream
        self.summary_path = summary_path
        self.token: str | None = None
        self.lines: list[str] = []

    def __enter__(self) -> "Output":
        self._stop()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._resume()
        if self.summary_path and self.lines:
            text = "\n".join(self.lines)
            fence = fence_for(text)
            with open(self.summary_path, "a", encoding="utf-8") as summary:
                summary.write(f"{fence}text\n{text}\n{fence}\n")

    def _stop(self) -> None:
        self.token = secrets.token_hex(16)
        print(f"::stop-commands::{self.token}", file=self.stream)

    def _resume(self) -> None:
        if self.token:
            print(f"::{self.token}::", file=self.stream)
            self.token = None

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)
        self.lines.append(text)

    def annotate(self, level: str, message: str) -> None:
        self._resume()
        print(f"::{level}::{_annotation_escape(message)}", file=self.stream)
        self._stop()
        self.lines.append(f"[{level}] {message}")


# ---------------------------------------------------------------------------
# 写入（真实 / dry-run）
# ---------------------------------------------------------------------------


@dataclass
class Issue:
    number: int | None
    state: str
    title: str
    body: str

    def ref(self) -> str:
        return f"#{self.number}" if self.number is not None else "（新 issue）"


class LiveWriter:
    def __init__(self, gh: Any, repo: str, out: Output):
        self.gh, self.repo, self.out = gh, repo, out

    def create_issue(self, title: str, body: str) -> Issue:
        try:
            self.gh.post(
                f"repos/{self.repo}/labels",
                {"name": LABEL, "color": LABEL_COLOR, "description": LABEL_DESCRIPTION},
            )
        except GitHubError as error:
            if error.status != 422:  # 422：标签已存在
                raise
        data = self.gh.post(f"repos/{self.repo}/issues", {"title": title, "body": body, "labels": [LABEL]})
        issue = Issue(data["number"], data.get("state", "open"), title, body)
        self.out.line(f"已新建 issue {issue.ref()}：{title}")
        return issue

    def comment(self, issue: Issue, body: str) -> None:
        self.gh.post(f"repos/{self.repo}/issues/{issue.number}/comments", {"body": body})
        self.out.line(f"已在 {issue.ref()} 评论。")

    def update_body(self, issue: Issue, body: str) -> None:
        self.gh.patch(f"repos/{self.repo}/issues/{issue.number}", {"body": body})
        issue.body = body
        self.out.line(f"已更新 {issue.ref()} 的正文。")

    def set_state(self, issue: Issue, state: str) -> None:
        payload = {"state": state}
        if state == "closed":
            payload["state_reason"] = "completed"
        self.gh.patch(f"repos/{self.repo}/issues/{issue.number}", payload)
        issue.state = state
        self.out.line(f"已把 {issue.ref()} 设为 {state}。")

    def rerun_failed_jobs(self, run_id: int) -> tuple[bool, str]:
        try:
            self.gh.post(f"repos/{self.repo}/actions/runs/{run_id}/rerun-failed-jobs")
        except GitHubError as error:
            self.out.annotate("warning", f"run {run_id} 自动重跑请求失败：{error}")
            return False, str(error)
        self.out.line(f"已对 run {run_id} 执行 rerun failed jobs。")
        return True, ""


class DryRunWriter:
    """只打印会做的事；不调用任何写接口。"""

    def __init__(self, out: Output):
        self.out = out

    def create_issue(self, title: str, body: str) -> Issue:
        self.out.line(f"[dry-run] 会新建 issue（标签 {LABEL}）：{title}")
        return Issue(None, "open", title, body)

    def comment(self, issue: Issue, body: str) -> None:
        self.out.line(f"[dry-run] 会在 {issue.ref()} 评论：")
        self.out.line(body)
        self.out.line("[dry-run] 评论结束")

    def update_body(self, issue: Issue, body: str) -> None:
        self.out.line(f"[dry-run] 会把 {issue.ref()} 的正文写成：")
        self.out.line(body)
        self.out.line("[dry-run] 正文结束")
        issue.body = body

    def set_state(self, issue: Issue, state: str) -> None:
        self.out.line(f"[dry-run] 会把 {issue.ref()} 设为 {state}")
        issue.state = state

    def rerun_failed_jobs(self, run_id: int) -> tuple[bool, str]:
        self.out.line(f"[dry-run] 会对 run {run_id} 执行 rerun failed jobs（实际没有重跑）")
        return True, ""


# ---------------------------------------------------------------------------
# 对账
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    repo: str
    watched: list[str]
    run_url: str = ""
    server_url: str = "https://github.com"
    excerpt_lines: int = 40
    excerpt_bytes: int = 15000
    excerpt_jobs: int = 3
    log_jobs: int = 20
    recent: int = 5


@dataclass
class Record:
    run_id: int
    attempt: int
    verdict: str
    rerun: str


@dataclass
class Context:
    gh: Any
    writer: Any
    out: Output
    settings: Settings


def is_watched_push(run: dict, settings: Settings) -> bool:
    head_repo = (run.get("head_repository") or {}).get("full_name", settings.repo)
    return (
        run.get("name") in settings.watched
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and head_repo == settings.repo
    )


def watched_runs(gh: Any, settings: Settings, sha: str) -> list[dict]:
    """这个提交上每个被监视 workflow 的最新一次 push 运行（字段反映最新一次尝试）。"""
    runs = get_pages(
        gh,
        f"repos/{settings.repo}/actions/runs",
        {"head_sha": sha, "event": "push", "branch": "main"},
        key="workflow_runs",
    )
    latest: dict[str, dict] = {}
    for run in runs:
        if run.get("head_sha") != sha or not is_watched_push(run, settings):
            continue
        current = latest.get(run["name"])
        if current is None or (run.get("created_at", ""), run["id"]) > (current.get("created_at", ""), current["id"]):
            latest[run["name"]] = run
    order = {name: i for i, name in enumerate(settings.watched)}
    return sorted(latest.values(), key=lambda run: order[run["name"]])


def recent_shas(gh: Any, settings: Settings) -> list[str]:
    data = gh.get(
        f"repos/{settings.repo}/actions/runs", {"branch": "main", "event": "push", "per_page": 100}
    ) or {}
    runs = sorted(
        data.get("workflow_runs", []),
        key=lambda run: (run.get("created_at", ""), run.get("id", 0)),
        reverse=True,
    )
    shas: list[str] = []
    for run in runs:
        if is_watched_push(run, settings) and run.get("head_sha") not in shas:
            shas.append(run["head_sha"])
    return shas[: settings.recent]


def find_issues(gh: Any, settings: Settings) -> dict[str, Issue]:
    found: dict[str, Issue] = {}
    for item in get_pages(gh, f"repos/{settings.repo}/issues", {"labels": LABEL, "state": "all"}):
        if "pull_request" in item or (item.get("user") or {}).get("login") != BOT_LOGIN:
            continue
        match = ISSUE_MARKER.search(item.get("body") or "")
        if not match:
            continue
        sha = match.group(1)
        if sha in found and found[sha].number < item["number"]:
            continue
        found[sha] = Issue(item["number"], item.get("state", "open"), item.get("title", ""), item.get("body") or "")
    return found


def read_records(gh: Any, settings: Settings, issue: Issue | None) -> dict[tuple[int, int], Record]:
    records: dict[tuple[int, int], Record] = {}
    if issue is None or issue.number is None:
        return records
    comments = get_pages(gh, f"repos/{settings.repo}/issues/{issue.number}/comments", {})
    for comment in comments:
        if (comment.get("user") or {}).get("login") != BOT_LOGIN:
            continue
        for match in RUN_MARKER.finditer(comment.get("body") or ""):
            run_id, attempt = int(match.group(1)), int(match.group(2))
            records[(run_id, attempt)] = Record(run_id, attempt, match.group(3), match.group(4))
    return records


def analyse_run(ctx: Context, run: dict) -> RunAnalysis:
    settings = ctx.settings
    jobs = get_pages(
        ctx.gh, f"repos/{settings.repo}/actions/runs/{run['id']}/jobs", {"filter": "latest"}, key="jobs"
    )
    failed = [job for job in jobs if job.get("conclusion") in FAILED]
    results: list[JobResult] = []
    for index, job in enumerate(failed):
        steps = [step["name"] for step in job.get("steps") or [] if step.get("conclusion") in FAILED]
        if index >= settings.log_jobs:
            results.append(JobResult(job["name"], steps, UNKNOWN, note="超过日志下载上限，未检查"))
            continue
        try:
            raw = ctx.gh.get_text(f"repos/{settings.repo}/actions/jobs/{job['id']}/logs")
        except GitHubError as error:
            results.append(JobResult(job["name"], steps, UNKNOWN, note=f"日志下载失败：{error}"))
            continue
        lines = parse_log(raw)
        verdict = classify_job(lines)
        results.append(
            JobResult(job["name"], steps, verdict.kind, verdict.hits, excerpt(lines, settings.excerpt_lines))
        )
    verdict, reason = classify_run(results)
    return RunAnalysis(verdict, reason, results)


def all_green(runs: list[dict]) -> bool:
    return bool(runs) and all(
        run.get("status") == "completed" and run.get("conclusion") in GREEN for run in runs
    )


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------

STATUS_TEXT = {
    "success": "✅ 成功",
    "failure": "❌ 失败",
    "timed_out": "⏱️ 超时",
    "cancelled": "⚪ 已取消",
    "skipped": "⏭️ 跳过",
    "neutral": "✅ 中性",
    "action_required": "⚠️ 需要批准",
    "startup_failure": "❌ 启动失败",
}


def status_text(run: dict) -> str:
    if run.get("status") != "completed":
        return "⏳ 运行中" if run.get("status") == "in_progress" else "⏳ 排队中"
    return STATUS_TEXT.get(run.get("conclusion") or "", f"❔ {run.get('conclusion')}")


def commit_subject(runs: list[dict]) -> str:
    for run in runs:
        message = ((run.get("head_commit") or {}).get("message") or "").splitlines()
        if message:
            return message[0].strip()
    return ""


def issue_title(sha: str, runs: list[dict]) -> str:
    subject = commit_subject(runs)
    if len(subject) > 60:
        subject = subject[:59] + "…"
    return f"main 检查失败：{sha[:7]} {subject}".strip()


def record_text(record: Record) -> str:
    base = f"第 {record.attempt} 次：{VERDICT_TEXT[record.verdict]}"
    if record.rerun == "yes":
        return base + "，已自动重跑 1 次"
    if record.rerun == "failed":
        return base + "，自动重跑请求失败"
    if record.verdict == INFRA:
        return base + "，不再自动重跑"
    return base + "，需要人工处理"


def render_body(settings: Settings, sha: str, runs: list[dict], records: dict[tuple[int, int], Record]) -> str:
    subject = commit_subject(runs)
    intro = f"main 上的提交 [`{sha[:7]}`]({settings.server_url}/{settings.repo}/commit/{sha})"
    if subject:
        intro += f"（`{inline(subject)}`）"
    lines = [
        f"<!-- main-watch sha={sha} -->",
        intro + " 由 push 触发的检查有失败。",
        "",
        "| 检查 | 结果 | 尝试 | 判定 |",
        "|---|---|---|---|",
    ]
    for run in runs:
        judged = sorted(
            (record for record in records.values() if record.run_id == run["id"]),
            key=lambda record: record.attempt,
        )
        judgement = "；".join(record_text(record) for record in judged) or "—"
        lines.append(
            f"| [{inline(run['name'])}]({run['html_url']}) | {status_text(run)} "
            f"| {run.get('run_attempt', 1)} | {judgement} |"
        )
    lines += [
        "",
        "- 每次失败的 job、失败步骤、判定依据和日志摘录见下方评论。",
        "- 失败步骤的日志只命中基础设施模式（下载返回 5xx、GitHub 限流、rustup / crates.io / apt / dnf / "
        "镜像仓库网络错误），且是该运行的第 1 次尝试时，自动重跑失败的 job，每个运行最多 1 次。"
        "其余失败需要人工处理。",
        "- 上表的检查全部成功后自动评论并关闭。",
        "",
        "<sub>由 `.github/workflows/main-watch.yml` 自动维护，正文会被覆盖。</sub>",
    ]
    return "\n".join(lines)


def verdict_sentence(analysis: RunAnalysis, record: Record, rerun_error: str, rerun_before: bool) -> str:
    if analysis.verdict == CODE:
        return "判定为代码失败（或无法确认只是基础设施问题），不自动重跑，需要人工处理。"
    if record.rerun == "yes":
        return "判定为基础设施失败，已自动重跑 1 次。"
    if record.rerun == "failed":
        return f"判定为基础设施失败，但自动重跑请求失败（{inline(clip(rerun_error, 200))}），请手动重跑。"
    if record.attempt > 1:
        return f"判定为基础设施失败，但这是第 {record.attempt} 次尝试，不再自动重跑，请人工确认。"
    if rerun_before:
        return "判定为基础设施失败，这个运行已经自动重跑过，不再重跑，请人工确认。"
    return "判定为基础设施失败，但没有自动重跑，请人工确认。"


EXCERPT_ORDER = {CODE: 0, UNKNOWN: 1, INFRA: 2, SECONDARY: 3}


def render_excerpts(settings: Settings, jobs: list[JobResult]) -> list[str]:
    candidates = sorted(
        (job for job in jobs if job.excerpt),
        key=lambda job: EXCERPT_ORDER.get(job.kind, 9),
    )[: settings.excerpt_jobs]
    if not candidates:
        return []
    out = [
        "",
        f"日志摘录（每个 job 取失败步骤报错前最多 {settings.excerpt_lines} 行，最多 {settings.excerpt_jobs} "
        "个 job，已去掉 curl 进度条并脱敏；完整日志见运行页面）：",
    ]
    marker = "（前面的行已截断）"
    budget = settings.excerpt_bytes

    def render_block(title: str, body: list[str]) -> str:
        text = "\n".join(body)
        fence = fence_for(text)
        return f"\n{title}\n\n{fence}text\n{text}\n{fence}"

    for job in candidates:
        title = f"#### {inline(job.name)}"
        body = list(job.excerpt or [])
        # 超长时从前面删行（报错前最后几行最有用），保留至少一行真实日志。
        while utf8_len(render_block(title, body)) > budget and len(body) > 2:
            body = [marker] + body[2:]
        block = render_block(title, body)
        if utf8_len(block) > budget:
            out += ["", "（日志摘录超出长度上限，其余省略）"]
            break
        out.append(block)
        budget -= utf8_len(block)
    return out


def render_run_comment(
    settings: Settings,
    sha: str,
    run: dict,
    analysis: RunAnalysis,
    record: Record,
    rerun_error: str = "",
    rerun_before: bool = False,
) -> str:
    lines = [
        f"<!-- main-watch run={record.run_id} attempt={record.attempt} "
        f"verdict={record.verdict} rerun={record.rerun} -->",
        f"### ❌ {inline(run['name'])} 第 {record.attempt} 次尝试失败",
        "",
        f"[运行页面]({run['html_url']}) · 提交 `{sha[:7]}`",
        "",
        f"**{verdict_sentence(analysis, record, rerun_error, rerun_before)}**",
        "",
        analysis.reason,
        "",
        "| job | 失败步骤 | 判定 | 依据 |",
        "|---|---|---|---|",
    ]
    for job in analysis.jobs[:MAX_TABLE_JOBS]:
        steps = "、".join(job.steps) or "未知"
        lines.append(
            f"| {inline(job.name)} | {inline(steps)} | {KIND_TEXT[job.kind]} "
            f"| `{inline(clip(redact(job.evidence()), 160))}` |"
        )
    if len(analysis.jobs) > MAX_TABLE_JOBS:
        lines.append(f"\n另有 {len(analysis.jobs) - MAX_TABLE_JOBS} 个失败的 job 未列出。")
    lines += render_excerpts(settings, analysis.jobs)
    if settings.run_url:
        lines += ["", f"<sub>[main-watch 运行]({settings.run_url})</sub>"]
    return "\n".join(lines)


def render_close_comment(settings: Settings, sha: str, runs: list[dict]) -> str:
    names = "、".join(f"`{inline(run['name'])}`" for run in runs)
    text = f"✅ `{sha[:7]}` 上被监视的检查都已通过（{names}），关闭。"
    if settings.run_url:
        text += f"\n\n<sub>[main-watch 运行]({settings.run_url})</sub>"
    return text + "\n" + CLOSE_MARKER


def report_analysis(out: Output, run: dict, analysis: RunAnalysis) -> None:
    out.line(
        f"run {run['id']}（{run['name']}，第 {run.get('run_attempt', 1)} 次尝试）"
        f"判定：{VERDICT_TEXT[analysis.verdict]}。{analysis.reason}"
    )
    for job in analysis.jobs:
        steps = "、".join(job.steps) or "未知"
        out.line(f"  - {job.name} / {steps}：{KIND_TEXT[job.kind]}（{clip(redact(job.evidence()), 200)}）")


def reconcile_commit(ctx: Context, sha: str, issue: Issue | None, only_run: int | None = None) -> None:
    gh, writer, out, settings = ctx.gh, ctx.writer, ctx.out, ctx.settings
    short = sha[:7]
    runs = watched_runs(gh, settings, sha)
    if not runs:
        out.line(f"{short}：没有被监视的 main push 运行。")
        return
    out.line(f"{short}：" + "；".join(f"{run['name']} {status_text(run)}" for run in runs))
    records = read_records(gh, settings, issue)
    failed = [run for run in runs if run.get("status") == "completed" and run.get("conclusion") in FAILED]
    targets = [run for run in failed if (run["id"], int(run.get("run_attempt") or 1)) not in records]
    if only_run is not None:
        targets = [run for run in targets if run["id"] == only_run]

    if targets and issue is None:
        issue = writer.create_issue(issue_title(sha, runs), render_body(settings, sha, runs, records))
    elif targets and issue is not None and issue.state == "closed":
        writer.set_state(issue, "open")

    for run in targets:
        attempt = int(run.get("run_attempt") or 1)
        analysis = analyse_run(ctx, run)
        report_analysis(out, run, analysis)
        rerun_before = any(
            record.run_id == run["id"] and record.rerun in ("yes", "failed") for record in records.values()
        )
        rerun, rerun_error = "no", ""
        if analysis.verdict == INFRA and attempt == 1 and not rerun_before:
            ok, rerun_error = writer.rerun_failed_jobs(run["id"])
            rerun = "yes" if ok else "failed"
        record = Record(run["id"], attempt, analysis.verdict, rerun)
        writer.comment(
            issue,
            render_run_comment(settings, sha, run, analysis, record, rerun_error, rerun_before),
        )
        records[(run["id"], attempt)] = record

    if issue is None:
        return
    body = render_body(settings, sha, runs, records)
    if body != issue.body:
        writer.update_body(issue, body)
    if issue.state == "open" and all_green(runs):
        writer.comment(issue, render_close_comment(settings, sha, runs))
        writer.set_state(issue, "closed")


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[0-9]{1,20}$")


def parse_args(argv: list[str] | None, environ: dict) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="main 分支 push 检查看门狗")
    parser.add_argument("--repo", default=environ.get("REPO", ""))
    parser.add_argument("--watched", default=environ.get("WATCHED", ""), help="被监视的 workflow 名，每行一个")
    parser.add_argument("--sha", default=environ.get("EVENT_SHA", ""), help="触发事件的提交")
    parser.add_argument("--run-id", default=environ.get("INPUT_RUN_ID", ""), help="只处理这个运行")
    parser.add_argument("--dry-run", action="store_true", default=environ.get("DRY_RUN") == "1")
    parser.add_argument("--run-url", default=environ.get("RUN_URL", ""))
    parser.add_argument("--server-url", default=environ.get("GITHUB_SERVER_URL") or "https://github.com")
    return parser.parse_args(argv)


def run(ctx: Context, sha: str, run_id: str) -> int:
    settings, out = ctx.settings, ctx.out
    issues = find_issues(ctx.gh, settings)
    only_run: int | None = None
    if run_id:
        only_run = int(run_id)
        target = ctx.gh.get(f"repos/{settings.repo}/actions/runs/{only_run}")
        if not is_watched_push(target, settings):
            out.annotate("error", f"run {only_run} 不是被监视的 workflow 在 main 上的 push 运行。")
            return 1
        if target.get("status") != "completed" or target.get("conclusion") not in FAILED:
            out.line(f"run {only_run} 的状态是 {status_text(target)}，不需要分类。")
        shas = [target["head_sha"]]
    else:
        shas = [sha] if sha else []
        candidates = recent_shas(ctx.gh, settings) + [s for s, issue in issues.items() if issue.state == "open"]
        for candidate in candidates:
            if candidate not in shas:
                shas.append(candidate)
    errors = 0
    for commit in shas:
        try:
            reconcile_commit(ctx, commit, issues.get(commit), only_run)
        except GitHubError as error:
            errors += 1
            out.annotate("error", f"{commit[:7]}：{error}")
    return 1 if errors else 0


def main(
    argv: list[str] | None = None,
    gh: Any = None,
    stream: TextIO | None = None,
    environ: dict | None = None,
) -> int:
    environ = os.environ if environ is None else environ
    args = parse_args(argv, environ)
    watched = [name.strip() for name in args.watched.splitlines() if name.strip()]
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo or ""):
        print("REPO 必须是 owner/name", file=sys.stderr)
        return 2
    if not watched:
        print("WATCHED 不能为空", file=sys.stderr)
        return 2
    if args.sha and not SHA.match(args.sha):
        print("sha 必须是 40 位十六进制", file=sys.stderr)
        return 2
    if args.run_id and not RUN_ID.match(args.run_id):
        print("run id 必须是数字", file=sys.stderr)
        return 2
    settings = Settings(args.repo, watched, run_url=args.run_url, server_url=args.server_url.rstrip("/"))
    gh = gh or GhCli()
    with Output(stream or sys.stdout, environ.get("GITHUB_STEP_SUMMARY")) as out:
        if args.dry_run:
            out.line("dry-run：只打印分类结果和会写的内容，不写 issue、不重跑。")
        writer = DryRunWriter(out) if args.dry_run else LiveWriter(gh, settings.repo, out)
        return run(Context(gh, writer, out, settings), args.sha, args.run_id)


if __name__ == "__main__":
    sys.exit(main())
