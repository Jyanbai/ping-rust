"""main-watch 的失败分类、issue 写入和重跑规则。

日志样本按真实运行的格式构造（BOM、时间戳、青色脚本回显、curl 进度条），内容取自：
- run 42580129094（CI，main 上 26252f4）Ubuntu 22.04 job：下载 shoes 时 GitHub 返回 504；
- run 41609673046（Legacy instance upgrade）：GitHub Release API 403 rate limit exceeded；
- run 41665983774（CI）AlmaLinux 9 job：单元测试 panic（断言失败）；
- run 41677964633（Ubuntu 24.04 acceptance）：#72 的真实回归，只有 exit code 22、没有 curl 报错。
已脱敏（去掉 UUID、无关 env）。不访问网络：python3 scripts/ci/test_main_watch.py
"""

import io
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main_watch as mw  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "main-watch.yml"
REPO = "Jyanbai/ping-rust"
SHA = "26252f4b07400f58e6f9f9bb4ad8e24b81d27b63"
TS = "2026-11-09T07:35:11.3393728Z "
EXPECTED_WATCHED = [
    "CI",
    "Ubuntu 24.04 acceptance",
    "Chain proxy systemd acceptance",
    "shoes schema compatibility",
    "Legacy instance upgrade",
    "Linux performance and reliability baseline",
    "VLESS-ENC interoperability",
    "Backward compatibility (v0.2.1 reads new files)",
]


def raw_log(*steps):
    """把 [(kind, text), …] 拼成 GitHub 原始日志：BOM、时间戳、脚本回显着色、group 标记。"""
    out = []
    for step in steps:
        for kind, text in step:
            if kind == "run":
                out.append(f"{TS}##[group]Run {text}")
            elif kind == "cmd":
                out.append(f"{TS}\x1b[36;1m{text}\x1b[0m")
            elif kind == "end":
                out.append(f"{TS}##[endgroup]")
            elif kind == "error":
                out.append(f"{TS}##[error]{text}")
            else:
                out.append(f"{TS}{text}")
    return "﻿" + "\n".join(out) + "\n"


# 之前成功的步骤：脚本源码里有 "error:"、"test result: FAILED"、"curl: (22)" 字样，不能算数。
EARLIER_STEPS = [
    [
        ("run", "set -euo pipefail"),
        ("cmd", "set -euo pipefail"),
        ("cmd", 'echo "error: installer accepted an invalid version" >&2'),
        ("cmd", "grep -q 'test result: FAILED' out.txt && echo 'thread x panicked at'"),
        ("cmd", "grep -q 'curl: (22) The requested URL returned error: 503' err.txt"),
        ("out", "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}"),
        ("end", ""),
        ("out", "MIN_INSTALL_SELF_VERSION=0.2.3"),
    ],
    [
        ("run", "python3 scripts/ci/test_codex_dispatch_prompt.py"),
        ("cmd", "python3 scripts/ci/test_codex_dispatch_prompt.py"),
        ("end", ""),
        ("out", "...."),
        ("out", "Ran 4 tests in 0.080s"),
        ("out", ""),
        ("out", "OK"),
    ],
]

CURL_ATTEMPT_504 = [
    ("out", "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current"),
    ("out", "                                 Dload  Upload   Total   Spent    Left  Speed"),
    ("out", ""),
    ("out", "  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0"),
    ("out", "  0    92    0     0    0     0      0      0 --:--:--  0:00:11 --:--:--     0"),
    ("out", "curl: (22) The requested URL returned error: 504"),
]


def download_step(status="504", url="https://github.com/cfal/shoes/releases/download/v0.3.7/shoes-x86_64-unknown-linux-musl.tar.gz"):
    step = [
        ("run", "set -euo pipefail"),
        ("cmd", "set -euo pipefail"),
        ("cmd", 'archive="$RUNNER_TEMP/shoes-v0.3.7.tar.gz"'),
        ("cmd", "curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \\"),
        ("cmd", '  --output "$archive" \\'),
        ("cmd", f"  {url}"),
        ("cmd", 'echo "$SHOES_ARCHIVE_SHA256  $archive" | sha256sum --check --strict'),
        ("out", "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}"),
        ("out", "env:"),
        ("out", "  CARGO_HOME: /home/runner/.cargo"),
        ("end", ""),
    ]
    for retries_left in (3, 2, 1, None):
        step += [(k, t.replace("504", status)) for k, t in CURL_ATTEMPT_504]
        if retries_left:
            step.append(
                ("out", f"Warning: Problem : HTTP error. Will retry in {2 ** (3 - retries_left)} seconds. {retries_left} retries left.")
            )
            step.append(("out", ""))
    step.append(("error", "Process completed with exit code 22."))
    return step


# 外部脚本里的下载：步骤脚本里看不到 URL，只能靠 curl 进度条判断（run 42580129094 的 Xray/Mihomo job）。
SCRIPT_DOWNLOAD_504 = [
    ("run", "bash scripts/ci/external-client-acceptance.sh"),
    ("cmd", "bash scripts/ci/external-client-acceptance.sh"),
    ("out", "shell: /usr/bin/bash --noprofile --norc -e -o pipefail {0}"),
    ("end", ""),
    *CURL_ATTEMPT_504,
    ("out", "Warning: Problem : HTTP error. Will retry in 1 seconds. 3 retries left."),
    *CURL_ATTEMPT_504,
    ("error", "Process completed with exit code 22."),
]

# ping-rust 自己（reqwest）下载 shoes 时的 504（run 42580129126 的 backward-compat job）。
REQWEST_504 = [
    ("run", "set -euo pipefail"),
    ("cmd", "docker exec compat bash /workspace/scripts/ci/backward-compat.sh"),
    ("end", ""),
    ("out", "Error: shoes 安装失败，原二进制状态已恢复"),
    ("out", ""),
    ("out", "Caused by:"),
    (
        "out",
        "    - x86_64-unknown-linux-musl: 下载 shoes-x86_64-unknown-linux-musl.tar.gz 时服务器返回错误: "
        "HTTP status server error (504 Gateway Time-out) for url "
        "(https://github.com/cfal/shoes/releases/download/v0.3.7/shoes-x86_64-unknown-linux-musl.tar.gz)",
    ),
    ("error", "Process completed with exit code 1."),
]

# run 41609673046：旧版 ping-rust 装 shoes 时 GitHub Release API 限流（链接被脚本脱敏）。
RATE_LIMIT_403 = [
    ("run", "sudo --preserve-env=GITHUB_TOKEN,NEW_PING_RUST bash scripts/ci/legacy-upgrade.sh"),
    ("cmd", "sudo --preserve-env=GITHUB_TOKEN,NEW_PING_RUST bash scripts/ci/legacy-upgrade.sh"),
    ("end", ""),
    ("out", "### L1: v0.1.20 → current source"),
    ("out", "ping-rust-x86_64-unknown-linux-musl.tar.gz: OK"),
    ("out", "install-old: exit=1"),
    ("out", "FAILED: exit=1; no retry performed"),
    ("out", "install-old.stderr: Error: shoes 安装失败，原二进制状态已恢复"),
    ("out", ""),
    ("out", "Caused by:"),
    ("out", "    0: GitHub Release API 返回错误"),
    ("out", "    1: HTTP status client error (403 rate limit exceeded) for url ([redacted-link]"),
    ("out", ""),
    ("error", "Process completed with exit code 1."),
]

# run 41665983774 AlmaLinux 9：真实的单元测试断言失败。panic 信息里有 "error sending request"、
# "SOCKS error" 这类网络字样，仍然必须判为代码失败。
UNIT_TEST_PANIC = [
    ("run", "cargo test --locked"),
    ("cmd", "cargo test --locked"),
    ("end", ""),
    ("out", "test sni::preflight::tests::local_sni_preflight_rejects_reality_ip_destination ... ok"),
    ("out", "test sni::preflight::tests::local_sni_preflight_rejects_tls12_target ... FAILED"),
    ("out", "test yaml::tests::yaml_1_2_booleans_and_nulls ... ok"),
    ("out", ""),
    ("out", "failures:"),
    ("out", ""),
    ("out", "---- sni::preflight::tests::local_sni_preflight_rejects_tls12_target stdout ----"),
    ("out", ""),
    (
        "out",
        "thread 'sni::preflight::tests::local_sni_preflight_rejects_tls12_target' (1063) "
        "panicked at src/sni/preflight.rs:411:9:",
    ),
    ("out", "应附上 shoes 的 TLS 版本错误：经 shoes 的请求失败，请更换候选或检查 VPS 出站网络；shoes 错误摘要："),
    (
        "out",
        "[2026-11-03T15:39:46.301 ERROR shoes::tcp::tcp_server] 127.0.0.1:34758 finished with error: "
        "error sending request for url (http://127.0.0.1:39731/generate_204): client error (Connect): "
        "error connecting to socks proxy: SOCKS error: io error during SOCKS handshake",
    ),
    ("out", "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"),
    ("out", ""),
    ("out", "failures:"),
    ("out", "    sni::preflight::tests::local_sni_preflight_rejects_tls12_target"),
    ("out", ""),
    ("out", "test result: FAILED. 273 passed; 1 failed; 3 ignored; 0 measured; 0 filtered out; finished in 3.72s"),
    ("out", ""),
    ("out", "error: test failed, to rerun pass `--bin ping-rust`"),
    ("error", "Process completed with exit code 101."),
]

# run 41677964633：#72 合并后的真实回归，失败只有 exit code 22，没有任何下载错误。
EXIT_22_ONLY = [
    ("run", "set -euo pipefail"),
    ("cmd", "! sudo ss -H -lnt | awk '{print $4}' | grep -Eq '(^|:)25449$'"),
    ("out", "env:"),
    ("out", "  SHOES_URL: https://github.com/cfal/shoes/releases/download/v0.3.6/shoes-x86_64-unknown-linux-musl.tar.gz"),
    ("end", ""),
    ("out", "timeout at share-uri"),
    ("error", "Process completed with exit code 22."),
]

# 经本地 HTTP 代理（Mihomo）访问测试服务器，代理坏了返回 502：这是代码失败，不能当成下载失败。
PROXY_502 = [
    ("run", "bash scripts/ci/external-client-acceptance.sh"),
    ("cmd", "bash scripts/ci/external-client-acceptance.sh"),
    ("end", ""),
    ("out", "snell aes-128-gcm: curl through mihomo"),
    ("out", "curl: (22) The requested URL returned error: 502"),
    ("out", "snell aes-128-gcm: FAIL"),
    ("error", "Process completed with exit code 1."),
]

# 同一个步骤里：下载第一次 504、重试成功，之后测试失败。
RETRY_THEN_TEST_FAILURE = [
    ("run", "bash scripts/ci/shoes-upgrade-acceptance.sh"),
    ("cmd", "bash scripts/ci/shoes-upgrade-acceptance.sh"),
    ("end", ""),
    *CURL_ATTEMPT_504,
    ("out", "Warning: Problem : HTTP error. Will retry in 1 seconds. 3 retries left."),
    ("out", "100 3606k  100 3606k    0     0   325k      0  0:00:11  0:00:11 --:--:--  325k"),
    ("out", "running 1 test"),
    ("out", "thread 'upgrade_keeps_profiles' panicked at tests/upgrade.rs:88:5:"),
    ("out", "assertion `left == right` failed"),
    ("out", "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"),
    ("error", "Process completed with exit code 101."),
]

ARTIFACT_MISSING = [
    ("run", "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    ("out", "with:"),
    ("out", "  name: vless-enc-records"),
    ("end", ""),
    ("out", "Downloading single artifact"),
    ("error", "Unable to download artifact(s): Artifact not found for name: vless-enc-records"),
]


def kind_of(*steps):
    return mw.classify_job(mw.parse_log(raw_log(*steps))).kind


class ClassifyTest(unittest.TestCase):
    def test_real_504_download_is_infra(self):
        verdict = mw.classify_job(mw.parse_log(raw_log(*EARLIER_STEPS, download_step())))
        self.assertEqual(verdict.kind, mw.INFRA)
        self.assertEqual(verdict.hits[0].label, "下载返回 HTTP 5xx")
        self.assertIn("returned error: 504", verdict.hits[0].line)
        self.assertNotIn(mw.CODE, {hit.kind for hit in verdict.hits})

    def test_504_inside_script_is_infra_via_curl_progress(self):
        self.assertEqual(kind_of(SCRIPT_DOWNLOAD_504), mw.INFRA)

    def test_reqwest_504_from_github_is_infra(self):
        self.assertEqual(kind_of(REQWEST_504), mw.INFRA)

    def test_reqwest_5xx_from_local_server_is_not_infra(self):
        local = [(k, t.replace("https://github.com/cfal/shoes/releases/download/v0.3.7", "http://127.0.0.1:18080"))
                 for k, t in REQWEST_504]
        self.assertEqual(kind_of(local), mw.UNKNOWN)

    def test_rate_limit_403_is_infra(self):
        verdict = mw.classify_job(mw.parse_log(raw_log(RATE_LIMIT_403)))
        self.assertEqual(verdict.kind, mw.INFRA)
        self.assertEqual(verdict.hits[0].label, "GitHub 限流")

    def test_curl_403_and_429_from_github_download_are_infra(self):
        for status in ("403", "429"):
            with self.subTest(status=status):
                step = download_step(status, "https://api.github.com/repos/cfal/shoes/releases/tags/v0.3.7")
                verdict = mw.classify_job(mw.parse_log(raw_log(step)))
                self.assertEqual(verdict.kind, mw.INFRA)
                self.assertEqual(verdict.hits[0].label, "下载被限流（HTTP 403/429）")

    def test_real_assertion_failure_is_code(self):
        verdict = mw.classify_job(mw.parse_log(raw_log(*EARLIER_STEPS, UNIT_TEST_PANIC)))
        self.assertEqual(verdict.kind, mw.CODE)
        self.assertNotIn(mw.INFRA, {hit.kind for hit in verdict.hits})

    def test_exit_code_22_without_download_error_is_not_infra(self):
        self.assertEqual(kind_of(EXIT_22_ONLY), mw.UNKNOWN)

    def test_proxy_502_without_download_context_is_not_infra(self):
        self.assertEqual(kind_of(PROXY_502), mw.UNKNOWN)

    def test_mixed_within_one_job_is_code(self):
        self.assertEqual(kind_of(RETRY_THEN_TEST_FAILURE), mw.CODE)

    def test_script_source_lines_do_not_count(self):
        # 只有之前成功的步骤（脚本源码里写着各种失败字样），最后一步是普通失败。
        step = [("run", "false"), ("cmd", "false"), ("end", ""), ("error", "Process completed with exit code 1.")]
        verdict = mw.classify_job(mw.parse_log(raw_log(*EARLIER_STEPS, step)))
        self.assertEqual(verdict.kind, mw.UNKNOWN)
        self.assertEqual(verdict.hits, [])

    def test_failures_after_the_first_error_are_ignored(self):
        upload = [("run", "actions/upload-artifact@x"), ("end", ""), ("out", "test result: FAILED. 0 passed"),
                  ("error", "No files were found with the provided path")]
        self.assertEqual(kind_of(download_step(), upload), mw.INFRA)

    def test_apt_and_crates_io_network_errors_are_infra(self):
        apt = [("run", "sudo apt-get install -y expect"), ("end", ""),
               ("out", "Err:1 http://azure.archive.ubuntu.com/ubuntu noble/main amd64 expect amd64 5.45.4-3 Connection failed [IP: 203.0.113.7 80]"),
               ("out", "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?"),
               ("error", "Process completed with exit code 100.")]
        cargo = [("run", "cargo build --locked"), ("end", ""),
                 ("out", "error: failed to get `serde` as a dependency of package `ping-rust v0.3.0`"),
                 ("out", "Caused by:"),
                 ("out", "  failed to query replaced source registry `crates-io`"),
                 ("out", "  failed to download from `https://index.crates.io/config.json`"),
                 ("out", "  [28] Timeout was reached (Connection timed out after 30001 milliseconds)"),
                 ("error", "Process completed with exit code 101.")]
        self.assertEqual(kind_of(apt), mw.INFRA)
        self.assertEqual(kind_of(cargo), mw.INFRA)

    def test_cargo_compile_error_and_fmt_diff_are_code(self):
        compile_error = [("run", "cargo build"), ("end", ""), ("out", "error[E0425]: cannot find value `x` in this scope"),
                         ("out", "error: could not compile `ping-rust` (bin \"ping-rust\") due to 1 previous error"),
                         ("error", "Process completed with exit code 101.")]
        fmt = [("run", "cargo fmt --all -- --check"), ("end", ""),
               ("out", "Diff in /home/runner/work/ping-rust/ping-rust/src/sni/preflight.rs:326:"),
               ("error", "Process completed with exit code 1.")]
        self.assertEqual(kind_of(compile_error), mw.CODE)
        self.assertEqual(kind_of(fmt), mw.CODE)


def job(kind, name="job"):
    return mw.JobResult(name, ["step"], kind)


class RunVerdictTest(unittest.TestCase):
    def test_all_infra_is_infra(self):
        self.assertEqual(mw.classify_run([job(mw.INFRA), job(mw.INFRA)])[0], mw.INFRA)

    def test_mixed_jobs_are_code(self):
        self.assertEqual(mw.classify_run([job(mw.INFRA), job(mw.CODE)])[0], mw.CODE)
        self.assertEqual(mw.classify_run([job(mw.INFRA), job(mw.UNKNOWN)])[0], mw.CODE)

    def test_artifact_missing_follows_its_source(self):
        missing = mw.classify_job(mw.parse_log(raw_log(ARTIFACT_MISSING)))
        self.assertEqual(missing.kind, mw.SECONDARY)
        self.assertEqual(mw.classify_run([job(mw.INFRA), job(mw.SECONDARY)])[0], mw.INFRA)
        self.assertEqual(mw.classify_run([job(mw.SECONDARY)])[0], mw.CODE)

    def test_no_failed_jobs_is_code(self):
        self.assertEqual(mw.classify_run([])[0], mw.CODE)


class ExcerptTest(unittest.TestCase):
    def test_excerpt_drops_progress_and_keeps_error(self):
        lines = mw.excerpt(mw.parse_log(raw_log(*EARLIER_STEPS, download_step())), 40)
        self.assertEqual(lines[-1], "##[error]Process completed with exit code 22.")
        self.assertIn("curl: (22) The requested URL returned error: 504", lines)
        self.assertFalse(any("--:--:--" in line or "% Total" in line for line in lines))
        self.assertFalse(any("\x1b" in line or line.startswith("2026-") for line in lines))
        # 只取失败步骤，不混进之前的步骤。
        self.assertFalse(any("Ran 4 tests" in line for line in lines))
        self.assertTrue(lines[0].startswith("Run "))

    def test_excerpt_limits_lines(self):
        step = [("run", "x"), ("end", "")] + [("out", f"line {i}") for i in range(200)] + [("error", "boom")]
        lines = mw.excerpt(mw.parse_log(raw_log(step)), 40)
        self.assertEqual(len(lines), 41)
        self.assertEqual(lines[-2], "line 199")

    def test_redaction(self):
        text = mw.redact(
            "for 198.18.0.1 and 20.62.1.5, test 203.0.113.9, loopback 127.0.0.1, "
            "id 0f8fad5b-d9cb-469f-a165-70867728950e, link vless://secret@example.com:443"
        )
        self.assertNotIn("20.62.1.5", text)
        self.assertIn("203.0.113.9", text)
        self.assertIn("127.0.0.1", text)
        self.assertNotIn("0f8fad5b", text)
        self.assertNotIn("vless://", text)

    def test_comment_respects_byte_limit(self):
        settings = mw.Settings(REPO, ["CI"], excerpt_bytes=3000)
        long_lines = ["中文日志行" * 40 + str(i) for i in range(41)]
        jobs = [mw.JobResult(f"job {i}", ["s"], mw.INFRA, excerpt=list(long_lines)) for i in range(3)]
        analysis = mw.RunAnalysis(mw.INFRA, "", jobs)
        record = mw.Record(1, 1, mw.INFRA, "yes")
        comment = mw.render_run_comment(settings, SHA, run_dict(1, "CI"), analysis, record)
        excerpt_part = comment.split("日志摘录", 1)[1]
        self.assertLess(len(excerpt_part.encode("utf-8")), 3000 + 600)
        self.assertIn("（前面的行已截断）", comment)
        self.assertIn(long_lines[-1], comment)

    def test_log_text_cannot_escape_code_formatting(self):
        result = mw.JobResult("j", ["s"], mw.CODE, [mw.Hit(mw.CODE, "panic", "panicked at `x` | @someone")])
        settings = mw.Settings(REPO, ["CI"])
        comment = mw.render_run_comment(
            settings, SHA, run_dict(1, "CI"), mw.RunAnalysis(mw.CODE, "", [result]), mw.Record(1, 1, mw.CODE, "no")
        )
        row = next(line for line in comment.splitlines() if line.startswith("| j |"))
        self.assertEqual(row.count("`"), 2)

        excerpt_with_fence = ["```", "@someone ##[error]x"]
        block = "\n".join(mw.render_excerpts(settings, [mw.JobResult("j", [], mw.CODE, excerpt=excerpt_with_fence)]))
        self.assertIn("````text", block)


# ---------------------------------------------------------------------------
# 对账：用假的 GitHub 记录所有写操作
# ---------------------------------------------------------------------------


def run_dict(run_id, name, conclusion="failure", attempt=1, status="completed", sha=SHA):
    return {
        "id": run_id,
        "name": name,
        "event": "push",
        "head_branch": "main",
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion if status == "completed" else None,
        "run_attempt": attempt,
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
        "created_at": "2026-11-09T07:33:53Z",
        "head_commit": {"message": "chore(shoes): 固定版本升级到 shoes v0.3.7 (#86)\n\nCo-authored-by: x"},
        "head_repository": {"full_name": REPO},
    }


class FakeGitHub:
    def __init__(self):
        self.runs = {}
        self.jobs = {}
        self.logs = {}
        self.issues = {}
        self.comments = {}
        self.writes = []
        self.fail_rerun = False

    def get(self, path, params=None):
        params = params or {}
        page = int(params.get("page", 1))
        base = f"repos/{REPO}/"
        assert path.startswith(base), path
        rest = path[len(base):]
        if rest == "actions/runs":
            runs = list(self.runs.values())
            for key, field in (("head_sha", "head_sha"), ("event", "event"), ("branch", "head_branch")):
                if key in params:
                    runs = [run for run in runs if run[field] == params[key]]
            return {"total_count": len(runs), "workflow_runs": runs if page == 1 else []}
        match = re.fullmatch(r"actions/runs/(\d+)", rest)
        if match:
            return self.runs[int(match.group(1))]
        match = re.fullmatch(r"actions/runs/(\d+)/jobs", rest)
        if match:
            assert params.get("filter") == "latest"
            return {"jobs": self.jobs.get(int(match.group(1)), []) if page == 1 else []}
        if rest == "issues":
            issues = [i for i in self.issues.values() if any(l["name"] == params["labels"] for l in i["labels"])]
            return issues if page == 1 else []
        match = re.fullmatch(r"issues/(\d+)/comments", rest)
        if match:
            return self.comments.get(int(match.group(1)), []) if page == 1 else []
        raise AssertionError(f"unexpected GET {path}")

    def get_text(self, path):
        match = re.fullmatch(rf"repos/{REPO}/actions/jobs/(\d+)/logs", path)
        job_id = int(match.group(1))
        if job_id not in self.logs:
            raise mw.GitHubError("not found", 404)
        return self.logs[job_id]

    def post(self, path, payload=None):
        self.writes.append(("POST", path, payload))
        rest = path[len(f"repos/{REPO}/"):]
        if rest == "labels":
            return {}
        if rest == "issues":
            number = len(self.issues) + 100
            self.issues[number] = {
                "number": number, "state": "open", "title": payload["title"], "body": payload["body"],
                "user": {"login": mw.BOT_LOGIN}, "labels": [{"name": name} for name in payload["labels"]],
            }
            return self.issues[number]
        match = re.fullmatch(r"issues/(\d+)/comments", rest)
        if match:
            self.comments.setdefault(int(match.group(1)), []).append(
                {"user": {"login": mw.BOT_LOGIN}, "body": payload["body"]})
            return {}
        if re.fullmatch(r"actions/runs/\d+/rerun-failed-jobs", rest):
            if self.fail_rerun:
                raise mw.GitHubError("gh: Forbidden (HTTP 403)", 403)
            return None
        raise AssertionError(f"unexpected POST {path}")

    def patch(self, path, payload):
        self.writes.append(("PATCH", path, payload))
        match = re.fullmatch(rf"repos/{REPO}/issues/(\d+)", path)
        self.issues[int(match.group(1))].update(payload)
        return {}

    # 便捷方法
    def add_failed_run(self, run_id, name, log, attempt=1):
        self.runs[run_id] = run_dict(run_id, name, attempt=attempt)
        job_id = run_id * 10
        self.jobs[run_id] = [
            {"id": job_id, "name": f"{name} job", "conclusion": "failure",
             "steps": [{"name": "Install stable shoes", "conclusion": "failure"}]},
            {"id": job_id + 1, "name": "ok job", "conclusion": "success", "steps": []},
        ]
        self.logs[job_id] = log

    def reruns(self):
        return [w for w in self.writes if w[1].endswith("rerun-failed-jobs")]

    def bot_comments(self, number):
        return [c["body"] for c in self.comments.get(number, [])]


WATCHED = ["CI", "Ubuntu 24.04 acceptance"]
INFRA_LOG = raw_log(*EARLIER_STEPS, download_step())
CODE_LOG = raw_log(UNIT_TEST_PANIC)


def reconcile(fake, *extra, environ=None):
    stream = io.StringIO()
    args = ["--repo", REPO, "--watched", "\n".join(WATCHED), "--sha", SHA, *extra]
    code = mw.main(args, gh=fake, stream=stream, environ=environ or {})
    return code, stream.getvalue()


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.fake.runs[2] = run_dict(2, "Ubuntu 24.04 acceptance", "success")

    def only_issue(self):
        self.assertEqual(len(self.fake.issues), 1)
        return next(iter(self.fake.issues.values()))

    def test_infra_failure_opens_issue_and_reruns_once(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        code, output = reconcile(self.fake)
        self.assertEqual(code, 0, output)
        issue = self.only_issue()
        self.assertEqual(issue["labels"], [{"name": "main-red"}])
        self.assertIn(f"<!-- main-watch sha={SHA} -->", issue["body"])
        self.assertIn(SHA[:7], issue["title"])
        self.assertIn("已自动重跑 1 次", issue["body"])
        self.assertEqual(len(self.fake.reruns()), 1)
        self.assertEqual(self.fake.reruns()[0][1], f"repos/{REPO}/actions/runs/1/rerun-failed-jobs")
        [comment] = self.fake.bot_comments(issue["number"])
        self.assertIn("判定为基础设施失败，已自动重跑 1 次", comment)
        self.assertIn("<!-- main-watch run=1 attempt=1 verdict=infra rerun=yes -->", comment)
        self.assertIn("Install stable shoes", comment)
        self.assertIn("curl: (22) The requested URL returned error: 504", comment)
        self.assertIn("https://github.com/Jyanbai/ping-rust/actions/runs/1", comment)

        # 再来一次（例如另一个 workflow 结束，或重跑还没开始）：不重复开 issue、不重复评论、不再重跑。
        writes_before = len(self.fake.writes)
        reconcile(self.fake)
        self.assertEqual(len(self.fake.writes), writes_before)
        self.assertEqual(len(self.fake.reruns()), 1)

    def test_second_attempt_failure_is_not_rerun(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        reconcile(self.fake)
        self.fake.runs[1]["run_attempt"] = 2
        reconcile(self.fake)
        issue = self.only_issue()
        comments = self.fake.bot_comments(issue["number"])
        self.assertEqual(len(comments), 2)
        self.assertIn("第 2 次尝试，不再自动重跑", comments[1])
        self.assertIn("rerun=no", comments[1])
        self.assertEqual(len(self.fake.reruns()), 1)
        self.assertIn("第 2 次：基础设施失败，不再自动重跑", issue["body"])

    def test_code_failure_opens_issue_without_rerun(self):
        self.fake.add_failed_run(1, "CI", CODE_LOG)
        reconcile(self.fake)
        issue = self.only_issue()
        [comment] = self.fake.bot_comments(issue["number"])
        self.assertIn("判定为代码失败", comment)
        self.assertIn("verdict=code rerun=no", comment)
        self.assertIn("panicked at", comment)
        self.assertEqual(self.fake.reruns(), [])

    def test_mixed_jobs_in_one_run_are_not_rerun(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.jobs[1].append({"id": 99, "name": "AlmaLinux 9", "conclusion": "failure",
                                  "steps": [{"name": "Unit and integration tests", "conclusion": "failure"}]})
        self.fake.logs[99] = CODE_LOG
        reconcile(self.fake)
        [comment] = self.fake.bot_comments(self.only_issue()["number"])
        self.assertIn("判定为代码失败", comment)
        # 代码失败的 job 的日志排在前面。
        self.assertLess(comment.index("#### AlmaLinux 9"), comment.index("#### CI job"))
        self.assertEqual(self.fake.reruns(), [])

    def test_missing_log_is_not_rerun(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        del self.fake.logs[10]
        reconcile(self.fake)
        [comment] = self.fake.bot_comments(self.only_issue()["number"])
        self.assertIn("日志下载失败", comment)
        self.assertEqual(self.fake.reruns(), [])

    def test_failed_rerun_request_is_reported_and_not_retried(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.fail_rerun = True
        reconcile(self.fake)
        reconcile(self.fake)
        [comment] = self.fake.bot_comments(self.only_issue()["number"])
        self.assertIn("自动重跑请求失败", comment)
        self.assertIn("rerun=failed", comment)
        self.assertEqual(len(self.fake.reruns()), 1)

    def test_second_failed_workflow_updates_same_issue(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.runs[2] = run_dict(2, "Ubuntu 24.04 acceptance", status="in_progress")
        reconcile(self.fake)
        self.fake.add_failed_run(2, "Ubuntu 24.04 acceptance", CODE_LOG)
        reconcile(self.fake)
        issue = self.only_issue()
        self.assertEqual(len(self.fake.bot_comments(issue["number"])), 2)
        self.assertIn("第 1 次：代码失败，需要人工处理", issue["body"])
        self.assertIn("第 1 次：基础设施失败，已自动重跑 1 次", issue["body"])

    def test_all_green_closes_issue(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        reconcile(self.fake)
        self.fake.runs[1].update(conclusion="success", run_attempt=2)
        reconcile(self.fake)
        issue = self.only_issue()
        self.assertEqual(issue["state"], "closed")
        self.assertEqual(issue["state_reason"], "completed")
        last = self.fake.bot_comments(issue["number"])[-1]
        self.assertIn("都已通过", last)
        self.assertIn(mw.CLOSE_MARKER, last)
        # 关闭后再对账不会重复评论。
        writes_before = len(self.fake.writes)
        reconcile(self.fake)
        self.assertEqual(len(self.fake.writes), writes_before)

    def test_pending_runs_keep_issue_open(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        reconcile(self.fake)
        self.fake.runs[1].update(status="in_progress", conclusion=None, run_attempt=2)
        reconcile(self.fake)
        self.assertEqual(self.only_issue()["state"], "open")
        self.assertIn("⏳ 运行中", self.only_issue()["body"])

    def test_green_commit_without_issue_writes_nothing(self):
        self.fake.runs[1] = run_dict(1, "CI", "success")
        reconcile(self.fake)
        self.assertEqual(self.fake.writes, [])

    def test_other_branches_and_events_are_ignored(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.runs[1]["head_branch"] = "codex/issue-1"
        self.fake.add_failed_run(3, "CI", INFRA_LOG)
        self.fake.runs[3]["event"] = "pull_request"
        self.fake.add_failed_run(4, "Codex CI Fix", INFRA_LOG)
        reconcile(self.fake)
        self.assertEqual(self.fake.writes, [])

    def test_markers_from_other_users_are_ignored(self):
        self.fake.issues[7] = {"number": 7, "state": "open", "title": "fake", "user": {"login": "someone"},
                               "body": f"<!-- main-watch sha={SHA} -->", "labels": [{"name": "main-red"}]}
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        reconcile(self.fake)
        self.assertEqual(len(self.fake.issues), 2)
        self.assertEqual(self.fake.comments.get(7), None)

    def test_dry_run_writes_nothing_and_prints_plan(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        code, output = reconcile(self.fake, "--dry-run")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.fake.writes, [])
        self.assertIn("判定：基础设施失败", output)
        self.assertIn("[dry-run] 会新建 issue（标签 main-red）", output)
        self.assertIn("[dry-run] 会对 run 1 执行 rerun failed jobs（实际没有重跑）", output)
        self.assertIn(f"<!-- main-watch sha={SHA} -->", output)
        self.assertIn("判定为基础设施失败，已自动重跑 1 次", output)
        # 日志内容打印在 stop-commands 范围内，不会被当成 workflow 命令。
        lines = output.splitlines()
        token = lines[0].split("::stop-commands::", 1)[1]
        self.assertTrue(token)
        self.assertEqual(lines[-1], f"::{token}::")
        self.assertIn("##[error]Process completed with exit code 22.", output)

    def test_dry_run_by_run_id(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.add_failed_run(2, "Ubuntu 24.04 acceptance", CODE_LOG)
        stream = io.StringIO()
        code = mw.main(["--repo", REPO, "--watched", "\n".join(WATCHED), "--run-id", "1", "--dry-run"],
                       gh=self.fake, stream=stream, environ={})
        output = stream.getvalue()
        self.assertEqual(code, 0, output)
        self.assertEqual(self.fake.writes, [])
        self.assertIn("run 1（CI，第 1 次尝试）判定：基础设施失败", output)
        self.assertNotIn("run 2（", output)

    def test_run_id_must_be_a_watched_main_push(self):
        self.fake.add_failed_run(1, "CI", INFRA_LOG)
        self.fake.runs[1]["event"] = "pull_request"
        stream = io.StringIO()
        code = mw.main(["--repo", REPO, "--watched", "\n".join(WATCHED), "--run-id", "1", "--dry-run"],
                       gh=self.fake, stream=stream, environ={})
        self.assertEqual(code, 1)

    def test_invalid_inputs_are_rejected(self):
        for args in (["--sha", "abc"], ["--run-id", "1; rm -rf /"], ["--repo", "x y"]):
            with self.subTest(args=args):
                base = ["--repo", REPO, "--watched", "CI"]
                code = mw.main(base + args, gh=FakeGitHub(), stream=io.StringIO(), environ={})
                self.assertEqual(code, 2)

    def test_recent_commits_and_open_issues_are_reconciled(self):
        # 并发组里排队的运行被取消时，下一次（或定时）对账仍然要处理之前的提交。
        older = "1" * 40
        self.fake.runs[5] = run_dict(5, "CI", sha=older)
        self.fake.jobs[5] = [{"id": 50, "name": "x", "conclusion": "failure", "steps": []}]
        self.fake.logs[50] = INFRA_LOG
        code, _ = mw.main(["--repo", REPO, "--watched", "\n".join(WATCHED)], gh=self.fake,
                          stream=io.StringIO(), environ={})
        self.assertEqual(code, 0)
        self.assertIn(older, self.only_issue()["body"])


class GhCliTest(unittest.TestCase):
    def test_calls_have_timeout_and_send_payload_on_stdin(self):
        completed = subprocess.CompletedProcess([], 0, b'{"number": 5}', b"")
        with mock.patch.object(mw.subprocess, "run", return_value=completed) as run:
            result = mw.GhCli(timeout=7).post("repos/a/b/issues", {"title": "t `x`"})
        self.assertEqual(result, {"number": 5})
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["gh", "api", "-X", "POST", "repos/a/b/issues"])
        self.assertEqual(command[5:], ["--input", "-"])
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"title": "t `x`"})
        self.assertEqual(run.call_args.kwargs["timeout"], 7)

    def test_errors_and_timeouts_become_github_errors(self):
        failed = subprocess.CompletedProcess([], 1, b"", b"gh: Validation Failed (HTTP 422)")
        with mock.patch.object(mw.subprocess, "run", return_value=failed):
            with self.assertRaises(mw.GitHubError) as caught:
                mw.GhCli().post("repos/a/b/labels", {"name": "x"})
        self.assertEqual(caught.exception.status, 422)
        with mock.patch.object(mw.subprocess, "run", side_effect=subprocess.TimeoutExpired("gh", 1)):
            with self.assertRaises(mw.GitHubError):
                mw.GhCli().get("repos/a/b/issues", {"page": 1})


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.lines = self.text.splitlines()

    def block_after(self, header, indent):
        start = self.lines.index(header)
        items = []
        for line in self.lines[start + 1:]:
            if not line.startswith(" " * indent) or not line.strip():
                break
            items.append(line.strip().removeprefix("- "))
        return items

    def test_watched_list_matches_trigger_and_workflow_files(self):
        triggers = self.block_after("    workflows:", 6)
        watched = self.block_after("          WATCHED: |-", 12)
        self.assertEqual(triggers, EXPECTED_WATCHED)
        self.assertEqual(watched, EXPECTED_WATCHED)
        names = {}
        for path in WORKFLOW.parent.glob("*.yml"):
            content = path.read_text(encoding="utf-8")
            names[content.splitlines()[0].removeprefix("name: ").strip()] = content
        for name in EXPECTED_WATCHED:
            with self.subTest(name=name):
                self.assertIn(name, names)
                self.assertRegex(names[name], r"\n  push:")

    def test_actions_pinned_permissions_minimal_and_no_interpolation_in_run(self):
        for line in self.lines:
            if "uses:" in line:
                self.assertRegex(line, r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40}\b")
        permissions = self.block_after("    permissions:", 6)
        self.assertEqual(
            sorted(p.split("#")[0].strip() for p in permissions),
            ["actions: write", "contents: read", "issues: write"],
        )
        self.assertIn("permissions:\n  contents: read\n", self.text)
        for index, line in enumerate(self.lines):
            if line.strip().startswith("run:"):
                self.assertNotIn("${{", line)
                indent = len(line) - len(line.lstrip())
                for body in self.lines[index + 1:]:
                    if body.strip() and len(body) - len(body.lstrip()) <= indent:
                        break
                    self.assertNotIn("${{", body)

    def test_dry_run_is_the_default_for_manual_runs(self):
        self.assertRegex(self.text, r"dry_run:\n(?:\s+.*\n)*?\s+default: true")
        self.assertIn("run_id:", self.text)


if __name__ == "__main__":
    unittest.main()
