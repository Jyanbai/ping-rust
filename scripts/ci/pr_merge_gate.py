"""Evaluate trusted Actions evidence for the current PR head. No PR code is run."""
import json
import io
import os
from pathlib import Path
import re
import sys
import urllib.request
import urllib.error
import zipfile

CONTEXT = "PR Merge Gate"
REVIEW_STEPS = ["Verify read-only sandbox", "Run Codex review", "Render review", "Publish review", "Upload review attestation"]
VERDICT = re.compile(r"^<!-- codex-review-verdict sha=([0-9a-f]{40}) base=([0-9a-f]{40}) findings=([0-9]+) run=([0-9]+) attempt=([0-9]+) -->$", re.M)


def succeeded(item):
    return item.get("status") == "completed" and item.get("conclusion") == "success"


def check_jobs(expected, jobs):
    errors = []
    for name, steps in expected.items():
        matches = [j for j in jobs if j.get("name") == name]
        if len(matches) != 1 or not succeeded(matches[0]):
            errors.append(f"job 未成功或缺失/重复：{name}")
            continue
        for step in steps:
            matches_s = [s for s in matches[0].get("steps", []) if s.get("name") == step]
            if len(matches_s) != 1 or not succeeded(matches_s[0]):
                errors.append(f"step 未实际成功：{name} / {step}")
    # 新增的 job 同样不得失败或跳过。
    if any(not succeeded(j) for j in jobs):
        errors.append("存在未成功的 job")
    return errors


def evaluate(sha, policy, runs, jobs):
    errors = []
    for workflow, expected in policy.items():
        candidates = [r for r in runs if r.get("head_sha") == sha
                      and r.get("path") == f".github/workflows/{workflow}"
                      and r.get("event") == "pull_request"]
        if not candidates:
            errors.append(f"缺失当前 head 的 PR 运行：{workflow}")
            continue
        run = max(candidates, key=lambda r: (r["id"], r.get("run_attempt", 1)))
        if not succeeded(run):
            errors.append(f"最新运行未成功：{workflow} ({run['id']})")
            continue
        errors.extend(f"{workflow}: {e}" for e in check_jobs(expected, jobs.get(run["id"], [])))
    return errors


def review_evidence(sha, base, comments):
    evidence = []
    for c in comments:
        if c.get("user", {}).get("login") != "github-actions[bot]" or c.get("user", {}).get("type") != "Bot":
            continue
        markers = VERDICT.findall(c.get("body", ""))
        if len(markers) != 1:
            continue
        for head, reviewed_base, count, run_id, attempt in markers:
            if head == sha and reviewed_base == base:
                evidence.append((int(run_id), int(attempt), int(count)))
    return max(evidence) if evidence else None


def review_candidates(number, sha, runs):
    """可信 run-name 在 job 开始前即绑定目标，失败/取消无需先发布评论。"""
    candidates = []
    for run in runs:
        if run.get("head_branch") != "main" or run.get("path") != ".github/workflows/codex-code-review.yml":
            continue
        title = run.get("display_title")
        if ((run.get("event") == "workflow_run" and title == f"Codex Review pr=0 sha={sha}")
                or (run.get("event") == "workflow_dispatch" and title == f"Codex Review pr={number} sha=none")):
            candidates.append(run)
    return candidates


def latest_review(number, sha, runs):
    candidates = review_candidates(number, sha, runs)
    return max(candidates, key=lambda r: (r["id"], r.get("run_attempt", 1))) if candidates else None


def deduplicated_review(run, jobs):
    """自动运行成功选择目标但未执行审查；必须另行验证已有的完整证明。"""
    if (run.get("event") != "workflow_run" or not succeeded(run) or len(jobs) != 1
            or check_jobs({"review": ["Checkout review policy", "Select PR"]}, jobs)):
        return False
    for name in REVIEW_STEPS:
        steps = [s for s in jobs[0].get("steps", []) if s.get("name") == name]
        if len(steps) != 1 or steps[0].get("status") != "completed" or steps[0].get("conclusion") != "skipped":
            return False
    return True


def run_jobs(api, run):
    """失败 job 重跑不包含此前成功的 job，按名称保留各 job 的最新执行。"""
    latest = {}
    for attempt in range(1, run["run_attempt"] + 1):
        current = {}
        for job in api.pages(f"actions/runs/{run['id']}/attempts/{attempt}/jobs", "jobs"):
            current.setdefault(job.get("name"), []).append(job)
        # 保留同一 attempt 的重复项，让 check_jobs 继续拒绝歧义证据。
        latest.update(current)
    return [job for matches in latest.values() for job in matches]


def review_verdict(sha, base, comments, runs, jobs):
    evidence = review_evidence(sha, base, comments)
    if not evidence:
        return ["缺失匹配当前 head/base 的独立 Codex 审查证明"]
    run_id, attempt, count = evidence
    run = runs.get(run_id, {})
    if (count != 0 or run.get("path") != ".github/workflows/codex-code-review.yml"
            or run.get("head_branch") != "main"
            or run.get("event") not in ("workflow_run", "workflow_dispatch")
            or run.get("run_attempt") != attempt or not succeeded(run)):
        return ["独立 Codex 审查有发现、运行未成功或证明不匹配"]
    expected = {"head": sha, "base": base, "findings": 0, "run": run_id, "attempt": attempt}
    if run.get("attestation") != expected:
        return ["缺失可信 Review 运行的证明产物，或产物与当前 head/base 不匹配"]
    return check_jobs({"review": REVIEW_STEPS}, jobs.get(run_id, []))


class GitHub:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        self.root = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        self.token = os.environ["GH_TOKEN"]

    def request(self, path, data=None):
        req = urllib.request.Request(self.root + "/repos/" + self.repo + "/" + path,
                                     data=None if data is None else json.dumps(data).encode(),
                                     headers={"Authorization": "Bearer " + self.token,
                                              "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)

    def pages(self, path, key=None):
        result = []
        for page in range(1, 101):
            sep = "&" if "?" in path else "?"
            data = self.request(f"{path}{sep}per_page=100&page={page}")
            rows = data[key] if key else data
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise RuntimeError("分页超出上限，拒绝使用不完整证据")

    def status(self, sha, state, description):
        self.request(f"statuses/{sha}", {"state": state, "context": CONTEXT,
                     "description": description[:140],
                     "target_url": os.environ["GATE_RUN_URL"]})

    def attestation(self, run):
        artifacts = self.pages(f"actions/runs/{run['id']}/artifacts", "artifacts")
        matches = [a for a in artifacts if a["name"] == f"codex-review-verdict-{run['run_attempt']}" and not a["expired"]]
        if len(matches) != 1:
            return None
        artifact = matches[0]
        if artifact.get("workflow_run", {}).get("id") != run["id"]:
            return None

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        # GitHub 的归档接口重定向到签名下载 URL；不向下载主机转发 API token。
        req = urllib.request.Request(f"{self.root}/repos/{self.repo}/actions/artifacts/{artifact['id']}/zip",
                                     headers={"Authorization": "Bearer " + self.token})
        try:
            urllib.request.build_opener(NoRedirect).open(req, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code != 302:
                raise
            location = error.headers["Location"]
        else:
            raise RuntimeError("证明产物下载未返回预期重定向")
        if not location.startswith("https://"):
            raise RuntimeError("拒绝非 HTTPS 证明产物")
        with urllib.request.urlopen(location, timeout=60) as response:
            payload = response.read(65537)
        if len(payload) > 65536:
            raise RuntimeError("证明产物超过大小上限")
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            files = archive.infolist()
            if len(files) != 1 or files[0].filename != "review-attestation.json" or files[0].file_size > 4096:
                raise RuntimeError("证明产物格式不符合要求")
            return json.loads(archive.read(files[0]))


def inspect_pr(api, number, policy, publish=True):
    pr = api.request(f"pulls/{number}")
    if pr["state"] != "open" or pr["base"]["ref"] != "main":
        return
    sha, base = pr["head"]["sha"], pr["base"]["sha"]
    if publish:
        api.status(sha, "pending", "正在核对当前 head 的必需运行及独立审查")
    try:
        runs = api.pages(f"actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
        runs = [r for r in runs if r.get("path", "").removeprefix(".github/workflows/") in policy
                and any(p.get("number") == number and p.get("head", {}).get("sha") == sha
                        and p.get("base", {}).get("sha") == base for p in r.get("pull_requests", []))]
        jobs = {}
        latest = {}
        for run in runs:
            key = run.get("path")
            if key not in latest or run["id"] > latest[key]["id"]:
                latest[key] = run
        for run in latest.values():
            if succeeded(run):
                jobs[run["id"]] = run_jobs(api, run)
        errors = evaluate(sha, policy, runs, jobs)
        comments = api.pages(f"issues/{number}/comments")
        review_runs = {}
        review_path = "actions/workflows/codex-code-review.yml/runs?branch=main"
        candidates = review_candidates(number, sha, api.pages(review_path, "workflow_runs"))
        selected = latest_review(number, sha, candidates)
        evidence = review_evidence(sha, base, comments)
        if not selected or not succeeded(selected):
            errors.append("当前 PR/head 最新独立审查缺失或尚未实际成功（包括无证明的失败/取消/跳过）")
        if evidence and any(evidence[:2] == (r["id"], r["run_attempt"]) for r in candidates):
            rid, _, _ = evidence
            run = api.request(f"actions/runs/{rid}")
            review_runs[rid] = run
            if (run.get("path") == ".github/workflows/codex-code-review.yml"
                    and run.get("head_branch") == "main" and succeeded(run)
                    and run.get("run_attempt") == evidence[1]):
                jobs[rid] = api.pages(f"actions/runs/{rid}/attempts/{run['run_attempt']}/jobs", "jobs")
                run["attestation"] = api.attestation(run)
            # CI 重跑触发的新自动审查可能由 Select PR 去重。只允许这类成功空运行
            # 沿用证明；其间任何实际审查、手动审查或失败均不得被后续去重遮住。
            for newer in candidates:
                if (newer["id"], newer["run_attempt"]) <= evidence[:2]:
                    continue
                review_runs[newer["id"]] = newer
                skipped_jobs = (api.pages(f"actions/runs/{newer['id']}/attempts/{newer['run_attempt']}/jobs", "jobs")
                                if succeeded(newer) and newer.get("event") == "workflow_run" else [])
                if not deduplicated_review(newer, skipped_jobs):
                    errors.append(f"较新的独立审查不是成功的自动去重运行：{newer['id']}")
        errors += review_verdict(sha, base, comments, review_runs, jobs)
        # 运行可能在取完 jobs 后被重新运行；只允许本次快照仍是最新 attempt。
        if not errors:
            for run in list(latest.values()) + list(review_runs.values()):
                fresh = api.request(f"actions/runs/{run['id']}")
                if fresh.get("run_attempt") != run.get("run_attempt") or not succeeded(fresh):
                    errors.append(f"证据读取期间运行已变化：{run['id']}")
            latest = latest_review(number, sha, api.pages(review_path, "workflow_runs"))
            if (not latest or not succeeded(latest)
                    or (latest["id"], latest["run_attempt"]) != (selected["id"], selected["run_attempt"])):
                errors.append("证据读取期间有新的独立审查，请等待最新运行完成")
        # 写回前重读 PR，避免新提交沿用旧 head/base 的快照。
        current = api.request(f"pulls/{number}")
        if current["head"]["sha"] != sha or current["base"]["sha"] != base or current["state"] != "open":
            errors.append("核对期间 PR 已变化，请等待下一次门禁")
        state = "failure" if errors else "success"
        print(json.dumps({"pr": number, "sha": sha, "base": base, "state": state, "errors": errors}, ensure_ascii=False))
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
                summary.write(f"\n## PR #{number}: {state}\n\nhead `{sha}` / base `{base}`\n\n")
                summary.writelines(f"- {error}\n" for error in errors)
        if publish:
            api.status(sha, state, f"{len(errors)} 项未满足；查看门禁日志" if errors else "当前 head 所有必需检查及独立审查实际成功")
        return errors
    except Exception:
        if publish:
            api.status(sha, "failure", "读取或验证证据失败，请检查门禁运行日志后重试")
        raise


def event_targets(api, event):
    """只核对事件关联的当前 PR；push 和旧 head 事件不扫描整个仓库。"""
    run = event.get("workflow_run")
    if run is None:
        return None, None
    if run.get("path") == ".github/workflows/codex-code-review.yml" or run.get("name") == "Codex Code Review":
        title = re.fullmatch(r"Codex Review pr=([0-9]+) sha=(none|[0-9a-f]{40})", run.get("display_title", ""))
        if not title or run.get("head_branch") != "main":
            return [], None
        number, sha = title.groups()
        if run.get("event") == "workflow_dispatch" and number != "0" and sha == "none":
            return [int(number)], None
        if run.get("event") != "workflow_run" or number != "0" or sha == "none":
            return [], None
    elif run.get("event") == "pull_request":
        sha = run.get("head_sha", "")
    else:
        return [], None
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return [], None
    prs = api.pages(f"commits/{sha}/pulls")
    return [p["number"] for p in prs if p["state"] == "open"
            and p["head"]["sha"] == sha and p["base"]["ref"] == "main"], sha


def main():
    api = GitHub()
    policy = json.loads(Path(__file__).with_name("pr_merge_gate_policy.json").read_text(encoding="utf-8"))
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    number = os.environ.get("PR_NUMBER", "")
    if not number and "pull_request" in event:
        number = str(event["pull_request"]["number"])
    targets, expected_sha = event_targets(api, event)
    if targets is not None:
        numbers = targets
    elif number:
        if not re.fullmatch(r"[1-9][0-9]*", number):
            raise ValueError("PR 编号必须是正整数")
        numbers = [int(number)]
    else:
        numbers = [p["number"] for p in api.pages("pulls?state=open&base=main")]
    for number in numbers:
        if event.get("workflow_run") and event.get("action") in ("requested", "in_progress"):
            pr = api.request(f"pulls/{number}")
            if (pr["state"] == "open" and pr["base"]["ref"] == "main"
                    and (expected_sha is None or pr["head"]["sha"] == expected_sha)):
                api.status(pr["head"]["sha"], "pending", "当前 head 的必需运行或独立审查已开始，等待最终证据")
            continue
        inspect_pr(api, number, policy, publish=os.environ.get("DRY_RUN") != "true")


if __name__ == "__main__":
    main()
