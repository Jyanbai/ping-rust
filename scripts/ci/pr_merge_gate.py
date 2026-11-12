"""Evaluate trusted Actions evidence for the current PR head. No PR code is run."""
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

CONTEXT = "PR Merge Gate"
REVIEW_STEPS = ["Verify read-only sandbox", "Run Codex review", "Render review", "Publish review"]
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


def review_verdict(sha, base, comments, runs, jobs):
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
    if not evidence:
        return ["缺失匹配当前 head/base 的独立 Codex 审查证明"]
    run_id, attempt, count = max(evidence)
    run = runs.get(run_id, {})
    if (count != 0 or run.get("path") != ".github/workflows/codex-code-review.yml"
            or run.get("event") not in ("workflow_run", "workflow_dispatch")
            or run.get("run_attempt") != attempt or not succeeded(run)):
        return ["独立 Codex 审查有发现、运行未成功或证明不匹配"]
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


def inspect_pr(api, number, policy, publish=True):
    pr = api.request(f"pulls/{number}")
    if pr["state"] != "open" or pr["base"]["ref"] != "main":
        return
    sha, base = pr["head"]["sha"], pr["base"]["sha"]
    if publish:
        api.status(sha, "pending", "正在核对当前 head 的必需运行及独立审查")
    try:
        runs = api.pages(f"actions/runs?head_sha={sha}&event=pull_request", "workflow_runs")
        jobs = {}
        latest = {}
        for run in runs:
            key = run.get("path")
            if key not in latest or run["id"] > latest[key]["id"]:
                latest[key] = run
        for run in latest.values():
            if succeeded(run):
                jobs[run["id"]] = api.pages(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
        errors = evaluate(sha, policy, runs, jobs)
        comments = api.pages(f"issues/{number}/comments")
        review_runs = {}
        for comment in comments:
            if comment.get("user", {}).get("login") != "github-actions[bot]":
                continue
            for head, reviewed_base, _, run_id, _ in VERDICT.findall(comment.get("body", "")):
                if head != sha or reviewed_base != base:
                    continue
                rid = int(run_id)
                review_runs[rid] = api.request(f"actions/runs/{rid}")
                run = review_runs[rid]
                jobs[rid] = api.pages(f"actions/runs/{rid}/attempts/{run['run_attempt']}/jobs", "jobs")
        errors += review_verdict(sha, base, comments, review_runs, jobs)
        # 运行可能在取完 jobs 后被重新运行；只允许本次快照仍是最新 attempt。
        if not errors:
            for run in list(latest.values()) + list(review_runs.values()):
                fresh = api.request(f"actions/runs/{run['id']}")
                if fresh.get("run_attempt") != run.get("run_attempt") or not succeeded(fresh):
                    errors.append(f"证据读取期间运行已变化：{run['id']}")
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


def main():
    api = GitHub()
    policy = json.loads(Path(__file__).with_name("pr_merge_gate_policy.json").read_text(encoding="utf-8"))
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    number = os.environ.get("PR_NUMBER", "")
    if not number and "pull_request" in event:
        number = str(event["pull_request"]["number"])
    if number:
        if not re.fullmatch(r"[1-9][0-9]*", number):
            raise ValueError("PR 编号必须是正整数")
        numbers = [int(number)]
    else:
        numbers = [p["number"] for p in api.pages("pulls?state=open&base=main")]
    for number in numbers:
        inspect_pr(api, number, policy, publish=os.environ.get("DRY_RUN") != "true")


if __name__ == "__main__":
    main()
