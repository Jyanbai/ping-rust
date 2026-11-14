"""Strict, fail-closed Release checks. Executed only inside GitHub Actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request

TAG = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
TARGETS = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}


class GateError(RuntimeError):
    pass


class Pending(GateError):
    pass


def require(ok, why):
    if not ok:
        raise GateError(why)


def verify_version(tag, manifest_text, lock_text):
    require(TAG.fullmatch(tag or "") is not None, f"tag 非严格 vX.Y.Z：{tag!r}")
    version = tag[1:]
    require(tomllib.loads(manifest_text)["package"]["version"] == version,
            f"tag {tag} 与 Cargo.toml 版本不一致")
    packages = [x for x in tomllib.loads(lock_text)["package"] if x["name"] == "ping-rust"]
    require(len(packages) == 1 and packages[0]["version"] == version,
            "Cargo.lock 中 ping-rust 版本与 tag 不一致")
    return version


def success(obj):
    return obj.get("status") == "completed" and obj.get("conclusion") == "success"


def step_aliases(step):
    """策略步骤可写成字符串，或 {"any_of": [...]} 显式别名清单（用于步骤更名过渡）。"""
    if isinstance(step, str):
        return [step]
    names = step.get("any_of") if isinstance(step, dict) and set(step) == {"any_of"} else None
    require(isinstance(names, list) and len(names) >= 2 and len(set(names)) == len(names)
            and all(isinstance(n, str) and n for n in names), f"无效的策略步骤：{step!r}")
    return names


def verify_jobs(required, jobs):
    by_name = {}
    for job in jobs:
        name = job.get("name")
        require(name and name not in by_name, f"重复或无名 job：{name}")
        by_name[name] = job
        require(success(job), f"job 未实际成功：{name} ({job.get('conclusion')})")
    require(bool(by_name), "workflow 没有实际执行任何 job")
    for name, required_steps in required.items():
        require(name in by_name, f"缺失必需 job：{name}")
        steps = {}
        for step in by_name[name].get("steps", []):
            steps.setdefault(step.get("name"), []).append(step)
        for title in required_steps:
            aliases = step_aliases(title)
            # 别名中恰好一个步骤出现且实际成功；同时出现多个别名同样拒绝。
            found = [step for alias in aliases for step in steps.get(alias, [])]
            require(len(found) == 1 and success(found[0]),
                    f"必需步骤缺失/失败/跳过：{name} / {' | '.join(aliases)}")


def combined_jobs(api, run):
    count = run.get("run_attempt", 1)
    require(isinstance(count, int) and 1 <= count <= 30, "运行 attempt 无效或过多")
    by_name = {}
    for attempt in range(1, count + 1):
        current = {}
        for job in api.pages(f"actions/runs/{run['id']}/attempts/{attempt}/jobs", "jobs"):
            current.setdefault(job.get("name"), []).append(job)
        for name, items in current.items():
            require(name and len(items) == 1, f"同一 attempt 的 job 缺失或重复：{name}")
            by_name[name] = items[0]
    return list(by_name.values())


def latest_for_policy(runs, sha, policy):
    output = {}
    for workflow in policy:
        matching = [r for r in runs if r.get("head_sha") == sha
                    and r.get("event") == "push"
                    and r.get("path") == f".github/workflows/{workflow}"]
        if not matching:
            raise Pending(f"同一 SHA 缺少必需 workflow：{workflow}")
        output[workflow] = max(matching, key=lambda r: (r["id"], r.get("run_attempt", 1)))
    return output


def verify_checks(api, sha, policy):
    require(SHA.fullmatch(sha or "") is not None, "需要完整的 40 位 tag 提交 SHA")
    query = f"actions/runs?head_sha={sha}&event=push"
    selected = latest_for_policy(api.pages(query, "workflow_runs"), sha, policy)
    for name, run in selected.items():
        if run.get("status") != "completed":
            raise Pending(f"{name} 未完成：run {run['id']} ({run.get('status')})")
        require(success(run), f"{name} 最新运行失败/跳过：run {run['id']} ({run.get('conclusion')})")
        verify_jobs(policy[name], combined_jobs(api, run))
    again = latest_for_policy(api.pages(query, "workflow_runs"), sha, policy)
    for name, before in selected.items():
        after = again[name]
        require((before["id"], before.get("run_attempt", 1)) ==
                (after["id"], after.get("run_attempt", 1)) and success(after),
                f"{name} 验证期间运行发生变化")
        live = api.get(f"actions/runs/{before['id']}")
        require(live.get("run_attempt", 1) == before.get("run_attempt", 1) and success(live),
                f"{name} 运行 attempt/结果在检查期间变化")
    return {name: f"{r['id']}/attempt-{r.get('run_attempt', 1)}"
            for name, r in selected.items()}


class API:
    def __init__(self, repo, token):
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""),
                "非法仓库名称")
        require(bool(token), "缺少 Actions 只读 API token")
        self.root = "https://api.github.com/repos/" + repo + "/"
        self.token = token

    def get(self, path):
        request = urllib.request.Request(
            self.root + path,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, ValueError) as error:
            raise GateError(f"GitHub API 请求失败 {path}: {error}") from error

    def pages(self, path, key):
        data = []
        for n in range(1, 21):
            page = self.get(path + ("&" if "?" in path else "?") +
                            f"per_page=100&page={n}")
            rows = page[key]
            require(isinstance(rows, list), f"API 数据不完整：{path}")
            data.extend(rows)
            if len(rows) < 100:
                return data
        raise GateError(f"分页超出上限：{path}")


def verify_artifacts(dist):
    dist = Path(dist)
    expected = {f"ping-rust-{name}.tar.gz" for name in TARGETS}
    actual = {x.name for x in dist.iterdir() if x.is_file()}
    require(actual == expected, f"归档数量或文件名不正确：{sorted(actual)}")
    sums = []
    for target, machine in TARGETS.items():
        name = f"ping-rust-{target}.tar.gz"
        path = dist / name
        require(0 < path.stat().st_size <= 67108864, f"无效归档体积：{name}")
        try:
            with tarfile.open(path, "r:gz") as tar:
                members = tar.getmembers()
                require(len(members) == 1 and members[0].name == "ping-rust"
                        and members[0].isfile() and members[0].mode & 0o111
                        and 0 < members[0].size <= 67108864,
                        f"归档内容/权限异常：{name}")
                binary = tar.extractfile(members[0]).read(67108865)
        except (tarfile.TarError, OSError) as error:
            raise GateError(f"归档损坏：{name}: {error}") from error
        require(len(binary) == members[0].size and binary[:4] == b"\x7fELF"
                and binary[4] == 2 and binary[5] == 1
                and int.from_bytes(binary[18:20], "little") == machine,
                f"二进制不完整或架构不符：{name}")
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    checksum = "\n".join(sorted(sums)) + "\n"
    (dist / "SHA256SUMS").write_text(checksum, encoding="ascii")
    return checksum


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["checks", "artifacts"])
    parser.add_argument("--tag", default=os.getenv("GITHUB_REF_NAME"))
    parser.add_argument("--sha", default=os.getenv("GITHUB_SHA"))
    parser.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--dist", default="dist")
    parser.add_argument("--wait-seconds", type=int, default=0)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    try:
        verify_version(args.tag, (root / "Cargo.toml").read_text(),
                       (root / "Cargo.lock").read_text())
        if args.mode == "artifacts":
            print(verify_artifacts(args.dist))
            return
        policy = json.loads((Path(__file__).with_name("release_gate_policy.json")).read_text())
        api = API(args.repo, os.getenv("GH_TOKEN"))
        end = time.monotonic() + min(max(args.wait_seconds, 0), 4500)
        while True:
            try:
                outcome = verify_checks(api, args.sha, policy)
                print("Release 必需工作流及步骤全部成功："
                      + json.dumps(outcome, ensure_ascii=False))
                return
            except Pending as pending:
                if time.monotonic() >= end:
                    raise
                print(f"等待同 SHA 的必需检查：{pending}", flush=True)
                time.sleep(30)
    except (GateError, OSError, KeyError, ValueError) as error:
        print(f"::error::Release 门禁拒绝：{error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
