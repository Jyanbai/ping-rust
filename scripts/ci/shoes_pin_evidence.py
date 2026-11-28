#!/usr/bin/env python3
"""Collect Release provenance for issue #157 on trusted GitHub Actions runners."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile


REPOSITORY = "https://github.com/cfal/shoes"
API = "https://api.github.com/repos/cfal/shoes"
BASELINE = "v0.3.8"
BASELINE_COMMIT = "7680938b96a245a21d9e481ad009205b956e4436"
BASELINE_MUSL_SHA256 = "83a31e39a622b0a28d74b8c73488bb8aa42b1758251b355685f65c80f484e5a6"
LIMIT = 128 * 1024 * 1024
SUPPORTED_ASSETS = {
    f"shoes-{arch}-unknown-linux-{libc}.tar.gz": (arch, libc)
    for arch in ("x86_64", "aarch64")
    for libc in ("gnu", "musl")
}
CURL = ["curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
        "--connect-timeout", "15", "--max-time", "180"]


def api_json(path):
    data = subprocess.run(
        [*CURL, "--max-filesize", str(1024 * 1024), f"{API}/{path}"],
        check=True, capture_output=True, timeout=185,
    )
    return json.loads(data.stdout)


def resolve_commit(tag, expected):
    ref = api_json(f"git/ref/tags/{tag}")
    if ref.get("ref") != f"refs/tags/{tag}":
        raise ValueError(f"{tag}: Git ref 不匹配")
    obj = ref["object"]
    visited = set()
    while True:
        sha = obj["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or sha in visited:
            raise ValueError(f"{tag}: Git 对象 SHA 无效或 tag 嵌套循环")
        if obj["type"] == "commit":
            if expected is not None and sha != expected:
                raise ValueError(f"{tag}: commit 与预期不符")
            return sha
        if obj["type"] != "tag" or len(visited) >= 8:
            raise ValueError(f"{tag}: tag 未解析到 commit")
        visited.add(sha)
        annotated = api_json(f"git/tags/{sha}")
        if annotated.get("sha") != sha:
            raise ValueError(f"{tag}: annotated tag SHA 不匹配")
        obj = annotated["object"]


def check_git_ref(tag, commit):
    ref = f"refs/tags/{tag}"
    peeled = f"{ref}^{{}}"
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--exit-code", REPOSITORY, ref, peeled],
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        check=True, capture_output=True, text=True, timeout=60,
    )
    refs = {name: sha for sha, name in (line.split("\t") for line in result.stdout.splitlines())}
    if ref not in refs or refs.get(peeled, refs[ref]) != commit:
        raise ValueError(f"{tag}: Git 远端 tag 与 API 解析出的 commit 不一致")


def release_assets(tag):
    release = api_json(f"releases/tags/{tag}")
    if release.get("tag_name") != tag:
        raise ValueError(f"{tag}: Release tag 不匹配")
    selected = {}
    for asset in release["assets"]:
        name = asset["name"]
        if name not in SUPPORTED_ASSETS:
            continue
        if name in selected:
            raise ValueError(f"{tag}: 重复的 Release 资产 {name}")
        selected[name] = asset
    for name, (_arch, libc) in SUPPORTED_ASSETS.items():
        if libc == "musl" and name not in selected:
            raise ValueError(f"{tag}: 缺少必需的 Release 资产 {name}")
    return selected


def download(url, archive):
    subprocess.run(
        [*CURL, "--location", "--proto-redir", "=https", "--max-filesize", str(LIMIT),
         "--output", str(archive), url],
        check=True, timeout=185,
    )


def version_output(tag, binary):
    result = subprocess.run(
        [str(binary), "--version"], check=True, capture_output=True, text=True, timeout=15,
    )
    version_pattern = rf"shoes {re.escape(tag[1:])}(?:\+g[0-9a-f]{{7,40}})?"
    first_line = next(iter((result.stdout.strip() or result.stderr.strip()).splitlines()), "")
    if not re.fullmatch(version_pattern, first_line):
        raise ValueError(f"{tag}: --version 首行不是预期版本行")
    return {"stdout": result.stdout, "stderr": result.stderr}


def verify_asset(tag, asset, directory):
    name = asset["name"]
    arch, _libc = SUPPORTED_ASSETS[name]
    url = f"{REPOSITORY}/releases/download/{tag}/{name}"
    if asset.get("browser_download_url") != url:
        raise ValueError(f"{tag} {name}: Release URL 不匹配")
    digest = asset.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"{tag} {name}: 缺少有效 API SHA-256")
    size = asset.get("size")
    if type(size) is not int or not 0 < size <= LIMIT:
        raise ValueError(f"{tag} {name}: API 归档大小无效")
    if tag == BASELINE and name == "shoes-x86_64-unknown-linux-musl.tar.gz":
        if digest != f"sha256:{BASELINE_MUSL_SHA256}":
            raise ValueError(f"{tag} {name}: API SHA-256 与基线 pin 不符")

    archive = directory / name
    download(url, archive)
    if archive.stat().st_size != size:
        raise ValueError(f"{tag} {name}: 下载归档大小与 API 不符")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != f"sha256:{actual}":
        raise ValueError(f"{tag} {name}: 下载归档 SHA-256 与 API 不符")

    with tarfile.open(archive, "r:gz") as bundle:
        members = [member for member in bundle if Path(member.name).name == "shoes"]
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= LIMIT:
            raise ValueError(f"{tag} {name}: 归档必须包含唯一且大小有效的 shoes 普通文件")
        with bundle.extractfile(members[0]) as stream:
            payload = stream.read()
    record = {"asset": name, "url": url, "size": size, "api_digest": digest,
              "archive_sha256": actual, "binary_sha256": hashlib.sha256(payload).hexdigest()}
    if platform.system() == "Linux" and arch == platform.machine():
        binary = directory / "shoes"
        binary.write_bytes(payload)
        binary.chmod(0o700)
        record["version"] = version_output(tag, binary)
    else:
        record["version_unverified_reason"] = "需要对应架构的 Linux runner"
    return record


def collect(tag, expected_commit):
    commit = resolve_commit(tag, expected_commit)
    check_git_ref(tag, commit)
    assets = release_assets(tag)
    with tempfile.TemporaryDirectory() as directory:
        records = [verify_asset(tag, assets[name], Path(directory)) for name in sorted(assets)]
    check_git_ref(tag, commit)
    return {"tag": tag, "commit": commit, "assets": records,
            "absent_gnu_assets": sorted(SUPPORTED_ASSETS.keys() - assets.keys())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-tag", help="额外核对指定候选 Release（默认只取证基线）")
    parser.add_argument("--expected-candidate-commit", help="从首次取证结果复核候选 tag")
    args = parser.parse_args()
    runner_arch = platform.machine()
    if (os.environ.get("GITHUB_ACTIONS") != "true" or platform.system() != "Linux"
            or runner_arch not in {"x86_64", "aarch64"}):
        parser.error("请在 GitHub Actions 的 x86_64/aarch64 Linux runner 上执行取证")
    if args.candidate_tag is not None and (
            args.candidate_tag == BASELINE or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.candidate_tag)):
        parser.error("候选 tag 必须是区别于基线的 v主版本.次版本.补丁版本")
    if args.expected_candidate_commit is not None:
        if args.candidate_tag is None:
            parser.error("复核候选 commit 必须指定 --candidate-tag")
        if not re.fullmatch(r"[0-9a-f]{40}", args.expected_candidate_commit):
            parser.error("候选 commit 必须是完整的 40 位小写 SHA")
    try:
        checkout = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        report = {
            "repository": os.environ["GITHUB_REPOSITORY"],
            "checkout_sha": checkout,
            "event_sha": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "job": os.environ["GITHUB_JOB"],
            "runner_arch": runner_arch,
            "releases": [collect(BASELINE, BASELINE_COMMIT)],
        }
        if args.candidate_tag is not None:
            report["releases"].append(collect(args.candidate_tag, args.expected_candidate_commit))
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, KeyError) as error:
        parser.exit(1, f"来源取证失败，停止切换 pin：{error}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
