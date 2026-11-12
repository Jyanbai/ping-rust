"""仅在 GitHub Actions 检查真实 Codex 发布包；不登录、不调用模型。"""

import os
import subprocess
import tempfile
from pathlib import Path

from test_codex_review import step_script


with tempfile.TemporaryDirectory(prefix="codex-runtime-") as temporary:
    work = Path(temporary)
    env = {
        **os.environ,
        "HOME": str(work / "home"),
        "RUNNER_TEMP": str(work),
        "GITHUB_PATH": str(work / "github-path"),
        "CODEX_HOME": str(work / "auth-unused"),
    }
    subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step_script("Install pinned Codex CLI")],
        env=env, check=True, timeout=300,
    )
    binary_dir = Path((work / "github-path").read_text().strip())
    subprocess.run([str(binary_dir / "codex"), "--version"],
                   env=env, check=True, timeout=30)
    subprocess.run([str(binary_dir / "codex-code-mode-host"), "--help"],
                   env=env, check=True, timeout=30, stdout=subprocess.DEVNULL)
    print("Codex CLI 与 code-mode host 均能启动，完整运行包校验通过。")
