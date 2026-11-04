# Codex Dispatch：在 GitHub 上用评论给 Codex 派任务

`.github/workflows/codex-dispatch.yml` 让仓库所有者用一条评论把任务交给 Codex，Codex 直接在 GitHub Actions 的 runner 上写代码：

| 在哪里评论 | 写法 | 结果 |
|---|---|---|
| PR | `/codex <要改什么>` | Codex 在该 PR 的分支上继续改，结果推到**同一个 PR** |
| issue | `/codex [补充要求]` | Codex 从 `main` 开始实现这个 issue，推到新分支并开新 PR（`Closes #issue`） |
| Actions 页面 | Run workflow，填 `prompt`（可选 `pr` / `base`） | 同上，不用留评论 |
| Actions 页面 | Run workflow，`prompt` 留空 | 只做自检：Codex 登录、凭据写回权限 |

> 本功能已于 2026-11-03 在真实 runner 上实测通过。

- 只接受仓库所有者本人的评论或手动触发（以及下面"CI 失败后自动派回 Codex"的派发），其他人评论 `/codex` 不会有反应。
- `/codex` 必须在一行的开头（允许前面有 `[via Claude]`）。
- 收到命令后，workflow 会给评论加 👀，再回一条带 Codex 任务链接的评论，完成后更新为结果（推送的 commit 或新 PR 的链接）。
- 同一个 PR / issue 的任务会排队，一次只跑一个。注意 GitHub 只保留一个排队中的任务：排队时再发一条，前一条排队中的会被取消。
- 每个任务消耗 ChatGPT 套餐里 Codex 的本地消息额度（和在电脑上用 Codex 是同一个池子）。GitHub Actions 分钟数对公开仓库免费。
- Codex 在沙箱里不能联网。Rust 依赖会预先下载，所以它能跑 `cargo build/test --offline`；需要外网或 Xray / Mihomo 的测试跑不了，推送后由 CI 完整测试。

## CI 失败后自动派回 Codex

`.github/workflows/codex-ci-fix.yml` 监视 `codex/*` 分支上的检查（CI、Ubuntu 验收、链式代理验收、向后兼容、VLESS-ENC、shoes schema / source、旧版升级）。这些 workflow 每次结束（不论成败）都会检查一次 PR 的最新提交：上面的检查全部跑完、且有失败时，它把失败的 job 名和日志摘录（每个 job 取第一条报错前的 60 行，最多附 3 个 job）整理成任务，派给 Codex 在**同一个 PR** 上修。

- 每个 PR 最多自动派 2 次。用完后贴一条评论并打 `needs-human` 标签，之后仍可以手动 `/codex`。
- 同一个提交只派一次；派发前会在 PR 下留一条带隐藏标记的评论，次数就是按这些评论数的。
- 只处理本仓库的 `codex/*` 分支。人或 Claude 开的其他分支、fork 来的 PR 都不会被自动修改。
- 不想自动修：给 PR 打 `no-auto-fix` 标签。整个关掉：仓库变量 `CODEX_CI_FIX` 设为 `off`。改次数：仓库变量 `CODEX_CI_FIX_MAX`。
- Codex 判断失败和本 PR 无关（比如偶发网络问题）或必须改 `.github/` 才能修时，不改代码，只在 PR 下说明理由，循环到此结束。
- 手动检查：Actions → Codex CI Fix → Run workflow，填分支和完整 SHA，勾着 `dry_run` 只在日志里打印会派发的任务，不评论、不派发。

派发用的是 `GITHUB_TOKEN` 触发 `codex-dispatch.yml` 的 `workflow_dispatch`（GitHub 允许 `GITHUB_TOKEN` 触发这种事件）。`codex-dispatch.yml` 只放行 `github-actions[bot]` 带 `pr` 参数的这一种触发，所以**其他 workflow 不要给 `GITHUB_TOKEN` `actions: write`，也不要使用 `pull_request_target`**。

为什么不用 Codex 云端环境（`codex cloud exec`）：网页上建的云端环境，Codex CLI 和 GitHub 上的 `@codex` 目前都查不到（接口返回空列表），所以改为在 runner 上直接运行 `codex exec`。

## 一次性配置

### 1. 新建 environment `codex`

Settings → Environments → New environment，名字填 `codex`。

在 **Deployment branches and tags** 里选 **Selected branches and tags**，添加规则 `main`。
这样只有 `main` 上的 workflow 能读到下面两个 secret，PR 分支上的 workflow 读不到。

### 2. 创建推送用的 token（`CODEX_BOT_TOKEN`）

GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token：

- Repository access：Only select repositories → `Jyanbai/ping-rust`
- Repository permissions：
  - **Contents**：Read and write（推送分支）
  - **Pull requests**：Read and write（开 PR）
  - **Environments**：Read and write（把刷新后的登录凭据写回 secret；GitHub REST 文档里 environment secret 的读写要求的就是这个权限）
  - **不要**给 Workflows 权限，这样 Codex 的改动无法修改 `.github/workflows/`
- 有效期按自己习惯设，过期后重新生成并替换即可

把生成的 token 存为 environment `codex` 的 secret，名字是 `CODEX_BOT_TOKEN`。

用 PAT 而不是 `GITHUB_TOKEN` 推送，是因为 `GITHUB_TOKEN` 推送和开的 PR 不会触发 CI 和审查 workflow。

### 3. 生成 CI 专用的 Codex 登录（`CODEX_AUTH_JSON`）

在自己的电脑上做一次（Windows PowerShell，需要已安装 Node.js）：

```powershell
npm install -g @openai/codex
$env:CODEX_HOME = "$HOME\.codex-ci"
New-Item -ItemType Directory -Force $env:CODEX_HOME | Out-Null
Set-Content -Path "$env:CODEX_HOME\config.toml" -Value 'cli_auth_credentials_store = "file"'
codex login --device-auth
```

按提示在浏览器或手机上完成登录。如果提示设备码登录不可用，把最后一行换成 `codex login`（会打开浏览器）。

然后把凭据存进 secret，并删掉本地副本：

```powershell
Get-Content "$env:CODEX_HOME\auth.json" -Raw | gh secret set CODEX_AUTH_JSON --env codex --repo Jyanbai/ping-rust
Remove-Item -Recurse -Force $env:CODEX_HOME
Remove-Item Env:CODEX_HOME
```

没装 `gh` 的话：用记事本打开 `auth.json`，全选复制，粘到 Settings → Environments → codex → Add environment secret（名字 `CODEX_AUTH_JSON`），再删掉 `.codex-ci` 文件夹。

为什么要单独的 `CODEX_HOME`：这样 CI 拿到的是一个独立的登录会话，不会和你电脑上 Codex 的会话共用 refresh token。refresh token 每用一次就会换新，两边共用会互相把对方挤掉。之后这份凭据只由 CI 使用和刷新，本地不要再留副本。

### 4. 自检

合并到 `main` 之后，到 Actions → Codex Dispatch → Run workflow，`prompt` 留空直接运行。它会：

- 用 `CODEX_AUTH_JSON` 让 Codex 回复一句 OK，确认登录可用（会用掉一条消息额度）；
- 用 `CODEX_BOT_TOKEN` 真写一次 environment secret `CODEX_WRITEBACK_CHECK`，确认写回权限没问题。

全绿再开始用 `/codex`。之后每 3 天的定时任务也跑同样的自检，token 过期或权限不对会直接显示失败。

### 5.（可选）environment 变量

| 变量 | 默认 | 作用 |
|---|---|---|
| `CODEX_MODEL` | 空（用套餐默认模型） | 指定 Codex 使用的模型 |
| `CODEX_REASONING_EFFORT` | 空（用模型默认强度） | 推理强度，如 `medium`、`high`，可选值取决于模型；只能是小写字母 |

两个变量的请求值会打印在运行日志和 job summary 里。`codex exec --json` 不会报告实际使用的模型，所以这里记录的是请求值。Codex CLI 不在本地校验这两个值（不认识的强度会原样发给服务端），写错时会不会报错由服务端决定，改完后看一次运行结果确认。

## 凭据怎么保持有效

Codex 在 `auth.json` 的 `last_refresh` 超过约 8 天时会自动刷新 token。workflow 每次运行后，如果文件变了，就用 `CODEX_BOT_TOKEN` 把新的 `auth.json` 写回 `CODEX_AUTH_JSON`。另外每 3 天有一个定时任务跑一遍自检，保证长时间不派任务时凭据也会被刷新。

如果日志里出现 401、`Not signed in`、`refresh_token_reused`，说明凭据失效了（被撤销、过期，或两个任务同时刷新），重做第 3 步即可。

## 安全说明

OpenAI 的指南（Maintain Codex account auth in CI/CD）不建议在公开仓库里用 ChatGPT 登录凭据。本仓库是公开的，所以 workflow 分成两个 job，并做了这些限制：

- **codex job**（持有 Codex 凭据）：Codex 的命令在沙箱里运行，只能写工作区和 `~/.cargo`，不能联网；推送用的 `CODEX_BOT_TOKEN` 只在写回凭据的步骤里出现，Codex 运行的步骤拿不到。Codex 的完整输出只写文件、不打日志；生成的 diff 和总结里只要出现任何 token 就中止。diff 用 Codex 运行前保存的 `.git` 副本生成，不受工作区里被改动的 git 配置影响。
- **push job**（不接触 Codex 凭据）：只下载 diff、检查路径、`git apply`、提交和推送。

其他限制：

1. 只接受仓库所有者的评论和手动触发，以及 `codex-ci-fix.yml` 在 `codex/*` 分支 CI 失败后的派发；
2. 两个 secret 都放在只允许 `main` 部署的 environment 里；
3. `CODEX_BOT_TOKEN` 没有 Workflows 权限，并且改动 `.github/workflows/` 或 `.github/actions/` 的 diff 会被直接拒绝；
4. 评论和 issue 内容只通过环境变量传给脚本，不做 `${{ }}` 插值；
5. job 结束时删除本地凭据文件。

公开仓库的 Actions 日志任何人都能看，所以不要往 `/codex` 评论里写任何敏感信息。对别人开的 issue 用 `/codex` 前，先确认 issue 内容可信，因为它会原样交给 Codex。
