# Codex Dispatch：在 GitHub 上用评论给 Codex 派任务

`.github/workflows/codex-dispatch.yml` 让仓库所有者用一条评论把任务交给 Codex，Codex 直接在 GitHub Actions 的 runner 上写代码：

| 在哪里评论 | 写法 | 结果 |
|---|---|---|
| PR | `/codex <要改什么>` | Codex 在该 PR 的分支上继续改，结果推到**同一个 PR** |
| issue | `/codex [补充要求]` | Codex 从 `main` 开始实现这个 issue，推到新分支并开新 PR（`Closes #issue`）。别人开的 issue 必须写明要求，见下文 |
| Actions 页面 | Run workflow，填 `prompt`（可选 `pr` / `base`） | 同上，不用留评论 |
| Actions 页面 | Run workflow，`prompt` 留空 | 只做自检：Codex 登录、凭据写回权限 |

> 本功能已于 2026-11-03 在真实 runner 上实测通过。

- 只接受仓库所有者本人的评论或手动触发（以及下面"CI 失败后自动派回 Codex"的派发），其他人评论 `/codex` 不会有反应。
- `/codex` 必须在一行的开头（允许前面有 `[via Claude]`）。
- 收到命令后，workflow 会给评论加 👀，再回一条带 Codex 任务链接的评论，完成后更新为结果（推送的 commit 或新 PR 的链接）。
- 同一个 PR / issue 的任务会排队，一次只跑一个。注意 GitHub 只保留一个排队中的任务：排队时再发一条，前一条排队中的会被取消。
- 每个任务消耗 ChatGPT 套餐里 Codex 的本地消息额度（和在电脑上用 Codex 是同一个池子）。GitHub Actions 分钟数对公开仓库免费。
- Codex 在沙箱里不能联网，也不能创建 TCP/UDP socket（连 127.0.0.1 也不行，见下文"沙箱里能跑哪些测试"）。Rust 依赖会预先下载，所以它能跑 `cargo build/test --offline`；监听或连接端口的测试、依赖 shoes / Xray / Mihomo 的测试跑不了，推送后由 CI 完整测试。prompt 要求 Codex 在最终回复里把这些测试单独列出、标"未验证"，不算作通过。

## Codex 接管实现、审查与回修

自 2026-11-12 起，Claude 停用，删除自动审查与 `@claude` 两个 workflow。
Codex 负责实现、独立只读审查及回修，Grok bot 只读播报进度，用户最终检查并决定合并。
共同审查清单与角色分工统一放在 `AGENTS.md`；`CLAUDE.md` 只保留历史兼容入口。

编译和测试统一由 GitHub Actions 执行，包括普通 Linux debug / release 构建。旧 SSH 构建环境
已停用，本机只编辑、操作 Git、派发任务和读取日志；部署与实机验收另行授权。

`.github/workflows/codex-code-review.yml` 复用 environment
`codex` 的 `CODEX_AUTH_JSON`、`CODEX_BOT_TOKEN` 和模型变量，不需要新增登录或 API key。
现有 `/codex <任务>` 仍负责写代码，循环如下：

**issue / 验收标准 → Codex 实现同一个 PR → CI → Codex 独立审查 → 自动回修 → 再次 CI / 审查 → 用户最终检查**。

- PR 的 **CI** 结束后自动审查（CI 失败也会审查）；只接受所有者在本仓库创建、以 `main`
  为目标的非草稿 PR。来自 fork 或其他作者的 PR 不自动消耗登录额度。
- 审查在独立、临时的 Codex 会话中使用默认分支的 `AGENTS.md`，只读查看 PR 的精确提交和差异，
  不运行其中的代码、编译或测试。模型步骤没有 GitHub token；命令沙箱不能写文件、联网或读登录凭据。
  结果以 **Codex Code Review** 为标题，由 `github-actions[bot]` 留在 PR 下。
- 同一个 head / base 提交组合成功审查后不重复消费额度；审查期间提交变化则不发布过期结果。
- 审查使用固定版本并校验 SHA-256 的完整 Codex 运行包，保留 code-mode host 和相邻资源。
  模型必须返回 `review_complete=true`，并读取 prompt 中未提供的随机校验值；未完成或工具读取失败时
  工作流失败，不发布成功结论、去重标记或回修任务。CI 会检查真实运行包的下载、布局和两个入口启动。
- 结构化结果通过完成状态、实际读取、格式和凭据校验后才发布。有问题时，单独步骤用现有所有者 PAT 留下 `/codex`
  回修评论，包含具体意见，触发现有 Codex Dispatch 更新同一个 PR；实现会话不需要联网获取评论。
  没有发现时不再派任务，也不自动合并。
- 成功标记包含 `status=complete`；修复前可能带有旧标记的未完成审查不作为去重依据。
- 每个 PR 默认最多自动回修 2 次，同一提交只派一次；超过上限明确交人工。`no-auto-fix` 标签
  同时禁止 CI 修复和审查回修。登录、额度或沙箱失败会报告失败，不发布“无问题”的结论。
- 对已打开的 PR（例如 #97），或需要重审时，到 Actions → **Codex Code Review** →
  **Run workflow**，分支选 `main`，填写 PR 编号。手动重审会绕过去重检查。
- 仓库变量 `CODEX_REVIEW=off` 暂停自动及手动审查；`CODEX_REVIEW_FIX=off` 只暂停审查回修；
  `CODEX_REVIEW_FIX_MAX` 调整每个 PR 的自动回修上限（1 至 10，默认 2），CI 修复另有独立预算。
- 这是使用现有登录的 Actions 审查工作流，与需要在 Codex 网页单独启用的官方 `@codex`
  GitHub 审查入口相互独立。只有合并到 `main` 后才会生效，真实模型调用、沙箱和评论派发需届时验证。
  审查回修不增加 `actions: write` 权限，不绕过 Codex Dispatch 的工作流文件限制。

## 沙箱里能跑哪些测试

2026-11-09 在 `ubuntu-latest` runner 上用 Codex CLI 0.166.0、权限配置 `ci` 实测（`codex sandbox -P ci`，不调用模型）：

| 项目 | 结果 |
|---|---|
| 执行固定版本 shoes（放在 `/opt/hostedtoolcache` 下） | 可以，`shoes --version` 输出 `shoes 0.3.7` |
| 在 127.0.0.1 / ::1 / 0.0.0.0 上创建 TCP socket | 不行，`socket()` 直接返回 `EPERM`（Operation not permitted） |
| 访问外网（域名、直连 IP） | 不行 |
| 读凭据文件、列出 `$RUNNER_TEMP` | 不行 |
| `cargo test --offline`（不设 shoes 环境变量，即 Codex 现在的情况） | 单元测试 270 通过、14 失败（`sni_probe` 6 个、`github_api` 4 个、`port_check`、`socks5_random_port`，以及需要调用 shoes 的 2 个），日志里有 10 处 `Operation not permitted`；`chain_v2_e2e`、`chain_proxy_e2e` 直接返回显示 ok |
| 同上，设置 `PING_RUST_TEST_SHOES` 和 `PING_RUST_SHOES_E2E_BIN` | 需要调用 shoes 的 2 个通过；SNI 预检 4 个、shoes watcher、`chain_v2_e2e`、`chain_proxy_e2e` 因不能绑定端口失败 |
| 沙箱外、同一台 runner、同样的环境变量 | 全部通过 |

原因在 Codex 本身：关闭网络（`network.enabled = false`）时，Linux 沙箱用 seccomp 无条件拒绝 `bind`、`listen`、`connect`、`accept`，`socket()` 只放行 `AF_UNIX`（Codex 源码 `codex-rs/linux-sandbox/src/seccomp.rs` 的 `NetworkSeccompMode::Restricted`）。能放行 IP socket 的只有托管网络代理模式，那要求 `network.enabled = true`，等于打开网络，所以没有采用。依赖 shoes 端到端流量的测试仍然只能靠推送后的 CI 和 `codex-ci-fix.yml`。

## CI 失败后自动派回 Codex

`.github/workflows/codex-ci-fix.yml` 监视 `codex/*` 分支上的检查（CI、Ubuntu 验收、链式代理验收、向后兼容、VLESS-ENC、shoes schema / source、旧版升级）。这些 workflow 每次结束（不论成败）都会检查一次 PR 的最新提交：上面的检查全部跑完、且有失败时，它把失败的 job 名和日志摘录（每个 job 取第一条报错前的 60 行，最多附 3 个 job）整理成任务，派给 Codex 在**同一个 PR** 上修。

- 每个 PR 最多自动派 2 次。用完后贴一条评论并打 `needs-human` 标签，之后仍可以手动 `/codex`。
- 同一个提交只派一次；派发前会在 PR 下留一条带隐藏标记的评论，次数就是按这些评论数的。
- 只处理本仓库的 `codex/*` 分支。其他分支、fork 来的 PR 都不会被自动修改。
- 不想自动修：给 PR 打 `no-auto-fix` 标签。整个关掉：仓库变量 `CODEX_CI_FIX` 设为 `off`。改次数：仓库变量 `CODEX_CI_FIX_MAX`。
- Codex 判断失败和本 PR 无关（比如偶发网络问题）或必须改 `.github/` 才能修时，不改代码，只在 PR 下说明理由，循环到此结束。
- 手动检查：Actions → Codex CI Fix → Run workflow，填分支和完整 SHA，勾着 `dry_run` 只在日志里打印会派发的任务，不评论、不派发。

派发用的是 `GITHUB_TOKEN` 触发 `codex-dispatch.yml` 的 `workflow_dispatch`（GitHub 允许 `GITHUB_TOKEN` 触发这种事件）。`codex-dispatch.yml` 只放行 `github-actions[bot]` 带 `pr` 参数的这一种触发，所以**其他 workflow 不要给 `GITHUB_TOKEN` `actions: write`，也不要使用 `pull_request_target`**。

为什么不用 Codex 云端环境（`codex cloud exec`）：网页上建的云端环境，Codex CLI 和 GitHub 上的 `@codex` 目前都查不到（接口返回空列表），所以改为在 runner 上直接运行 `codex exec`。

## 只读规划（Architecture 阶段）

`.github/workflows/codex-plan.yml`（**Codex Architecture Plan**）是 Agent Pipeline 2.0 的规划阶段，目前**只能手动触发**：
Actions → Codex Architecture Plan → Run workflow，分支选 `main`，填 issue 编号。经过真实 issue → PR → CI → 审查 → 回修验证后，再考虑自动启用。

| 输入 | 说明 |
|---|---|
| `issue` | 要规划的 issue 编号（必须是打开的 issue，不接受 PR） |
| `notes` | 所有者补充说明。issue 不是所有者创建的时候必须填写，此时标题和正文不会交给 Codex |
| `force_plan` | 默认关闭：模型判定为简单任务时只给要点并提示可直接 `/codex`；勾选后始终输出完整方案 |
| `allow_refresh` | 默认关闭：登录上次刷新已满 7 天（Codex 约 8 天刷新一次）或无法判断时不运行；确认没有其他 Codex 任务在跑后勾选重试 |

- 只接受仓库所有者在 `main` 上触发；使用 environment `codex` 的 `CODEX_AUTH_JSON` 和 `CODEX_MODEL` / `CODEX_REASONING_EFFORT`，不新增登录或 token。
- 与 Codex Code Review 相同的只读沙箱（`:read-only`、禁止网络、读不到 `$RUNNER_TEMP`），运行前实测；模型步骤没有 GitHub token。分析的是触发时 `main` 的精确提交和该提交的 `AGENTS.md`。
- 模型必须读取 prompt 中没有的随机校验值并返回 `plan_complete=true`，结构化结果通过格式和凭据检查后，才由 `github-actions[bot]` 以 **Codex Architecture Plan** 为标题评论到 issue。同一 run/attempt 只评论一次；失败时评论“未完成”，不发布方案。
- 方案包括相关源码与调用链、兼容性、技术风险与回滚、实施步骤、测试计划（回归测试排在最前）以及“已验证 / 未验证 / 失败”。规划不编译、不运行测试，所以“已验证”只代表读过源码。
- workflow 权限只有 `contents: read` 和 `issues: write`；不推送、不开 PR、不派发 `/codex`。`CODEX_BOT_TOKEN` 只在写回刷新后登录的那一步使用，与审查工作流相同，没有扩大权限。
- **方案如何交给实现**：实现会话读不到 issue 评论。所有者确认（或修改）方案后，在 issue 下评论 `/codex <确认后的方案要点>`，由现有 Codex Dispatch 实现，之后照常进入 CI、独立审查和回修。
- 共享登录的刷新：所有规划任务在同一个并发组 `codex-plan` 里串行（GitHub 只保留一个排队任务，再排队会取消前一个排队中的任务）。规划与 Dispatch / Review 之间没有并发组互斥，所以登录接近刷新期限时默认停止，避免同时刷新触发 `refresh_token_reused`。
- 失败时评论前会重新检查 issue 是否仍打开；方案已发布、只是之后写回登录失败时，评论只说明写回失败，不说没有方案。
- 仓库变量 `CODEX_PLAN=off` 可以停用这个入口。

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

- **codex job**（持有 Codex 凭据）：Codex 的命令在沙箱里运行（权限配置 `ci`，写在 CI 生成的 `$CODEX_HOME/config.toml` 里），只能写工作区和 `~/.cargo`，不能联网，并且读不到 `$RUNNER_TEMP`：Codex 凭据、用于遮蔽的 token 列表和 `.git` 副本都放在这里。每次运行 Codex 前，workflow 先用同一配置在沙箱里实测一次（不调用模型），凭据可读、能访问外网（按域名或直连 IP）或工作区不可写就直接停止；推送用的 `CODEX_BOT_TOKEN` 只在写回凭据的步骤里出现，Codex 运行的步骤拿不到。Codex 的完整输出只写文件、不打日志；生成的 diff 和总结里只要出现任何 token 就中止。diff 用 Codex 运行前保存的 `.git` 副本生成，不受工作区里被改动的 git 配置影响。
- **push job**（不接触 Codex 凭据）：只下载 diff、检查路径、`git apply`、提交和推送。

其他限制：

1. 只接受仓库所有者的评论和手动触发，以及 `codex-ci-fix.yml` 在 `codex/*` 分支 CI 失败后的派发；
2. 两个 secret 都放在只允许 `main` 部署的 environment 里；
3. `CODEX_BOT_TOKEN` 没有 Workflows 权限，并且改动 `.github/workflows/` 或 `.github/actions/` 的 diff 会被直接拒绝；
4. 评论和 issue 内容只通过环境变量传给脚本，不做 `${{ }}` 插值；
5. job 结束时删除本地凭据文件；
6. 不是仓库所有者创建的 issue，标题和正文不会交给 Codex，只使用你 `/codex` 评论里写的要求；评论里没写要求时任务直接拒绝并回复说明。

公开仓库的 Actions 日志任何人都能看，所以不要往 `/codex` 评论里写任何敏感信息。别人开的 issue 可能含有提示注入，作者也能在你评论之后修改正文，所以对这类 issue 请把要做的事完整写在 `/codex` 后面。
