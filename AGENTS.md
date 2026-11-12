# ping-rust 开发规则

所有在本仓库工作的 agent 都遵守本文件。任务提示里另有规定时（例如 GitHub Actions 派发的运行环境约束），以任务提示为准。

## Agent 分工与开发循环（2026-11-12 更新）

| 角色 | 职责 |
|---|---|
| Codex 实现会话 | 从 issue 验收标准出发实现功能、补测试、开或更新同一个 PR，处理 CI 和审查发现的问题 |
| Codex 审查会话 | 用独立上下文只读审查 PR，按下面的清单检查，给出中文问题、文件行号与证据 |
| Grok bot | 只读汇总进度、失败检查、待人工处理事项；不写代码、不提交、不合并 |
| 用户 | 确定需求与取舍，最终检查并决定合并；授权发版和实机操作 |

Claude 当前完全不可用，不再依赖 Claude 的额度、GitHub Action、`@claude` 或用户手动转达。
Codex 接管实现和审查，但这两步必须使用独立会话；审查会话不直接修代码，也不能把自己的结论当成运行证据。

开发循环：**issue 与验收标准 → Codex 实现 → CI → Codex 独立审查 → 按意见回修同一个 PR → 再次 CI / 审查 → 用户最终检查**。

- 写代码的入口仍是所有者的 `/codex <任务>` 和 Codex Dispatch；CI 失败由 Codex CI Fix 回派。
- Codex Code Review 在 PR 的 CI 结束后只读审查；有效发现自动回派 Codex，保持同一个 PR。
- 自动回修必须有去重和次数上限，尊重 `no-auto-fix`；预算耗尽、凭据/额度故障或无法验证时明确交给用户，不无限重试。
- 自动化不得删除或放宽断言、修改旧状态兼容夹具来换取绿灯；未运行的测试写“未验证”。
- 合并到 `main` 必须取得用户在当次对话中的明确同意，并使用 squash；提交、推送、tag、Release 和服务器操作遵守现有授权规则。
- 工作流是否已生效以默认分支和实际运行记录为准，不能仅凭文档或一次任务提交成功宣称循环已跑通。

## PR 审查清单（所有审查会话共用）

只报告真实存在、能说出具体失败场景的问题，不报告代码风格偏好。意见用中文，并给出优先级、文件、行号和依据。

1. **范围**：改动是否只做了 issue / PR 描述要求的事；有没有夹带无关修改。
2. **断言与夹具**：是否删除或放宽了已有断言；是否修改了 `tests/fixtures/yaml/compat/` 或 `tests/fixtures/yaml/chain-v2/`。有意修改测试时，PR 描述里是否逐条说明了原因。
3. **测试覆盖**：新行为、修复的 bug 有没有对应测试；测试是否真的会在旧代码上失败。
4. **证据**：PR 描述里写“已验证”“通过”的项，是否有命令输出或 CI run 支撑；没运行的是否标了“未验证”。
5. **兼容性**：对照下面的兼容性红线逐条检查，尤其是已有节点、主菜单编号与 README / expect 回归、非交互路径读 stdin、`--version` 输出、state 向后兼容。
6. **错误处理**：取消、无效输入不应该让整个菜单退出；网络有超时；提交失败时配置能回滚。
7. **安全**：有没有泄露密钥、真实地址或分享链接；新 workflow 的 action 是否固定 SHA、外部输入是否直接插进脚本；外部二进制是否固定版本并校验。
8. **发版**：有没有未经要求修改版本号、发布流程或 shoes pin；pin 改动是否符合 `docs/SHOES_PIN_UPGRADE.md`。

## 项目

ping-rust 是纯 Rust 编写的 [shoes](https://github.com/cfal/shoes) 代理内核安装与管理工具。提供交互式数字菜单（`sudo prs`），也提供 `prs add reality`、`prs info`、`prs url`、`prs qr` 等命令。界面、文档、提交说明以中文为主。

运行时文件：`/usr/local/bin/shoes`、`/etc/shoes/config.yaml`（聚合配置）、`/etc/shoes/ping-rust-state.json`（受管状态）、`/etc/shoes/profiles/`（每个节点一份）。

### 代码地图

| 位置 | 内容 |
|---|---|
| `src/menu.rs`、`src/menu/chain.rs` | 数字菜单、链式代理菜单 |
| `src/cli.rs` | 命令行子命令、首次默认部署（bootstrap）、结果输出 |
| `src/config.rs`、`src/config/presets.rs`、`src/config/presets/*.rs` | 受管协议。`presets.rs` 是协议注册表，新增协议从这里开始 |
| `src/config/transaction.rs`、`src/config/commit.rs`、`src/deployment.rs` | dry-run、原子提交、失败回滚 |
| `src/service.rs` | systemd、热重载验证（MainPID 不变、监听端口符合预期） |
| `src/installer.rs` | shoes 安装与 pin（`SHOES_RELEASE_TAG`），升级流程见 `docs/SHOES_PIN_UPGRADE.md` |
| `src/client.rs` | 分享链接、二维码、Clash Meta / sing-box / NekoBox 导出 |
| `src/chain_proxy.rs`、`src/chain_proxy/` | Chain Proxy 2.0（节点、Pool、Chain、路由规则） |
| `src/vless_encryption.rs` | VLESS-ENC 密钥生成（调用 `shoes generate-vless-encryption`） |
| `src/self_update.rs`、`src/install_self.rs` | 自更新、一键安装 |
| `scripts/ci/` | CI 验收脚本 |
| `tests/fixtures/yaml/` | YAML 兼容与 golden 夹具，说明见该目录的 README |

## 构建与测试位置（2026-11-12 更新）

- 编译和测试统一在 **GitHub Actions**，包括 Linux debug / release 和多平台检查。Codex 的实现、独立审查与回修使用现有 Actions 入口，本机只编辑、操作 Git、派发任务和读取日志。
- 旧 SSH 构建环境已停用，不再向它同步源码、运行后台构建或清理编译缓存；本机也不运行编译和测试命令。
- 使用仓库现有 workflow 验证，对照对应提交的 Actions 最终结论和 job / step 日志汇报。未运行、被跳过或受沙箱限制的检查写“未验证”；任务提交成功不代表验证通过。
- 部署与实机验收单独按用户授权执行，不把它们混入自动构建与审查循环。

## 常用命令（在 GitHub Actions 中执行）

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

部分测试需要 shoes 二进制：`PING_RUST_TEST_SHOES`、`PING_RUST_SHOES_E2E_BIN` 指向固定版本的 shoes（当前 v0.3.7，下载地址和 SHA-256 见 `.github/workflows/ci.yml`）。没有 shoes、不能绑定端口或不能联网时，这些测试会失败或跳过，写明"未运行"即可，CI 会完整测试。

这些测试统一通过 `tests/support/shoes_e2e.rs` 读取 shoes 路径：缺变量时在 stderr 打印 `SKIPPED(e2e): <测试名>：<原因>` 并跳过，cargo test 仍显示 ok。报告测试结果时，`SKIPPED(e2e)` 的条目要算作"未运行"，不能算作"通过"。设置 `PING_RUST_REQUIRE_E2E=1` 时缺变量直接失败；CI 中提供了 shoes 的测试步骤都设置了它。

## 工作规则

1. **范围**：一个任务对应一个 issue、一个 PR，只做任务要求的事。任务外的发现写进 PR 描述的"建议"一节，不要顺手改。
2. **测试先行**：先写能复现问题的测试，再改代码。新行为必须有测试覆盖。
3. **断言**：不删除、不放宽已有断言。行为是按任务要求有意改变的，可以修改对应测试，但要在 PR 描述里逐条写明改了哪个测试、为什么。
4. **证据**：PR 描述写清改了什么、跑了哪些检查、结果如何。没有实际运行过的项写"未验证"，不能写成"通过"。不编造运行结果。PR 描述的内容只放在 PR 里，不要另存为仓库里的文档文件。
5. **依赖**：新增 crate 要说明理由；能用已有依赖解决的不加新依赖。外部二进制必须固定版本并校验 SHA-256。
6. **发版**：不改版本号、不推 tag、不发 Release、不发布 crates.io，除非任务明确要求。GitHub Release 不要标成 pre-release（一键安装下载的是 `releases/latest`）。
7. **提交说明**：Conventional Commits 风格（`fix:`、`feat:`、`docs:`、`ci:`、`test:`、`chore:`），标题一行说清改动。

## 兼容性红线

- **旧版磁盘状态夹具不改**：`tests/fixtures/yaml/compat/`、`tests/fixtures/yaml/chain-v2/` 记录的是旧版本写出的文件，用来证明新版本还能读。新格式放进新目录（如 `chain-v036/`、`vless-enc/`）。`golden/` 只在导出格式有意改变时重新生成，并在 PR 里说明。
- **向后兼容**：新版本写出的 state 必须能被 v0.2.1 读取（`backward-compat.yml` 会检查）。
- **已有节点不动**：升级 ping-rust 不得自动改变已有节点的端口、凭据、SNI 或客户端配置。
- **主菜单可以调整**：改动主菜单编号或文字的 PR 必须在描述里给出新旧编号对照，并同步更新 README 和 `tests/menu_input.exp`。
- **非交互路径不读 stdin**：`ping-rust bootstrap`、`install-self` 可能在 `curl | bash` 里运行，绝不能等待用户输入。
- **自更新兼容**：`ping-rust --version` 的 stdout 必须保持 `ping-rust X.Y.Z` 这一行，commit 等额外信息写到 stderr。旧版本的 self-update 依赖这一点。
- **一致性**：服务端配置、分享链接、二维码、各客户端导出必须一致。某种客户端不支持时明确拒绝并说明原因，不能静默生成一个不一样的配置。
- **改动要可回滚**：写配置走现有的 dry-run → 原子提交 → 热重载或受控重启 → 失败回滚流程，不绕开。

## 安全与脱敏

- 代码、测试、文档、PR、日志里不出现真实的公网 IP、UUID、密钥、token、分享链接。测试地址用 `203.0.113.0/24`、`example.com` 这类保留地址。
- 服务端私钥、decryption 等只写入权限 0600 的文件，不打印到终端或日志。
- GitHub Actions：第三方 action 固定到 commit SHA；外部输入（issue、评论、PR 标题）只经环境变量传给脚本，不用 `${{ }}` 直接插值进命令。
- 访问网络的代码要有明确超时，失败时给出可操作的中文提示。
