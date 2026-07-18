# ping-rust 完成度与验收证据

审计日期：2026-07-18

本文件把原始目标逐项映射到实现、自动化证据和外部验收边界。`已实现` 表示代码路径和自动化证据完整；Debian 12 与成功标准指定的 Ubuntu 24.04 均已完成独立实机验收。

## 需求映射

| 原始需求 | 状态 | 实现位置 | 当前证据 |
|---|---|---|---|
| Rust 2021、Rust 代码占绝对主导 | 已实现 | `Cargo.toml`、`src/` | 7,037 行 Rust / 241 行安装 shell，Rust 占 96.69%；代理、配置、服务、运维、自更新与快速部署事务核心均为 Rust |
| clap v4 子命令与数字菜单 | 已实现 | `src/cli.rs`、`src/menu.rs` | `prs` 主菜单固定 1..10，协议编号固定为连续的 1/2/3/4/5；采用 233boy 风格 `1)` 列表与 `请选择 [0-N]` 提示，主菜单 0 退出、所有子菜单 0 返回 |
| 快速添加与直接分享 | 已实现，Ubuntu 24.04 实测 | `src/fast_add.rs`、`src/deployment.rs`、`src/client.rs` | `add/a`、协议短别名、随机端口/凭据、公网地址探测、`--yes/--plain`；真实 PTY 的 Reality/SS 添加、URI 与监听均通过 |
| 分享信息重显与隐私边界 | 已实现 | `src/cli.rs`、`src/client.rs` | `info/i`、`url`、`qr` 按名称/UUID 读取保存地址；Reality URL 含 flow/pbk/sid 且不含私钥；二维码只调用本机 qrencode |
| 激活失败事务回滚 | 已实现，Ubuntu 24.04 实测 | `src/deployment.rs`、`src/config.rs`、`src/service.rs` | 添加、修改和删除共用部署事务；失败恢复 config/state/profiles/unit、enabled/active 和端口，且不输出分享 URI |
| shoes GitHub Release 预编译安装 | 已实现，Debian/Ubuntu 实测 | `src/installer.rs` | v0.2.7 GNU 不兼容时自动回退 digest 校验过的 static musl；Ubuntu 24.04 约 2 秒完成 Reality 服务部署且提交前健康检查通过 |
| cargo 源码安装 shoes | 已实现，Debian 实测 | `src/installer.rs` | 从与 schema CI 相同的 cfal/shoes 固定提交 `386b115...` 执行 `cargo install --git --rev --locked`；保留低内存单任务/关闭 LTO 保护，避免 crates.io 新版本 schema 漂移 |
| Reality X25519 密钥和完整 shoes YAML | 已实现 | `src/config.rs` | X25519 派生单测；本地 shoes 0.2.8 `--dry-run` 解析成功 |
| Hysteria2 与 TUIC 快速配置 | 已实现 | `src/config.rs` | 随机凭据、自签名/外部证书支持；本地 shoes 0.2.8 同时加载两套 PEM 并解析成功 |
| Shadowsocks 六种 cipher | 已实现 | `src/config.rs`、`src/client.rs` | legacy/2022 六种 shoes cipher 全部真实 dry-run；2022 标准 Base64 与 16/32 字节前置校验；客户端 ChaCha 标准名称单独映射 |
| AnyTLS（TLS 与 Reality 外层） | 已实现 | `src/config.rs`、`src/cli.rs`、`src/menu.rs` | 多用户、UDP、padding、fallback、自签名/外部证书和 Reality 高级模式均已接通；TLS 与 Reality 两种配置通过固定 shoes dry-run |
| 固定 latest shoes schema 验证 | 已实现 | `.github/workflows/shoes-schema.yml` | 固定 `386b11532424b8665ee3e46340c6236fb3c47595` / 0.2.8 从源码构建；五单协议、五协议联合、六 cipher 与 Reality+AnyTLS 共 13 次显式 dry-run 成功 |
| 多配置添加、查看、删除 | 已实现 | `src/config.rs`、`src/cli.rs`、`src/menu.rs` | `/etc/shoes/profiles/<协议>-<端口>.yaml` 为真实单节点 mapping；菜单显示并操作真实 basename，Rust 按 state 顺序聚合为 shoes 顶层数组 |
| 菜单 `2. 更改配置` | 已实现，Ubuntu 24.04 实测 | `src/menu.rs`、`src/config.rs`、`src/deployment.rs` | 原占位提示已替换为协议感知修改流程；端口、名称、地址、凭据、Reality SNI、SS cipher、AnyTLS 用户密码均同步 YAML/sidecar，经真实 shoes dry-run、原子提交和 systemd 稳定激活后才成功，失败精确回滚 |
| 候选验证与安全提交 | 已实现 | `src/config.rs`、`src/utils.rs` | 进程间 advisory lock；候选先执行 shoes dry-run；config/state/profile 目录任一步失败均恢复精确旧快照，拒绝 symlink、特殊文件和非规范文件名 |
| systemd unit 与启停/重启/状态/日志 | 已实现，Debian/Ubuntu 实测 | `src/service.rs`、`systemd/ping-rust.service` | 首次、active、failed 三态启用策略和 start-limit 恢复均通过；Ubuntu 真实 reboot 后自动 active，三协议端口全部监听 |
| 更新与卸载 | 已实现，Debian/Ubuntu 实测 | `src/installer.rs`、`src/service.rs`、`src/utils.rs` | update/uninstall 共用全局锁；更新前保存旧 shoes，验证新内核能加载现有配置并在 restart 后稳定 active，否则恢复旧二进制和服务；卸载仍只删除确实属于本工具的文件与别名 |
| BBR、端口检查、备份恢复 | 已实现，Debian/Ubuntu 实测 | `src/operations.rs` | 两台 VPS 均由 ping-rust 写入并验证 bbr/fq；备份递归包含真实 profiles，旧备份恢复时在 staging 幂等物化后校验，失败恢复原目录 |
| Clash Meta、sing-box、Nekobox 客户端导出 | 已实现，前三协议 Debian/Ubuntu 实测 | `src/client.rs` | 五协议 YAML/JSON/URI 解析测试；Reality 私钥不泄漏；普通 AnyTLS 支持三格式，AnyTLS+Reality 仅输出 sing-box，Mihomo/标准 URI 不支持时明确报错 |
| Ubuntu 22.04/24.04、Debian 12、Rocky/Alma 9 x86_64 | 构建/测试通过；Ubuntu/Debian 运行态实测 | `.github/workflows/ci.yml`、`.github/workflows/ubuntu-acceptance.yml` | CI 覆盖五个目标系统；Ubuntu acceptance run `29635760772` 实际加载五协议并复核监听，另有 Ubuntu 24.04.3 与 Debian 12 独立 systemd/公网验收；GNU ELF 最高 GLIBC 2.34 |
| ARM64 次优先支持 | 构建与模拟运行已证实 | `src/installer.rs`、Release workflow | aarch64 GNU ELF 最高 GLIBC 2.34；v0.1.8 aarch64 musl 静态 binary 通过 qemu-user-static `--version` 并公开发布 |
| ping-rust 预编译一键安装 | 已发布并端到端验证 | `.github/workflows/release.yml`、`scripts/install.sh` | v0.1.8 的 x86_64/aarch64 musl、SHA256SUMS 已公开；Release workflow 从公开 URL 零输入部署默认 Reality，验证随机监听、systemd、URI 与重复运行保护，同时覆盖 `prs`、冲突保护、旧 `sb` 迁移和自更新 |
| ping-rust 原生自更新 | 已发布并端到端验证 | `src/self_update.rs`、`src/cli.rs`、`src/menu.rs` | 独立 `self-update` 保留 shoes `update` 语义；v0.1.6 发布 job 在非 root 自定义目录真实完成公开资产下载、双重 SHA-256、运行中原子替换和安装后版本复核 |
| README、MIT、cargo install 发布 | 已发布并验证 | `README.md`、`LICENSE`、`scripts/install.sh` | README 第一屏提供无需 Rust 的一键入口，并保留 crates.io/Git/源码安装；release build、doc、隔离 `cargo package` 门禁通过 |
| GitHub 源码开源 | 已发布 | `Cargo.toml`、GitHub `main` | `Jyanbai/ping-rust` 已为 Public/非空并建立 `main`；首个提交与跨平台 CI 修复均已推送 |
| 公开 `cargo install ping-rust` | 已发布并验证 | crates.io `ping-rust 0.1.8` | 正式 `cargo publish --locked` 成功；公开 registry API 与独立 `cargo install ping-rust --version 0.1.8 --locked` 均返回 0.1.8 |
| 干净 Ubuntu 24.04 三分钟部署并公网连通 | 已完成 | `README.md` 验收清单、Ubuntu acceptance workflow | Ubuntu 24.04.3 干净基线安装后，Reality 部署约 2 秒；官方 Windows sing-box 在 reboot 前后均握手成功且观察到 VPS 公网出口 |

## Milestone 10：latest shoes 五协议 schema 对齐

- 唯一 schema 事实来源固定为 cfal/shoes master commit `386b11532424b8665ee3e46340c6236fb3c47595`，其 `Cargo.toml` 版本为 0.2.8。
- Reality 继续使用 TLS 外层 `reality_targets`、X25519 base64url 密钥、0..=16 偶数长度十六进制 short ID、VLESS 内层和 `vision: true`；新增 short ID 与 `max_time_diff` 高级参数校验。
- Hysteria2/TUIC 保持 QUIC transport，显式写入 `h3` ALPN 和 `num_endpoints`；TUIC 的 `zero_rtt_handshake` 同步保存并映射到 sing-box/Mihomo 客户端字段。
- Shadowsocks 支持 shoes 当前六种 cipher。2022 cipher 按标准 Base64 生成并校验 AES-128 16 字节、AES-256/ChaCha20 32 字节，避免 shoes 内部长度断言；服务端保留 shoes 的 `ietf` 名称，客户端导出映射标准名称。
- AnyTLS 默认生成 `tls_targets` + TLS target + `protocol.type: anytls`，支持一个或多个用户、UDP、严格 padding、fallback 与证书；高级模式生成 `reality_targets` + AnyTLS，且不错误开启 Vision。
- 正式生成路径（包括自定义 `--output`）在原子写入前调用实际 `/usr/local/bin/shoes --dry-run`；单元测试通过私有注入点只跳过外部进程，公开生产入口始终启用真实校验。
- 客户端导出对服务端字段逐项对应；Clash Meta 明确不支持 AnyTLS+Reality，标准 AnyTLS URI也无法携带 Reality 公钥，因此这两种组合返回中文错误，只有 sing-box 生成 Reality+AnyTLS。
- GitHub run `29635356030` 从固定 SHA 构建 shoes，在 Ubuntu 24.04 对五个单协议配置、五协议联合配置、六种 Shadowsocks cipher 和 Reality+AnyTLS 执行 13 次显式 `shoes --dry-run`，全部输出 `config parsed successfully`。
- 首次验证 run 因 CLI 标准输出包含一次性 Reality 私钥而被主动删除；工作流随后把生成 stdout 静默，仅保留 shoes 校验结果。重跑日志已扫描，无 `Reality 私钥`、PEM 私钥头或 `private_key:`。
- 同一最终提交的常规 CI run `29635356053` 在 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 全部成功。
- main acceptance run `29635760772` 在 Ubuntu 24.04 用 Release shoes v0.2.7 实际启动 Reality、Hysteria2、TUIC、Shadowsocks、AnyTLS；备份恢复、更新和重启后五个监听仍通过，随后完成卸载清理。

## Milestone 11：233boy 风格 sb 快速路径

- 本地 `sing-box-main/sing-box-main` 仅作为交互行为参考：主菜单 1..10、协议 1/3/8/18/20、`add/a` 和添加后直接显示 URL；配置 schema、安全提交和服务管理仍以 ping-rust 当前 Rust 实现及 shoes dry-run 为准。
- 官方安装脚本安装 `ping-rust` 后创建相对符号链接 `sb → ping-rust`；已存在的文件或指向其它程序的链接会被保留。卸载侧也只删除解析后确实指向当前可执行文件的 symlink。
- `sb add reality`、`sb a r 443`、`sb add ss` 支持空端口随机、自动 UUID/X25519/short ID/SS 2022 密钥和公网地址探测；`--server-address` 可覆盖探测，`--plain` stdout 仅保留分享 URI。
- 快捷 Reality URI 包含 v2rayN 所需 `encryption=none`、`flow=xtls-rprx-vision`、`security=reality`、`sni`、`fp`、`pbk`、`sid`、`type=tcp`；Shadowsocks 使用 SIP002 URL-safe Base64 auth。
- ManagedProfile 新增可选 `server_address` 且 serde 默认兼容旧 sidecar；`info/url/qr` 可按名称或 UUID 重显，二维码不使用外部网页。
- 统一 deployment 事务让原有受管 `generate` 和新 `add` 都在服务确认 active 后才成功；激活失败会精确恢复配置、状态、unit 与服务 enabled/active 状态。
- 本地门禁：53/53 tests、fmt、check、clippy `-D warnings`、release build、doc、严格 package/publish dry-run、actionlint v1.7.12、ShellCheck 全通过。
- GitHub CI run `29640353028` 五发行版全绿；固定 shoes schema run `29639726196` 的五协议矩阵全绿。
- Ubuntu 24.04 acceptance run `29640353088` 在 2m33s 内完成公开 crate 基线、当前源码、五协议、真实 `sb` Reality/SS PTY、事务故障回滚、客户端导出、运维与卸载清理。

## Milestone 12：prs 与连续菜单编号

- 快速命令由 `sb` 改为 `prs`；一键安装创建相对链接 `prs → ping-rust`，已存在的非本工具 `prs` 文件或链接保持不变。
- 从旧版升级时，只移除目标精确为同目录 `ping-rust` 的旧 `sb` 符号链接；Rust 卸载同样通过 canonical path 判断所有权，不删除用户自己的命令。
- 快速与高级协议菜单统一为 `1=TUIC`、`2=Hysteria2`、`3=Shadowsocks`、`4=VLESS-REALITY`、`5=AnyTLS`；不再接受 8/18/20 等旧菜单编号。
- 主菜单显式显示 `0. 退出` 并循环运行；协议、运维、服务、更新、配置选择、导出格式等子菜单统一显示 `0. 返回`，空输入不再表示退出。
- `prs → 1 → 4/3 → 端口或回车随机 → URL → 0 退出` 已写入 Ubuntu 24.04 expect PTY 验收；Release workflow 同时验证 `prs`、冲突保护和旧 `sb` 安全迁移。
- 本地门禁：54/54 tests、fmt、check、clippy `-D warnings`、release build、doc、package/publish dry-run、actionlint v1.7.12、ShellCheck 全通过。
- 精确产品提交 `d9ef776` 的 main CI run `29641525438`、固定 shoes schema run `29641525465`、Ubuntu 24.04 acceptance run `29641525455` 全部成功；tag CI/schema 也再次全绿。
- GitHub Release run `29641681305` 全部成功；发布 job 从公开资产验证 `prs`、非本工具命令冲突保护、旧 `sb` 安全迁移和原生自更新。
- v0.1.6 公开资产：x86_64 2,597,445 bytes / SHA-256 `548dbb89a8dbe1dee2b322ff2cd9deaf0a56258c20be5ec28b4aad5bf6fb8f63`；aarch64 2,428,751 bytes / SHA-256 `466a2a09bdd1ee780af94a3c8caddceff8e68e66b3359510aaa5c1dce6dac88f`；公开 SHA256SUMS 与 GitHub API digest 一致。
- crates.io 0.1.6 已正式发布；全新隔离 Cargo root 从 registry 编译安装后返回 `ping-rust 0.1.6`，并确认 `--random-port`、`--yes`、`--plain` 快速添加帮助存在。

## Milestone 13：安装脚本零输入默认 Reality

- `scripts/install.sh` 默认在安装并验证 ping-rust 后，以 root 调用 Rust `bootstrap`；无需再运行 `prs`，不询问协议或端口。
- `bootstrap` 在配置和状态均不存在时自动安装 shoes、探测公网地址、选择随机可用端口、生成 VLESS-Reality-Vision 全部安全凭据、dry-run、原子提交、激活 systemd 并输出 `vless://`。
- 任一配置或状态文件存在时 bootstrap 安全跳过，避免升级或重跑安装器时重复添加；高级用户可用 `--no-bootstrap` 只安装管理工具。
- 菜单入口也复用同一 Rust bootstrap，因此 cargo 安装后首次运行 `prs` 仍具备相同安全默认行为；部署和回滚核心未移入 Bash。
- Ubuntu acceptance 直接运行安装器调用的 bootstrap 命令，断言输出中没有“选择协议/输入端口”、端口为随机高位端口、URI 完整、systemd active 且实际监听。
- Release workflow 从公开 tag 资产运行默认 install.sh 全链路，静默捕获敏感 URI，验证监听、重复 bootstrap 幂等，再卸载清理；普通安装/冲突/迁移测试使用 `--no-bootstrap` 保持职责独立。
- 本地门禁：55/55 tests、fmt、check、clippy `-D warnings`、actionlint v1.7.12、ShellCheck 全通过。
- 首轮 Ubuntu run `29642950205` 已实际完成 shoes 安装、systemd unit 启用和 Reality 激活，随后因验收脚本用行首锚点从带终端样式的展示输出提取 URI 而失败；改为只确认展示含 URI，再通过 `url` 命令取得规范值，不更改产品部署逻辑。
- 精确产品提交 `5774869` 的 CI run `29642950179` 与固定 shoes schema run `29642950174` 成功；验收提取修复提交 `a473cfb` 的 CI run `29643148634` 与 Ubuntu 24.04 acceptance run `29643148659` 全部成功。
- v0.1.7 Release run `29643229765` 的双架构 MUSL build 和发布 job 全部成功；“Verify published one-click installer”直接运行公开安装器，验证零询问、随机端口、规范 URI、systemd active、真实监听与二次 bootstrap 安全跳过。
- v0.1.7 tag shoes schema run `29643229756` 从固定 shoes 0.2.8 源码构建，并对五协议、全部 Shadowsocks cipher、Reality+AnyTLS 执行实际 `shoes --dry-run`，全部成功。
- v0.1.7 公开资产独立下载复核：x86_64 2,598,642 bytes / SHA-256 `ac31ed3e9db951ffb900f970fb7f027bfeb11bcb0cff7c625520d0d719c50767`；aarch64 2,431,641 bytes / SHA-256 `d15373ce83ea3dfb58b574f745d76714aeeefbf1e91db6612e1fb49fe260d455`；两者与公开 `SHA256SUMS` 和 GitHub API digest 一致。
- crates.io 0.1.7 已正式发布；`cargo search ping-rust` 返回 0.1.7，全新隔离 Cargo root 从 registry 下载编译后 `ping-rust --version` 返回 `ping-rust 0.1.7`。

## Milestone 14：配置修改修复与本地 Grok 审查加固

- 用户实测“2. 更改配置”不可用的直接根因是主菜单分支只有“请使用 generate 或删除重建”的占位输出，没有调用任何修改 API；不是输入方式或 VPS 环境问题。
- 新增协议感知修改菜单，选择配置后可改端口、名称、客户端公网地址和全部凭据；Reality 可改 SNI，Hysteria2/TUIC/SS 可改密码，SS 可改 cipher，AnyTLS 可选择用户改密码。密码输入默认隐藏，成功直接显示更新后的分享链接。
- 配置修改在同一全局锁中验证 YAML/sidecar 条目数量、顺序端口与协议一致性，候选先通过真实 `shoes --dry-run`，再原子提交；systemd 未稳定 active 时恢复修改前 config/state/unit/enabled/active 状态。
- shoes Release 下载增加 GitHub HTTPS 来源、API digest、声明尺寸与 128 MiB 流式上限；cargo 安装固定到 schema CI 提交，防止上游 schema 漂移。
- shoes update 在获取全局锁后保存旧二进制；新内核必须能 dry-run 现有配置且重启后两次探测保持 active，否则恢复旧二进制并重新启动旧服务。update/uninstall/config transaction 不再并发互相覆盖。
- 新建配置名称强制不区分大小写唯一；旧数据若存在同名项，名称选择明确拒绝并要求 UUID，避免静默选错。
- `/etc/shoes` 统一收紧为 0700、文件为 0600；备份恢复遇到 symlink/特殊文件拒绝并回滚。四个 GitHub workflow 的第三方 Actions 均固定完整 commit SHA，并加入 Dependabot 更新通道。
- Ubuntu 24.04 acceptance run `29645174670` 通过真实 `prs → 2 → 选择 Reality → 改端口` PTY 路径，并验证新端口监听、旧端口消失；同一 run 的五协议、激活故障回滚、导出、运维和清理全部成功。
- 精确产品提交 `960edde` 的 main CI run `29645174662`、固定 shoes schema run `29645174650` 与 Dependabot 配置 run `29645176313` 全部成功；tag CI `29645387085` 和 schema run `29645387104` 再次全绿。
- GitHub Release run `29645387081` 的 x86_64/aarch64 MUSL 构建、公开 checksum、Release 创建和一键安装器默认 Reality 全部成功。独立下载复核：x86_64 2,632,869 bytes / SHA-256 `11a87df2afa8dc387dba2f5f2a9366d7cd3fa344aad54476e1c3a86263a996c1`；aarch64 2,462,412 bytes / SHA-256 `a165b41cd469339de070053ae4d6aabf8320cd844e892fc9881de068aadea7fe`；两者均只含一个 `ping-rust` 且与 `SHA256SUMS`/GitHub digest 一致。
- crates.io 0.1.8 已正式发布；全新隔离 Cargo root 从公共 registry 下载编译，`ping-rust --version` 返回 0.1.8，`add`/`self-update` 帮助存在。
- 本地门禁：62/62 tests、fmt、check、clippy `-D warnings`、release build、doc、严格 package/publish dry-run、RustSec、actionlint v1.7.12、ShellCheck 与 diff check 全部通过；v0.1.8 发布闭环完成。

## Milestone 15：233boy 风格简洁菜单

- 以本地只读参考 `sing-box-main/sing-box-main/src/core.sh` 的 `is_main_menu`、`ask get_config_file`、`show_list`、`get info`、`del` 和 `change` 为交互基准；Rust 配置事务、shoes schema 与安全边界保持独立实现。
- 主菜单改为短横线标题、`shoes: running/stopped` 状态、固定 `1)` 到 `10)` 列表和 `请选择 [0-10]`；协议与子菜单统一相同格式，不再显示 Dialoguer 的长数字提示。
- 查看、更改、删除与导出统一显示 `VLESS-REALITY-53453`、`SHADOWSOCKS-端口` 等 `协议-端口` 名称，不展示 UUID；内部仍使用 UUID 精确定位，安全性不变。
- 只有一个配置时直接选中，多个配置时才显示数字列表；查看配置只展示协议、端口、SNI、地址和可复制 URI。添加、修改和删除成功提示也不再输出内部 UUID。
- 保留用户指定的 `0`：主菜单退出，所有子菜单返回。Ubuntu 24.04 PTY 验收已扩展到查看配置、短名称显示、删除菜单输入 0 返回且不误删。
- 产品提交 `910e369` 的 CI run `29646166398` 与固定 shoes schema run `29646166410` 成功。首次 PTY run 因验收脚本把完整环境的配置数量误写死为 2 而超时；菜单实际正确显示 7 项，未发现产品故障。
- 配置数量无关的测试修正提交 `2fdd1b7` 后，CI run `29646275985` 与 Ubuntu 24.04 acceptance run `29646275983` 全绿；后者真实完成短配置名、查看 URI、删除菜单输入 0 返回、修改配置、五协议、故障回滚、导出与卸载清理。
- 当前版本号为 0.1.9；本地 63/63 tests、check、clippy `-D warnings`、release build、doc、严格 package/publish dry-run、actionlint、ShellCheck 与 diff check 全部通过。源码已推送 main，尚未创建不可覆盖的 crates.io/GitHub Release 0.1.9。

## Milestone 16：真实的一节点一配置文件

- 菜单中的 `VLESS-REALITY-53453.yaml`、`SHADOWSOCKS-端口.yaml` 等名称现在对应 `/etc/shoes/profiles/` 下的真实独立 YAML 文件，不再只是由协议和端口临时拼出的显示标签。
- 每个 profile 文件只保存一个 shoes `ServerConfig` mapping；Rust 事务层按 sidecar state 顺序重新解析全部 mapping，确定性生成 shoes 实际加载的 `/etc/shoes/config.yaml` 顶层数组。
- 文件名只由受控协议枚举和规范 `u16` 端口推导，逻辑备注不进入路径；改端口会删除旧 basename 并创建新 basename，陌生文件、symlink、目录、特殊文件和 `0443` 等非规范写法均拒绝覆盖。
- 旧版只有 config/state 的安装在首次进入菜单时执行幂等迁移；聚合配置与 state 数量、顺序、端口或协议不一致时明确拒绝。旧备份在 staging 中补齐 profile 文件后再执行一致性和 shoes 校验。
- 添加、修改、删除都在同一进程间锁和部署事务中提交 config/state/profiles；删除只有在 systemd 成功切换后才清理证书，失败则同时恢复三类配置文件和 service snapshot。
- 本地单测覆盖单 mapping 形状、确定性聚合、迁移幂等、改端口重命名、陌生文件保护、状态写失败目录回滚及延迟凭据清理；当前 66/66 tests、fmt/check、Clippy、release、rustdoc、RustSec、actionlint 与 crate dry-run 全部通过。
- Ubuntu 24.04 workflow 已加入五协议真实文件、模拟旧版目录迁移、真实 PTY 改名/查看/删除、profile 目录故障回滚哈希、备份归档和恢复断言；等待产品提交推送后的远程运行证据。

## Milestone 6 修复结果

- 修复第二个受管配置必然被“仅一个 server”校验拒绝的问题。
- 把 shoes 外部校验移到正式文件提交之前，失败候选由临时文件自动清理。
- 对生成、删除、备份和恢复加 `/run/lock/ping-rust.lock` 进程间互斥，避免两个 ping-rust 实例互相覆盖。
- 配置和 sidecar 状态提交失败时恢复精确旧内容或“不存在”状态。
- 自动证书生成/后续验证失败时清理本次生成的证书与私钥。
- 更新、删除和恢复保留服务原 active/inactive 状态；恢复后的服务启动失败会回滚原目录并尝试恢复原服务。
- 恢复额外检查 sidecar schema、条目数量和监听端口一致性。
- 移除对最小系统可能缺失的 `which` 依赖，直接安全遍历 `PATH`。
- 为 Release 解包的 shoes 单文件增加 128 MiB 上限。

## Milestone 7 Debian 12 VPS 证据

- 环境：Debian 12 bookworm x86_64、systemd 252、404 MiB RAM + 2.5 GiB swap；初始无 Rust、shoes、ping-rust 或 shoes.service。
- `cargo install --path . --locked` 在低内存环境原生完成；默认 Release 安装随后约 2 秒完成。
- Reality TCP 443、Hysteria2 UDP 8443、TUIC UDP 10443 同时通过 shoes `--dry-run`，systemd 为 enabled/active，journal 无启动错误。
- Windows 外部 shoes 客户端通过 Reality 访问公网，观测出口为 VPS 公网 IP。首次失败由服务端日志定位为 VPS 系统钟慢约 27 分钟；从正确 RTC 校时后原配置立即成功。
- Clash Meta、sing-box、Nekobox 对三协议共 9 份导出均通过 YAML/JSON/非空 URI 检查，且未出现 Reality 服务端私钥。
- BBR、TCP/UDP 端口检查、日志、Release 更新、0600 备份与恢复、服务 inactive 状态保持均已执行。
- VPS 是用户提供的 Debian 12，不是成功标准指定的 Ubuntu 24.04；因此 Ubuntu 运行态结论仍明确保留为待验收。
- 默认 shoes LTO 在 404 MiB 内存下产生约 71 GB 读取并陷入页等待；安装器现按 `/proc/meminfo` 在低于 1 GiB 时自动单任务、关闭 LTO，正常内存服务器仍保留上游 release profile。
- 低内存模式用 51m35s 完成 crates.io shoes v0.2.2；同一 Reality 客户端端到端成功后恢复推荐的 v0.2.7 Release。
- 逐配置删除覆盖 active 有剩余、inactive 保持、最后一条自动停服；默认卸载确认保留配置哈希，随后 Release 重装恢复 enabled/active。
- 安装 chrony 后 NTP 误差约 0.1 ms；真实 reboot 后 boot ID 改变，shoes/chrony 自动启动，三端口监听且公网 Reality 再次成功。

## Milestone 9 Ubuntu 24.04 VPS 证据

- 环境：Ubuntu 24.04.3 LTS x86_64、systemd 255、约 960 MiB RAM；初始无 Rust、ping-rust、shoes、配置或 unit。
- 最小 rustup 环境首次暴露缺少 `cc` 的真实前置；安装 Ubuntu 官方 `build-essential pkg-config git ca-certificates` 后，公开 crates.io 0.1.2 与固定 Git 提交均约 2 分钟完成，README 已补充该依赖。
- 一键脚本从公开 v0.1.2 Release 下载、校验并安装成功；当前修复版本安装 shoes v0.2.7 后，Reality 从安装开始到 systemd active/listening 用时约 2 秒。
- Reality TCP 443、Hysteria2 UDP 8443、TUIC UDP 9443 同时运行；新增配置后 MainPID 改变且对应监听出现，证明活动服务实际重载了 YAML。
- 三协议的 Clash Meta、sing-box、Nekobox 共 9 份导出全部生成；备份恢复、更新、连续快速 restart、信息与日志路径均通过。
- 官方 Windows sing-box 1.13.14 读取 Reality 导出，配置检查与公网请求成功，代理出口为该 VPS；真实 reboot 前后各验证一次。
- reboot 后 boot ID 改变，`shoes.service` 仍 enabled/active，三个监听全部自动恢复；数字菜单 `9` 退出路径由真实伪终端验证。
- 删除 TUIC/Hysteria2 时服务保持 active 且对应端口消失；删除最后一条 Reality 后服务自动停止；`uninstall --purge` 删除 binary、unit 与配置。
- 公开 v0.1.3 一键安装器再次在该 VPS 校验成功；`enable-bbr` 写入 sysctl 后验证 `default_qdisc=fq`、`tcp_congestion_control=bbr`，随后删除测试 binary 并保留用户要求的 BBR 系统设置。
- 测试结束后清除远端导出、备份、回滚及三个临时安装 root；本机临时客户端配置和主机认证辅助文件也已删除，不保留测试凭据。

## Linux 交叉构建证据

构建链：cargo-zigbuild 0.23.0 + Zig 0.15.2，target 后缀显式指定 glibc 2.34。

| Target | ELF | 大小 | SHA-256 | 动态加载器 | 最高 GLIBC |
|---|---:|---:|---|---|---:|
| x86_64-unknown-linux-gnu.2.34 | ELF64 LE, machine 62 | 5,068,528 bytes | `067EDA152B49FBB16845202A952418C963FF786C7AD9C66626DE7AB52D40EF4F` | `/lib64/ld-linux-x86-64.so.2` | 2.34 |
| aarch64-unknown-linux-gnu.2.34 | ELF64 LE, machine 183 | 4,470,328 bytes | `A5FE31C4FA997EEAC4F385F2E1B27168DCAA1C5649830AC36562EB4FDD52BABE` | `/lib/ld-linux-aarch64.so.1` | 2.34 |

本地可检查产物位于 `target/linux-artifacts/`；`target` 已被 `.gitignore` 排除，不会意外发布二进制或交叉工具链。

## 最终自动化门禁

- `cargo fmt -- --check`
- `cargo check --all-targets`
- `cargo test --all-targets`：66/66 通过
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --locked --release`
- `cargo doc --locked --no-deps`
- `cargo install --path . --locked` 后执行 `ping-rust --help`
- `cargo package --locked` / `cargo publish --dry-run --locked`：提交前 `--allow-dirty` 候选打包 32 个文件、378.6 KiB（压缩 90.0 KiB），隔离解包重编译与上传前校验通过；提交后仍需 strict clean-worktree 复验
- `cargo-audit 0.22.2`：扫描当前 Cargo.lock 的 224 个依赖，RustSec 1166 条 advisory 中无命中
- `SOURCE_SNAPSHOT.md`：14/14 section、282,263 bytes，Cargo/主要 Rust（含 deployment/fast_add）/README 全部与真实文件逐字一致
- actionlint v1.7.12：`ci.yml`、`release.yml`、`shoes-schema.yml`、`ubuntu-acceptance.yml` 零诊断；ShellCheck v0.11.0 对一键安装器零诊断
- v0.1.8 产品提交 `960edde`：main CI `29645174662`、Ubuntu 24.04 acceptance `29645174670`、固定 shoes schema `29645174650` 全部成功；tag CI `29645387085` 与 schema `29645387104` 再次成功
- v0.1.8 Release run `29645387081`：双架构 MUSL、SHA256SUMS、公开一键安装默认 Reality 全部成功；crates.io 公开隔离安装返回 `ping-rust 0.1.8`
- v0.1.9 简洁菜单：CI `29646275985` 与 Ubuntu 24.04 acceptance `29646275983` 成功；真实 PTY 覆盖查看短名称/URI、删除菜单 0 返回且不误删
- GitHub shoes schema run `29635356030`：固定 shoes 0.2.8 commit 的五单协议、五协议联合、六 Shadowsocks cipher、Reality+AnyTLS 共 13 次显式 dry-run 全部成功，且日志敏感信息扫描为零命中
- GitHub Actions CI run `29635356053`：五个目标发行版全部成功
- GitHub main CI run `29635760760`：五个目标发行版全部成功；Ubuntu 24.04 acceptance run `29635760772`：五协议 systemd、导出、运维和清理全成功
- GitHub Actions CI run `29630050826`：systemd 修复提交的跨发行版矩阵全部成功
- GitHub Ubuntu 24.04 acceptance run `29630050797`：公开 crates 安装、当前源码、Reality 三分钟预算、三协议端口、9 份导出、备份恢复、更新、连续重启与卸载清理全部成功
- GitHub Actions CI run `29627957682`：v0.1.2 tag 的 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 共 5/5 jobs 成功
- GitHub Release run `29626549437`：x86_64 musl、aarch64 musl、Publish GitHub Release 共 3/3 jobs 成功；发布 job 从公开资产执行安装器并得到 `ping-rust 0.1.0`
- v0.1.0 公开资产：x86_64 2,457,171 bytes / SHA-256 `99d6d06e30f0f2cc3698318ff6f6e924da71ef4c283cbbfd11dddb936ee49120`；aarch64 2,298,967 bytes / SHA-256 `3a28ff756fa23c58de4cd6a798dc8ae91e6c4bd9ff21dc93eeb9025f68a771a3`；两者均与 SHA256SUMS 交叉核验且归档仅含 `ping-rust`
- v0.1.1 Release run `29627638839`：两个 musl build、checksum 与公开 Release 创建成功；最终强制自更新因 install.sh 对可写自定义目录仍无条件 sudo 而失败。权限拒绝发生在原子替换前，旧 binary 未损坏；修复进入 0.1.2，不改写已公开 tag。
- GitHub Release run `29627957641`：v0.1.2 的 x86_64 musl、aarch64 musl、Publish GitHub Release 共 3/3 jobs 成功；公开一键安装和 `self-update --version v0.1.2 --force` 均通过。
- v0.1.2 公开资产独立下载复核：x86_64 2,491,684 bytes / SHA-256 `d6ae81cc349791b7d189fbcb13abb3fc41898faf08beb69217e71e6561c9ee78`；aarch64 2,331,294 bytes / SHA-256 `c0ed8f1611691c6da45c7268af5095d80fd882b08884d56e195c4c373e1b6a1a`；两者与 SHA256SUMS、GitHub API digest 一致，且各归档仅含一个 `ping-rust`。
- GitHub Release run `29630671628`：v0.1.3 的 x86_64 musl、aarch64 musl 与 Publish GitHub Release 3/3 jobs 成功；公开一键安装和强制自更新探针均通过。
- v0.1.3 公开资产独立下载复核：x86_64 2,491,829 bytes / SHA-256 `3a5f37e462e534cbb123dfde4edbe44663363679b7ba7582681180d203ea8d01`；aarch64 2,331,135 bytes / SHA-256 `b25497ac2dbdc55868a6a6abef27bca4835c4324fe2112b1e38b24e6e02210d7`；两者与 SHA256SUMS、GitHub API digest 一致。
- crates.io 0.1.3 正式发布后，官方 API 最新版本为 0.1.3；全新隔离 root 从 registry 下载并编译，`ping-rust --version` 与 `--help` 均成功。
- 最终 main CI run `29630793672` 的 Ubuntu 22.04/24.04、Debian 12、Rocky 9、AlmaLinux 9 全部成功；Ubuntu acceptance run `29630793721` 明确从 crates.io 安装 0.1.3，并在 1m53s 内完成当前源码、三协议、systemd、9 份导出、运维与清理全链路。
- v0.1.4 发布前 main 门禁：CI run `29637074075` 五个目标系统全部成功；Ubuntu 24.04 acceptance run `29637074073` 在 1m55s 内完成五协议 systemd、客户端导出、运维与清理；shoes schema run `29637074085` 的 13 次显式 dry-run 全部成功。
- GitHub Release run `29637241120`：v0.1.4 的 x86_64 musl、aarch64 musl 与 Publish GitHub Release 3/3 jobs 成功；tag/Cargo 版本一致性、静态依赖检查、QEMU ARM64 版本探针、公开一键安装与强制自更新均通过。
- v0.1.4 公开资产独立下载复核：x86_64 2,565,491 bytes / SHA-256 `2915b52ae0b50f0e201a76cb5b3c6636b594fe2edca4c8bf14067ac615753d25`；aarch64 2,401,406 bytes / SHA-256 `380954eb53bd1904b0c6d547de2e48380c0c41a785a48ad9b5efa8b8d6a8ceb7`；两者与 SHA256SUMS、GitHub API digest 一致。
- crates.io 0.1.4 正式发布且未 yanked，crate checksum 为 `bc8e1ecaba7498d67e5494eb819212eecf173138cb5f61a2328d4abd752d866c`；全新隔离 root 从 registry 下载并编译，`ping-rust --version` 返回 `ping-rust 0.1.4`，帮助入口正常。
- v0.1.5 发布前：CI run `29640353028`、shoes schema run `29639726196`、Ubuntu acceptance run `29640353088` 全部成功；Ubuntu 新增真实 sb 数字 PTY 与 systemd 一次性启动故障回滚证据。
- GitHub Release run `29640482140` 全部成功：x86_64/aarch64 MUSL 构建与运行探针、正式 Release、公开一键安装、`sb` 相对链接与既有命令冲突保护、自更新均通过。
- v0.1.5 公开资产：x86_64 2,601,613 bytes / SHA-256 `c810560be21889a44275190c42a80d9d36f6c9b7fe1b13d8aa01db44f3f2205d`；aarch64 2,433,902 bytes / SHA-256 `39a3e32b03994bc44148151652c08d61dd15e15526a3b34ecfca71451951cfc9`；两者与公开 `SHA256SUMS` 和 GitHub API digest 一致。
- crates.io 0.1.5 正式发布；`cargo search ping-rust` 返回 0.1.5，全新隔离 Cargo root 从 registry 下载编译后 `ping-rust --version` 返回 `ping-rust 0.1.5`，并确认快速添加帮助包含 `--plain`。
- v0.1.6 main 门禁：CI run `29641525438`、shoes schema run `29641525465`、Ubuntu acceptance run `29641525455` 全部成功；真实 PTY 使用连续协议编号并输入 0 退出。
- v0.1.6 Release run `29641681305` 全部成功；双架构 MUSL、SHA256SUMS、一键安装、`prs`、冲突保护、旧 `sb` 迁移与自更新均通过。
- crates.io 0.1.6 正式发布且公开检索可见；独立 registry 安装、版本和快速添加帮助验证成功。
- v0.1.7 发布前 main 门禁：CI run `29643148634` 和 Ubuntu 24.04 acceptance run `29643148659` 成功；安装器 bootstrap 零输入完成 Reality、systemd、监听和完整后续五协议验收。
- v0.1.7 tag CI run `29643229768` 五个目标发行版全部成功；Release run `29643229765` 的 x86_64/aarch64 MUSL 与公开一键安装完整探针全部成功。
- v0.1.7 tag shoes schema run `29643229756` 成功；固定 shoes 0.2.8 的全部协议生成与 dry-run 矩阵再次通过。
- v0.1.7 公开资产：x86_64 2,598,642 bytes / SHA-256 `ac31ed3e9db951ffb900f970fb7f027bfeb11bcb0cff7c625520d0d719c50767`；aarch64 2,431,641 bytes / SHA-256 `d15373ce83ea3dfb58b574f745d76714aeeefbf1e91db6612e1fb49fe260d455`；两者与 SHA256SUMS、GitHub API digest 一致。
- crates.io 0.1.7 正式发布；公开 registry 搜索与全新隔离安装均确认 `ping-rust 0.1.7`。

## 发布状态

公开稳定版 v0.1.8 已发布。main 的 v0.1.9 候选新增真实一节点一配置文件及简洁菜单，尚未创建 crates.io/GitHub Release；本 Goal 只授权形成并推送经验证候选，不擅自发布不可覆盖版本。
