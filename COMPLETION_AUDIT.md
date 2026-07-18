# ping-rust 完成度与验收证据

审计日期：2026-07-18

本文件把原始目标逐项映射到实现、自动化证据和外部验收边界。`已实现` 表示代码路径和自动化证据完整；Debian 12 与成功标准指定的 Ubuntu 24.04 均已完成独立实机验收。

## 需求映射

| 原始需求 | 状态 | 实现位置 | 当前证据 |
|---|---|---|---|
| Rust 2021、Rust 代码占绝对主导 | 已实现 | `Cargo.toml`、`src/` | 4,371 行 Rust / 177 行安装 shell，Rust 占 96.11%；代理、配置、服务、运维与自更新核心均为 Rust |
| clap v4 子命令与 233boy 风格数字菜单 | 已实现 | `src/cli.rs`、`src/menu.rs` | 主菜单及全部子菜单明确显示 `1..N` 并校验数字输入；九个主入口完整接通 |
| shoes GitHub Release 预编译安装 | 已实现，Debian/Ubuntu 实测 | `src/installer.rs` | v0.2.7 GNU 不兼容时自动回退 digest 校验过的 static musl；Ubuntu 24.04 约 2 秒完成 Reality 服务部署且提交前健康检查通过 |
| `cargo install shoes` 源码安装 | 已实现，Debian 实测 | `src/installer.rs` | 在无 cargo PATH、404 MiB RAM 下从当前 binary 同目录解析 cargo，低内存模式 51m35s 安装 v0.2.2；三协议 dry-run 与公网 Reality 均通过 |
| Reality X25519 密钥和完整 shoes YAML | 已实现 | `src/config.rs` | X25519 派生单测；本地 shoes 0.2.8 `--dry-run` 解析成功 |
| Hysteria2 与 TUIC 快速配置 | 已实现 | `src/config.rs` | 随机凭据、自签名/外部证书支持；本地 shoes 0.2.8 同时加载两套 PEM 并解析成功 |
| Shadowsocks 六种 cipher | 已实现 | `src/config.rs`、`src/client.rs` | legacy/2022 六种 shoes cipher 全部真实 dry-run；2022 标准 Base64 与 16/32 字节前置校验；客户端 ChaCha 标准名称单独映射 |
| AnyTLS（TLS 与 Reality 外层） | 已实现 | `src/config.rs`、`src/cli.rs`、`src/menu.rs` | 多用户、UDP、padding、fallback、自签名/外部证书和 Reality 高级模式均已接通；TLS 与 Reality 两种配置通过固定 shoes dry-run |
| 固定 latest shoes schema 验证 | 已实现 | `.github/workflows/shoes-schema.yml` | 固定 `386b11532424b8665ee3e46340c6236fb3c47595` / 0.2.8 从源码构建；五单协议、五协议联合、六 cipher 与 Reality+AnyTLS 共 13 次显式 dry-run 成功 |
| 多配置添加、查看、删除 | 已实现 | `src/config.rs`、`src/cli.rs`、`src/menu.rs` | sidecar 状态、端口冲突和条目一致性检查；多 server 与精确回滚测试 |
| 候选验证与安全提交 | 已实现 | `src/config.rs`、`src/utils.rs` | 进程间 advisory lock；同目录候选先执行 shoes dry-run；失败候选不触碰正式配置测试 |
| systemd unit 与启停/重启/状态/日志 | 已实现，Debian/Ubuntu 实测 | `src/service.rs`、`systemd/ping-rust.service` | 首次、active、failed 三态启用策略和 start-limit 恢复均通过；Ubuntu 真实 reboot 后自动 active，三协议端口全部监听 |
| 更新与卸载 | 已实现，Debian/Ubuntu 实测 | `src/installer.rs`、`src/service.rs` | Release/cargo 更新、连续重启、逐配置删除、最后一条自动停服、默认保留与 `--purge` 清理均通过 |
| BBR、端口检查、备份恢复 | 已实现，Debian/Ubuntu 实测 | `src/operations.rs` | 两台 VPS 均由 ping-rust 写入并验证 bbr/fq；TCP/UDP 端口判断、0600 备份 round-trip 和服务状态恢复均通过 |
| Clash Meta、sing-box、Nekobox 客户端导出 | 已实现，前三协议 Debian/Ubuntu 实测 | `src/client.rs` | 五协议 YAML/JSON/URI 解析测试；Reality 私钥不泄漏；普通 AnyTLS 支持三格式，AnyTLS+Reality 仅输出 sing-box，Mihomo/标准 URI 不支持时明确报错 |
| Ubuntu 22.04/24.04、Debian 12、Rocky/Alma 9 x86_64 | 构建/测试通过；Ubuntu/Debian 运行态实测 | `.github/workflows/ci.yml`、`.github/workflows/ubuntu-acceptance.yml` | CI 覆盖五个目标系统；Ubuntu acceptance run `29635760772` 实际加载五协议并复核监听，另有 Ubuntu 24.04.3 与 Debian 12 独立 systemd/公网验收；GNU ELF 最高 GLIBC 2.34 |
| ARM64 次优先支持 | 构建与模拟运行已证实 | `src/installer.rs`、Release workflow | aarch64 GNU ELF 最高 GLIBC 2.34；v0.1.3 aarch64 musl 静态 binary 通过 qemu-user-static `--version` 并公开发布 |
| ping-rust 预编译一键安装 | 已发布并端到端验证 | `.github/workflows/release.yml`、`scripts/install.sh` | v0.1.3 的 x86_64/aarch64 musl、SHA256SUMS 已公开；tag workflow 3/3 jobs 成功，并从公开 URL 完成指定版本安装与 version 验证 |
| ping-rust 原生自更新 | 已发布并端到端验证 | `src/self_update.rs`、`src/cli.rs`、`src/menu.rs` | 独立 `self-update` 保留 shoes `update` 语义；v0.1.3 发布 job 在非 root 自定义目录真实完成公开资产下载、双重 SHA-256、运行中原子替换和安装后版本复核 |
| README、MIT、cargo install 发布 | 已发布并验证 | `README.md`、`LICENSE`、`scripts/install.sh` | README 第一屏提供无需 Rust 的一键入口，并保留 crates.io/Git/源码安装；release build、doc、隔离 `cargo package` 门禁通过 |
| GitHub 源码开源 | 已发布 | `Cargo.toml`、GitHub `main` | `Jyanbai/ping-rust` 已为 Public/非空并建立 `main`；首个提交与跨平台 CI 修复均已推送 |
| 公开 `cargo install ping-rust` | 已发布并验证 | crates.io `ping-rust 0.1.3` | 正式 `cargo publish --locked` 成功；官方 API 与独立 `cargo install ping-rust --version 0.1.3 --locked` 均验证公共版本、帮助和运行入口 |
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
- `cargo test --all-targets`：41/41 通过
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --locked --release`
- `cargo doc --locked --no-deps`
- `cargo install --path . --locked` 后执行 `ping-rust --help`
- `cargo package --locked` / `cargo publish --dry-run --locked`：当前 clean worktree 打包 29 个文件，包含五协议示例与固定 shoes workflow；隔离解包重编译与上传前校验均通过
- `cargo-audit 0.22.2`：扫描当前 Cargo.lock 的 224 个依赖，RustSec 1166 条 advisory 中无命中
- `SOURCE_SNAPSHOT.md`：12/12 section、175,658 bytes，Cargo/主要 Rust/README 全部与真实文件逐字一致
- actionlint v1.7.12：`ci.yml`、`release.yml`、`shoes-schema.yml`、`ubuntu-acceptance.yml` 零诊断；ShellCheck v0.11.0 对一键安装器零诊断
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

## 发布状态

公开源码已推送到 `Jyanbai/ping-rust` 的 `main`。Ubuntu 24.04 成功标准已由独立 VPS 与 GitHub runner 双重完成；v0.1.3 已同时发布到 GitHub Releases 与 crates.io，双架构静态资产、一键安装、自更新和公共 cargo 安装均已验证。

本次五协议对齐只按用户要求推送源码到 `main`，未创建新 tag、GitHub Release 或 crates.io 版本。公开 v0.1.3 是本次变更前的稳定版；五协议在下一版本发布前应使用 Git main 安装验证。
