# ping-rust 完成度与验收证据

审计日期：2026-07-17

本文件把原始目标逐项映射到实现、自动化证据和外部验收边界。`已实现` 表示代码路径和自动化证据完整；实机证据明确区分已验收的 Debian 12 与尚待验收的 Ubuntu 24.04。

## 需求映射

| 原始需求 | 状态 | 实现位置 | 当前证据 |
|---|---|---|---|
| Rust 2021、Rust 代码占绝对主导 | 已实现 | `Cargo.toml`、`src/` | 2,762 行 Rust / 166 行安装 shell，Rust 占 94.33%；代理、配置、服务与运维核心仍全部为 Rust |
| clap v4 子命令与 233boy 风格数字菜单 | 已实现 | `src/cli.rs`、`src/menu.rs` | 主菜单及全部子菜单明确显示 `1..N` 并校验数字输入；九个主入口完整接通 |
| shoes GitHub Release 预编译安装 | 已实现，Debian 实测 | `src/installer.rs` | v0.2.7 GNU 因 GLIBC_2.38 不兼容时自动回退 digest 校验过的 static musl；约 2 秒完成且提交前健康检查通过 |
| `cargo install shoes` 源码安装 | 已实现，Debian 实测 | `src/installer.rs` | 在无 cargo PATH、404 MiB RAM 下从当前 binary 同目录解析 cargo，低内存模式 51m35s 安装 v0.2.2；三协议 dry-run 与公网 Reality 均通过 |
| Reality X25519 密钥和完整 shoes YAML | 已实现 | `src/config.rs` | X25519 派生单测；本地 shoes 0.2.8 `--dry-run` 解析成功 |
| Hysteria2 与 TUIC 快速配置 | 已实现 | `src/config.rs` | 随机凭据、自签名/外部证书支持；本地 shoes 0.2.8 同时加载两套 PEM 并解析成功 |
| 多配置添加、查看、删除 | 已实现 | `src/config.rs`、`src/cli.rs`、`src/menu.rs` | sidecar 状态、端口冲突和条目一致性检查；多 server 与精确回滚测试 |
| 候选验证与安全提交 | 已实现 | `src/config.rs`、`src/utils.rs` | 进程间 advisory lock；同目录候选先执行 shoes dry-run；失败候选不触碰正式配置测试 |
| systemd unit 与启停/重启/状态/日志 | 已实现，Debian 实测 | `src/service.rs`、`systemd/ping-rust.service` | daemon-reload、enable/start/stop/restart、状态与 journal 均通过；VPS 重启 11 秒后自动 active，三协议端口全部监听 |
| 更新与卸载 | 已实现，Debian 实测 | `src/installer.rs`、`src/service.rs` | Release/cargo 更新、active/inactive 状态保持、逐配置删除、最后一条自动停服、默认卸载保留配置及重装恢复均通过 |
| BBR、端口检查、备份恢复 | 已实现，Debian 实测 | `src/operations.rs` | BBR 当前算法为 bbr；TCP/UDP 端口判断正确；0600 备份 round-trip、marker 清理、哈希一致及 active/inactive 恢复均通过 |
| Clash Meta、sing-box、Nekobox 客户端导出 | 已实现，Debian 实测 | `src/client.rs` | 三协议共 9 份导出均成功解析；逐值检查 Reality 服务端私钥泄漏为 0 |
| Ubuntu 22.04/24.04、Debian 12、Rocky/Alma 9 x86_64 | 远程构建/测试通过；Ubuntu 运行态待实机 | `.github/workflows/ci.yml`、交叉构建证据 | CI run `29597417851` 的 Ubuntu 22.04/24.04、Debian 12、Rocky 9、AlmaLinux 9 共 5/5 jobs 成功；Debian 12 x86_64 另有原生 systemd/公网验收；Linux GNU ELF 最高 GLIBC 2.34 |
| ARM64 次优先支持 | 构建与模拟运行已证实 | `src/installer.rs`、Release workflow | aarch64 GNU ELF 最高 GLIBC 2.34；v0.1.0 aarch64 musl 静态 binary 通过 qemu-user-static `--version` 并公开发布 |
| ping-rust 预编译一键安装 | 已发布并端到端验证 | `.github/workflows/release.yml`、`scripts/install.sh` | v0.1.0 的 x86_64/aarch64 musl、SHA256SUMS 已公开；tag workflow 3/3 jobs 成功，并从公开 URL 完成指定版本安装与 version 验证 |
| README、MIT、cargo install 发布准备 | 已实现 | `README.md`、`LICENSE`、`scripts/install.sh` | README 第一屏提供无需 Rust 的一键入口，并保留 crates.io/Git/源码安装；release build、doc、隔离 `cargo package` 门禁通过 |
| GitHub 源码开源 | 已发布 | `Cargo.toml`、GitHub `main` | `Jyanbai/ping-rust` 已为 Public/非空并建立 `main`；首个提交与跨平台 CI 修复均已推送 |
| 公开 `cargo install ping-rust` | 等待 crates.io 认证 | 发布包 | crates.io API 当前显示 `ping-rust` 名称未占用，publish dry-run 已通过；尚未真实发布 crate，不能宣称该安装命令已上线 |
| 干净 Ubuntu 24.04 三分钟部署并公网连通 | Debian 路径通过，Ubuntu 待实机 | `README.md` 验收清单 | Debian 12 上已安装 ping-rust 后，Release + 三协议生成远低于 3 分钟；Windows 外部 Reality 客户端经代理观察到 VPS 公网出口；提供的 VPS 不是 Ubuntu |

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
- `cargo test --all-targets`：25/25 通过
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --locked --release`
- `cargo doc --locked --no-deps`
- `cargo install --path . --locked` 后执行 `ping-rust --help`
- `cargo package --locked` / `cargo publish --dry-run --locked`：发布工作流提交后以干净工作区打包 24 个文件，隔离解包重编译与上传前校验均通过
- `cargo audit`：扫描 Cargo.lock 的 240 个依赖，RustSec 1166 条 advisory 中无命中
- `SOURCE_SNAPSHOT.md`：11/11 section、110,868 bytes，README section 与真实文件逐字一致
- actionlint v1.7.12：`ci.yml` 与新增 `release.yml` 零诊断；ShellCheck v0.11.0 对一键安装器零诊断
- GitHub Actions CI run `29626486447`：发布提交的 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 共 5/5 jobs 成功
- GitHub Release run `29626549437`：x86_64 musl、aarch64 musl、Publish GitHub Release 共 3/3 jobs 成功；发布 job 从公开资产执行安装器并得到 `ping-rust 0.1.0`
- v0.1.0 公开资产：x86_64 2,457,171 bytes / SHA-256 `99d6d06e30f0f2cc3698318ff6f6e924da71ef4c283cbbfd11dddb936ee49120`；aarch64 2,298,967 bytes / SHA-256 `3a28ff756fa23c58de4cd6a798dc8ae91e6c4bd9ff21dc93eeb9025f68a771a3`；两者均与 SHA256SUMS 交叉核验且归档仅含 `ping-rust`

## 剩余的外部发布与验收

仍需要一台允许 root/systemd/公网入站的全新 Ubuntu 24.04 x86_64 VPS 重复 README 清单。Debian 12 已给出 Linux/systemd/公网路径的强证据，但不能替代明确指定的 Ubuntu 24.04 成功标准。

公开源码已推送到 `Jyanbai/ping-rust` 的 `main`，当前远程 CI 5/5 jobs 成功；v0.1.0 Release 与 README 一键安装命令已经上线并由 Ubuntu runner 端到端验证。`cargo publish --dry-run` 已通过，真正发布 crates.io 仍需用户提供发布授权与登录凭据。
