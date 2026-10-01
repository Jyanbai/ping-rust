# ping-rust 完成度与验收证据

## v0.2.0 功能 × 验证方式

下表只引用仓库中实际存在的测试或 workflow；本地未运行的验收不会标成通过。

| 功能 | 适用 shoes 来源 | 验证方式 | 具体证据 |
|---|---|---|---|
| 13 种协议配置与 schema | github-release v0.2.7 / verified-pin；历史证据按条目版本 | CI 容器 / shoes `--dry-run` | `.github/workflows/shoes-schema.yml` 的 `Dry-run every checked-in example`、`scripts/ci/validate-shoes-schema.sh` |
| Verified Hot Reload | verified-pin（固定 revision） | CI systemd acceptance、单元测试 | `.github/workflows/ubuntu-acceptance.yml` 热重载步骤；`service::tests::hot_reload_requires_same_pid_and_exact_listener_delta` |
| Chain Proxy 2.0 Nodes/Pools/Chains/规则 | github-release v0.2.7 / verified-pin；历史证据按条目版本 | CI systemd acceptance、单元测试 | `.github/workflows/chain-systemd.yml` 的 `chain_systemd_acceptance`；`tests/chain_v2_e2e.rs`；`chain_proxy::state::tests::*` |
| Pool 内全部节点手动探针 | github-release v0.2.7 / verified-pin；历史证据按条目版本 | 单元测试、CI systemd acceptance 通过 | `chain_proxy::tests::pool_probe_summary_reports_success_and_failure`、`chain_proxy::tests::pool_probe_reports_missing_member_without_network`；`.github/workflows/chain-systemd.yml` 的 `chain_systemd_acceptance` mixed Pool stage 对在线节点严格断言 `namespace-two: 可用[^\r\n]*ms`，Ubuntu/Debian [run 36713152604](https://github.com/Jyanbai/ping-rust/actions/runs/36713152604) 通过 |
| Update Center 与降级保护 | github-release v0.2.7 / verified-pin；历史证据按条目版本 | 单元测试 | `cli::tests::update_status_comparison_is_fail_soft_and_drift_is_explicit`；`installer::tests::known_release_downgrade_is_blocked_unless_explicitly_allowed` |
| H2MUX | github-release v0.2.7 / verified-pin；历史证据按条目版本 | CI 容器、单元测试 | `.github/workflows/shoes-schema.yml` 的 sing-box 检查与 watcher probe；`client::tests::h2mux_exports_only_valid_sing_box_preferences` |
| SOCKS5、Snell v3、NaiveProxy、SS2022+ShadowTLS v3 | github-release v0.2.7 / verified-pin；历史证据按条目版本 | CI systemd acceptance、单元测试 | `.github/workflows/ubuntu-acceptance.yml` 的 `Verify prs numeric PTY flow for all protocol presets`；`config::tests::socks5_generation_round_trip_and_edits_preserve_exact_auth_and_udp_state`、`config::tests::snell_v3_yaml_matches_fixed_shoes_schema`、`config::tests::naiveproxy_generates_tls_h2_inner_auth_and_random_credentials`、`config::tests::shadowtls_v3_generates_nested_tcp_only_shadowsocks` |
| 实机 VPS v0.2.0 全量清单 | 历史测试 github-release v0.2.7 | 失败（最新为第 2 项闸门） | 2026-10-01，首次 Reality 外部失败记录保留；追加定位为大陆 OpenWrt/Passwall2 测试路径问题，用户授权临时直连例外后同配置外部请求通过。随后新增认证 SOCKS5 节点使 MainPID 改变，Hot Reload 失败；改端口/删除和第 3–8 项未验证，停止发版。详见“v0.2.x 实机 VPS 验收”。 |

### 证据边界

本文早期 Milestone 保留历史版本记录；每条 Debian/Ubuntu VPS 记录适用其标题和条目中注明的 ping-rust、shoes 版本，不可外推为 v0.2.0。本文新增代码的门禁结果只在实际运行后记录。

本 PR 的历史运行记录：本地三项 Rust 门禁通过（160 个单元测试）；[CI run 36703040410](https://github.com/Jyanbai/ping-rust/actions/runs/36703040410)、[shoes schema run 36703040429](https://github.com/Jyanbai/ping-rust/actions/runs/36703040429)、[Ubuntu/Debian Chain systemd run 36703814702](https://github.com/Jyanbai/ping-rust/actions/runs/36703814702)、[Ubuntu/Debian acceptance run 36700674910](https://github.com/Jyanbai/ping-rust/actions/runs/36700674910) 和[upstream drift run 36700674699](https://github.com/Jyanbai/ping-rust/actions/runs/36700674699) 已成功。这些 run 均早于本次严格在线 Pool 断言。当前本地 `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets --all-features -- -D warnings`、`cargo test --locked --all-targets` 已通过（161 个单元测试）；严格在线 Pool 断言在 [Ubuntu/Debian Chain run 36713152604](https://github.com/Jyanbai/ping-rust/actions/runs/36713152604) 通过。旧版 upstream drift run 的整体成功不代表 ping-rust 的 systemd 热重载流程经过 upstream shoes 验证。

## v0.2.x 实机 VPS 验收

- 记录日期：2026-10-01（Asia/Hong_Kong）。
- 测试对象 / MERGE_SHA：`74b39c86d1065c1fb483c4c7c2f163976f120f2f`。
- [PR #18](https://github.com/Jyanbai/ping-rust/pull/18) 于 2026-10-01 10:56:53 +08:00 squash 合并；提交标题为 `feat: add chain pool probes and sync v0.2.0 docs (#18)`。
- 合并前 head：`c5bbc0632d5cbaf26c3bc4bdcb9a0bd5a89fbcac`；GitHub API 返回该 head 的 14/14 check runs 均为 completed/success，legacy commit status contexts 为 0。
- 合并前成功 runs：CI [36714079418](https://github.com/Jyanbai/ping-rust/actions/runs/36714079418)、[36714086358](https://github.com/Jyanbai/ping-rust/actions/runs/36714086358)，schema [36714086309](https://github.com/Jyanbai/ping-rust/actions/runs/36714086309)，Chain systemd [36714217716](https://github.com/Jyanbai/ping-rust/actions/runs/36714217716)，upstream drift [36714222657](https://github.com/Jyanbai/ping-rust/actions/runs/36714222657)。这些均为 CI 证据。
- 合并后的四个 runs 均已 completed/success：CI [36808215481](https://github.com/Jyanbai/ping-rust/actions/runs/36808215481)、schema [36808215545](https://github.com/Jyanbai/ping-rust/actions/runs/36808215545)、Chain systemd [36808215360](https://github.com/Jyanbai/ping-rust/actions/runs/36808215360)、Ubuntu acceptance [36808215327](https://github.com/Jyanbai/ping-rust/actions/runs/36808215327)。这些均为 CI 证据，不是 prs-test 实机验收。
- VPS 系统版本 / 架构：Debian GNU/Linux 13 (trixie)，`DEBIAN_VERSION_FULL=13.7`；x86_64；systemd 257；1 vCPU；1913 MiB RAM；1024 MiB swap。`timedatectl show -p NTPSynchronized` 返回 `yes`。
- SSH 前置：通过。初始 `ssh prs-test` 因别名尚未配置而返回 255；用户补充测试主机与 PPK 登录方式后，已在仓库之外配置本机 `prs-test`，实际 `ssh prs-test 'id -u'` 返回 `0`。主机地址和密钥不进入仓库记录。
- 初始基线：`/etc/shoes`、`/etc/systemd/system/shoes.service`、`/usr/local/bin/shoes`、`/usr/local/bin/ping-rust`、`/root/.cargo/bin/ping-rust` 均不存在，`shoes.service` 为 inactive；尚无 Rust 工具链。此基线不代表系统没有其它软件或服务。
- 构建前置：`apt-get update` 与 `apt-get install -y --no-install-recommends build-essential pkg-config git ca-certificates curl sudo python3` 成功；最小 rustup 工具链实际返回 `rustc 1.98.1`、`cargo 1.98.1`。
- 源码安装首次尝试：指定 MERGE_SHA 的 `cargo install --git ... --rev ... --locked` 实际退出 101，输出 `failed to write .../lib.rmeta: No space left on device (os error 28)`；`df -h / /tmp` 显示根磁盘仍有 2.3 GiB 可用，而 `/tmp` 为 957 MiB tmpfs 且已满。保留失败日志后，仅将本次 Cargo 临时目录迁至私有验收目录，并设置 `TMPDIR` / `CARGO_BUILD_BUILD_DIR` 后重试相同命令；重试在 4m00s 完成，退出 0，版本为 `ping-rust 0.2.0`。随后 `ping-rust install-self --install-dir /usr/local/bin --quiet --no-bootstrap` 将本次编译结果安装到 sudo PATH，未提前部署节点。
- 本机客户端前置：通过。已从 SagerNet/sing-box 官方 Release `v1.14.2` 下载 `sing-box-1.14.2-windows-amd64.zip`，与 GitHub asset digest 比对 SHA-256 一致；实际执行 `sing-box.exe version` 返回 `sing-box version 1.14.2`、`windows/amd64`，tags 包含 `with_quic`、`with_utls`、`with_naive_outbound`。文件仅存于本地忽略的 `target/` 目录。版本与构建特性输出不替代协议连接验收。
- shoes pin 保持 `386b11532424b8665ee3e46340c6236fb3c47595`。

下表区分实际执行项与因闸门而未执行项。第 1 项部署阶段无需协议、端口或凭据输入；出现正常管理菜单后只输入 `0` 退出。节点凭据由产品自动生成；Windows 本地 sing-box 的 loopback mixed/SOCKS5 入口也配置用户名和随机密码。任何密钥、认证参数、分享链接和主机地址均不写入本记录。

| 项目 | 状态 | 关键命令 / 脱敏输出摘要 / 未验证原因 |
|---|---|---|
| 1. 零输入 Reality 部署、外部握手与出口 | 失败 | 实际 `cargo install --git https://github.com/Jyanbai/ping-rust.git --rev 74b39c86d1065c1fb483c4c7c2f163976f120f2f --locked` 成功后执行 `sudo ping-rust`：出现首次自动部署提示和分享链接，退出 0；shoes 来源为 GitHub Release v0.2.7，服务 enabled/active，MainPID `1348455`；`ss -ltnp` 确认 Reality TCP `32352` 监听。`sudo ping-rust export sing-box --profile <NODE_ID> --server <VPS_ADDRESS> --output <PRIVATE_CONFIG>` 后，Windows `sing-box.exe check -c <PRIVATE_CONFIG>` 退出 0，`sing-box.exe run -c <PRIVATE_CONFIG>` 正常启动。实际 `curl.exe --noproxy '' --socks5-hostname 127.0.0.1:<LOCAL_PORT> --proxy-user <AUTH> --fail --silent --show-error --max-time 30 https://api.ipify.org` 退出 97：`cannot complete SOCKS5 connection to api.ipify.org. (1)`；客户端 VLESS outbound 日志为 `15.0s ... context deadline exceeded`。Reality 外部请求失败；未取得出口 IP，出口一致性为未验证。 |
| 2. Hot Reload：新增 / 修改端口 / 删除非最后 SOCKS5 节点 | 未验证 | 第 1 项失败后按闸门停止。未执行新增、改端口或删除，也没有相应前后 PID/监听证据。原计划使用带认证的 `sudo ping-rust add socks5 --port <PORT> --yes`、菜单端口修改、`sudo ping-rust delete <NODE_ID> --yes`，每步前后记录 `systemctl show shoes.service -p MainPID --value` 和 `ss -ltnp`。 |
| 3a. SS2022 + ShadowTLS v3 | 未验证 | 因第 1 项闸门停止；未执行 `sudo ping-rust add shadowsocks --shadowtls --yes`、sing-box 导出或本机外部请求。 |
| 3b. 带认证 SOCKS5 | 未验证 | 因第 1 项闸门停止；未生成服务器 SOCKS5 节点或执行 `curl --socks5-hostname <VPS_ADDRESS>:<PORT> --proxy-user <AUTH> <TEST_URL>`。Reality 测试使用的本机带认证入口不替代此项 VPS SOCKS5 验收。 |
| 3c. Hysteria2 | 未验证 | 因第 1 项闸门停止；未执行 `sudo ping-rust add hysteria2 --yes`、UDP 放行或外部连接，无法判断安全组是否允许 UDP。 |
| 3d. NaiveProxy | 未验证 | 因第 1 项闸门停止；本机官方 sing-box 1.14.2 声明 `with_naive_outbound`，但未部署 Naive 节点或执行外部请求。未以“缺少支持 Naive 的构建”为由跳过测试。 |
| 4. Chain Proxy 2.0 与 Pool 探针 | 未验证 | 因第 1 项闸门停止；未启动 loopback Shadowsocks 上游，未创建 Pool / 两跳 Chain / BLOCK 域名 / DIRECT CIDR / 默认 Chain，也未执行外部路由请求、停上游、菜单“测试 Pool 内全部节点”或断链失败检查。规划中的两个上游位于同一 VPS，出口 IP 无法区分路径，恢复验收后必须以真实上游/路由或故障注入证据确认。 |
| 5. Update Center 与降级拒绝 | 未验证 | 因第 1 项闸门停止；未执行菜单 `6 → 3` 状态检查或较旧 shoes Release 降级拒绝。MERGE_SHA 的 shoes `update` CLI 没有 `--version` 参数，恢复验收后必须使用真实支持的入口，不能伪造指定版本运行。 |
| 6. 备份、修改与恢复 | 未验证 | 因第 1 项闸门停止；未执行 `sudo ping-rust backup <ARCHIVE>`、配置修改、`sudo ping-rust restore <ARCHIVE>` 或配置哈希对比。 |
| 7. 真实重启 | 未验证 | 因第 1 项闸门停止；未执行 `sudo reboot`，也没有 reboot 后 boot ID、enabled/active、监听恢复或 Reality 重连证据。 |
| 8. 卸载清理 | 未验证 | 因第 1 项闸门停止；未执行 `sudo ping-rust uninstall --purge` 或清理验证。保留当前测试实例供定位。 |

### 失败后的只读初步定位

- Windows 到 Reality TCP `32352` 的 socket 连接成功，说明测试时 TCP 可达；不能据此认定 Reality 握手成功。
- Windows 客户端日志确实走 `outbound/vless[reality-default]`，在约 15 秒后返回 `context deadline exceeded`；没有直连出口成功的结论。
- 服务端 `journalctl -u shoes.service --no-pager -n 60` 只取得 systemd 启动、`Starting 1 server(s)..` 和 `Starting REALITY+Vision TCP server at <REDACTED>:32352`，未取得足以定位握手失败阶段的日志。
- 在内存中核对导出数据：outbound 类型为 `vless`、flow 为 `xtls-rprx-vision`；目标地址与 SSH 测试主机一致，端口与 profile 一致，UUID / SNI / Reality public key / short ID 与 profile 均一致。不输出这些值。
- VPS 对所选 Reality fallback 的只读 HTTPS HEAD 检查成功，curl 退出 0，首个 HTTP 状态为 `HTTP/2 103`。
- VPS 的 `NTPSynchronized=yes`；与 Windows 客户端比较的估计时钟差为 VPS 快约 43.7 秒（查询往返约 0.24 秒）。此观察尚未证明故障由时钟导致。
- 未更换 shoes、未改变 pin、节点参数或系统时钟，未执行后续验收。根因未确定；须继续检查 Reality 握手阶段、网络路径和运行环境。

发布闸门：实机第 1 项失败，已停止，等待用户处理。当前未创建 `release/v0.2.1` PR、未推 `v0.2.1` tag、未发布 GitHub Release 或 crates.io；阶段 4 的默认安装 / v0.2.0 升级 / 最终 purge 均为未验证。本记录供失败报告和后续定位，不代表发版验收完成。

### 2026-10-01：用户授权清理 HK 并更换测试 VPS

- HK 清理：通过。用户要求清理旧测试实例后，实际执行 `sudo ping-rust uninstall --purge`、`cargo uninstall ping-rust`，移除本次安装的 `/usr/local/bin/ping-rust` 与私有远端测试目录，并删除残留来源记录和进程锁。确认 `/etc/shoes`、shoes unit、shoes / ping-rust / cargo ping-rust 二进制、`prs` 别名和测试目录均不存在；无 shoes 进程，服务为 inactive/not-found。此清理不改变上述 Reality 失败结论，也不补足重启等未执行项。
- 新 VPS 环境：Debian GNU/Linux 13.4 trixie、x86_64、systemd 257、3 vCPU、1964 MiB RAM、3071 MiB swap；root SSH，`NTPSynchronized=yes`。主机地址、一次性登录密码和 SSH 私钥均不进入仓库记录。
- 初次登录发现新 VPS 已有 `ping-rust 0.2.0`、shoes enabled/active、配置和 unit。用户明确选择“备份后清理并重新验收”，随后实际执行产品 `backup`，并额外备份配置、unit、来源记录和原二进制，备份权限 0600。两份备份已复制到本机仓库之外，分别与远端 SHA-256 比对一致；保留恢复能力。
- 已执行 `sudo ping-rust uninstall --purge` 并清理原管理二进制，确认首次部署基线无配置、unit、shoes / ping-rust 二进制及 shoes 进程；将本机 `prs-test` 指向新测试 VPS。
- 构建前置依赖已安装；最小 Rust 工具链为 `rustc 1.98.1` / `cargo 1.98.1`。实际执行原 MERGE_SHA 的 `cargo install --git https://github.com/Jyanbai/ping-rust.git --rev 74b39c86d1065c1fb483c4c7c2f163976f120f2f --locked`，4m16s 完成，退出 0，`sudo ping-rust --version` 返回 `ping-rust 0.2.0`；临时构建文件使用根磁盘私有目录，避免 tmpfs 限制。
- 新 VPS 实际执行 `sudo ping-rust`，部署阶段零输入，进入管理菜单后才输入 `0` 退出。默认安装 shoes GitHub Release v0.2.7；自动 Reality 部署退出 0，MainPID `2545078`，服务 enabled/active，`ss -ltnp` 确认 TCP `48662`。
- 本机官方 Windows sing-box 1.14.2 读取新导出配置，`check` 退出 0、`run` 正常启动；loopback mixed/SOCKS5 入口配置认证。沿用上表第 1 项脱敏 curl 命令，实际请求再次退出 97：`cannot complete SOCKS5 connection to api.ipify.org. (1)`；客户端 VLESS outbound 约 15.0s 后 `context deadline exceeded`。未取得出口 IP，出口一致性未验证。
- 失败后只读诊断：外部 TCP `48662` 可连接；VPS 到所选 Reality fallback 的 HTTPS HEAD 退出 0，返回 `HTTP/2 302`；地址、端口、UUID、SNI、公钥、short ID 在内存中比对均匹配。服务端仅取得本次 Reality 监听启动日志，未取得握手阶段错误。VPS `NTPSynchronized=yes`，估计比 Windows 快约 43.65 秒（查询 RTT 约 0.14 秒）；因果关系未验证。两次共同客户端/内核版本为 Windows sing-box 1.14.2 / shoes v0.2.7，不能据此认定根因。

| 新 VPS 项目 | 状态 | 命令 / 脱敏结果 / 边界 |
|---|---|---|
| 1. 零输入 Reality 与外部握手/出口 | 失败 | `sudo ping-rust` 部署成功；`sing-box check/run` 成功；带认证本地代理后的外部 curl 退出 97，VLESS outbound 15.0s 超时。出口一致性未验证。 |
| 2. Hot Reload 新增/改端口/删除非最后节点 | 未验证 | 第 1 项闸门后停止，未执行 SOCKS5 节点操作或前后 PID/监听比对。 |
| 3. SS2022 + ShadowTLS v3 / SOCKS5 / Hysteria2 / NaiveProxy | 未验证 | 四种协议均因第 1 项闸门未执行外部连接。未测试 UDP 放行；本机声明支持 Naive outbound，未以客户端缺失为由跳过。 |
| 4. Chain / Pool / BLOCK / DIRECT / 断链禁止直连 | 未验证 | 未启动 loopback 上游或创建拓扑，未执行路由、Pool 探针或故障注入；第 1 项闸门后停止。 |
| 5. Update Center 与降级拒绝 | 未验证 | 未执行状态菜单或降级命令；第 1 项闸门后停止。 |
| 6. 本次配置 backup → 修改 → restore | 未验证 | 新 VPS 原配置的测试前备份与保全成功，不等于本次配置的修改/恢复/哈希验收；第 1 项闸门后停止。 |
| 7. 真实 reboot 与恢复 | 未验证 | 未执行 reboot 或重启后外部握手；第 1 项闸门后停止。 |
| 8. 本次部署 uninstall --purge | 未验证 | 新 VPS 测试前 purge 成功，不等于本次部署后的最终卸载验收；保留当前实例供定位。 |

新 VPS 第 1 项再次触发停止闸门，已停止后续验收和发版，等待用户处理。旧 HK 失败记录保留；没有 release PR、v0.2.1 tag、GitHub Release 或 crates.io 发布，阶段 4 均未验证。

### 2026-10-01：Reality 排查与用户授权的环境修正

本节为后续追加结论，以上首次失败及其未验证项保持原样。仍测试 MERGE_SHA `74b39c86d1065c1fb483c4c7c2f163976f120f2f`；未修改代码、shoes pin、shoes 二进制、节点凭据、unit 或系统时钟。先完成只读排查；用户随后明确选择“按 (a) 修正环境并重测”，授权修正测试路径并恢复原验收顺序。

下表时间均为 **2026-10-01，Asia/Hong_Kong（UTC+08:00），Windows 采集时钟**。VPS/HK/OpenWrt 原生日志另外保留各自主机时间；VPS 比 Windows 快约 43.6 秒，相关日志按实测差值对齐。日志摘要省略公网地址、认证字段和分享链接；命令中的 `<...>` 是脱敏占位符。

| 排查步骤 | 时间 | 实际命令 / 比较方式 | 脱敏输出与状态 |
|---|---|---|---|
| 客户端机器与本机网络 | 12:11:22 | `Get-CimInstance Win32_OperatingSystem`；`Get-NetAdapter`；`Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0'`；读取代理是否启用 | 通过：Windows 11 10.0.22631，本机 Codex 执行环境；Realtek 有线以太网 Up，IPv4 默认路由在该接口；未见活动 VPN 适配器，WinINET 代理未启用。用户确认在中国大陆，上游 OpenWrt 启用 Passwall2；本机无 VPN 不代表路由器无透明代理。 |
| VPS 地址族与 NAT 线索 | 12:14:00 | `ip -j address show`；`ip -j route show table main`；`curl -4 https://api.ipify.org`；私有导出地址/端口比较 | 通过：导出服务器与 SSH 公网目标一致，地址族 IPv4，端口与 profile/监听一致；VPS 网卡实际为私网 IPv4，出口与 VPS 公网 IP 一致。另有 WARP 的 IPv4/IPv6 接口。云端 NAT/端口映射实现细节未验证；后续 HK 和大陆直连证实本端口实际可达。 |
| IPv6 出站 | 12:14:00 | `curl -6 --fail --silent --show-error --connect-timeout 5 --max-time 10 https://api64.ipify.org` | 失败：退出 7，`Could not connect to server`。不能把存在 WARP IPv6 地址写成 IPv6 出站成功。 |
| 服务与配置基线 | 12:14:00 | `systemctl show shoes.service -p MainPID -p ActiveState -p ExecStart`；`sha256sum /etc/shoes/config.yaml /etc/shoes/ping-rust-state.json` | 通过：Debian 13.4、KVM x86_64；active/running，MainPID `2545078`；配置和 state 哈希取得。只读诊断及 Reality 环境修正前后两份哈希一致，直到后续授权新增 SOCKS5。 |
| 同版本 Linux 客户端 | 12:15:29 / 12:19:13 | GitHub API 固定 `v1.14.2` 资产；`Get-FileHash -Algorithm SHA256`；私有目录中的 `sing-box-1.14.2 version` | 通过：官方 Linux amd64 压缩包 SHA-256 与 API digest 一致；客户端 1.14.2，revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`。没有使用 VPS 原有 1.13.11 或 HK 原有 1.15.0-alpha.4 代替版本对照。 |
| 回环配置校验 | 12:19:14 | `sing-box-1.14.2 check -c <PRIVATE_LOOPBACK_CONFIG>` | 通过：退出 0。同一导出 outbound 仅把 server 改为 `127.0.0.1`；增加 loopback 带认证 mixed 入口、明确 route final 和 debug 日志。诊断目录 0700、配置 0600，不改运行中服务。 |
| 回环 Reality 请求 | 12:19:15 | `curl --noproxy '' --socks5-hostname 127.0.0.1:<LOCAL_PORT> --proxy-user <AUTH> --fail --silent --show-error --max-time 25 https://api.ipify.org` | 通过：退出 0，用时 `0.531s`，出口与 VPS 公网 IP 一致；客户端 VLESS outbound 完成上传/下载。回环成功后转网络路径排查。 |
| 同时跟踪服务端日志 | 12:19:14–12:19:16 | `timeout 45 journalctl -u shoes.service -f -n 0 -o short-iso-precise --no-pager`，同时启动 sing-box debug | 通过：实际同步采集；回环成功请求期间无新增 shoes journal 行。未将“没有日志”写成握手失败原因。 |
| 大陆 TCP 与 Reality 重试 | 12:22:12–12:22:28 | `socket.create_connection((<VPS_IPV4>,48662),timeout=8)`；同上带认证 curl；VPS 同时 `timeout 40 tcpdump -ni any -tttt -q -s 128 -l 'tcp port 48662'` | 失败：客户端 TCP connect 返回成功，但 Reality curl 退出 97，用时 `15.047s`，VLESS `context deadline exceeded`。VPS 抓包已启动，期间未出现该端口报文，shoes journal 也无新增行；客户端 TCP connect 不能单独证明 SYN 到达 VPS。 |
| VPS 防火墙 / 云安全组 | 12:22:28 | `ufw status verbose`（存在时）；`nft list ruleset`；`iptables-save`；`ip6tables-save` | 通过：ufw 未安装；INPUT 为 accept，没有对 Reality 端口的 drop，Docker 的 FORWARD/drop 仅针对其容器转发。用户确认云安全组“都开放了”；云控制台独立检查为未验证。 |
| HK 登录身份 | 12:22:10–12:22:11 | `ssh -i <EXISTING_KEY> agent@<HK_ADDRESS>`；`id`；`pwd` | 通过：现有 SSH key 直接登录 agent，uid/gid `1000`，目录 `/home/agent`；后续客户端在自有私有目录执行，未使用 sudo。没有重新安装 HK 上已清理的 ping-rust/shoes。 |
| HK 固定版本与配置 | 12:24:16–12:24:20 | agent 在自有目录下载官方 1.14.2 包、`sha256sum`、解包、`sing-box version`、`sing-box check -c <PRIVATE_CONFIG>` | 通过：下载 SHA-256 与已验证官方 digest 一致；版本 1.14.2，配置 check 退出 0，使用原 VPS 公网地址/端口与原 Reality 凭据。 |
| HK 网络与 Reality | 12:24:21–12:24:24 | HK `socket.create_connection` 与同上带认证 curl；VPS `tcpdump -nni any -tttt -s 128 -l 'tcp port 48662'`；同步 `journalctl -u shoes -f` | 通过：TCP connect `0.059s`；Reality 请求退出 0，用时 `0.656s`，出口与 VPS 公网 IP 一致。抓包含 loopback SYN 正对照、HK SYN/SYN-ACK 和双向有效载荷。仅 TCP connect 后主动关闭的探针产生 `EOF while reading`，不归因于成功的 Reality 请求。 |
| OpenWrt 活动透明代理 | 12:25:16–12:26:31 | 现有 key 登录网关；`pgrep -af 'xray|sing-box|passwall2'`；`nft list ruleset`；内存读取 `/tmp/etc/passwall2/acl/default.json` 的路由/嗅探设置 | 通过：Passwall2 enabled，TCP 默认 redirect 到 Xray `2001`，透明入口启用 `destOverride: [http,tls,quic]`，未设置 `routeOnly`；同时看到 xkeen 规则，但其 `xkeen_active_interfaces` 集合为空，不能将本次截获归因于 xkeen。未公开上游节点凭据。 |
| Passwall2 请求去向日志 | 12:31:24 | `grep -E '<REALITY_PORT>\|<SNI>' /tmp/etc/passwall2/acl/default.log` | 通过：与时间差对齐的原失败和本次失败日志均为 `accepted tcp:<VPS_ADDRESS>:48662 [tcp_redir -> <PASSWALL_UPSTREAM>]`。证实请求进入现有透明代理链；是否由 SNI 覆盖或链上其它环节具体造成丢失仍未验证。 |
| Reality 字段与密钥 | 12:29:39 | 私有读取 config/state/export；`X25519(private_key).public_key()` 内存比较 | 通过：服务端私钥派生公钥与导出一致；UUID、short ID、SNI、dest 一致；服务端 VLESS、vision=true；客户端 flow=`xtls-rprx-vision`、uTLS enabled、fingerprint=`chrome`；无 multiplex，max_time_diff=`60000ms`。 |
| SNI IPv4 TLS | 12:29:39 | `curl -4 --noproxy '' --output /dev/null --connect-timeout 5 --max-time 12 --write-out '<HTTP/TLS_TIMINGS>' https://<SNI>/` | 通过：退出 0，HTTP 302，TCP `0.003099s`、TLS `0.049682s`、总计 `0.052983s`，ssl_verify=0。目标站 IPv4 TLS 不存在 15 秒挂起。 |
| SNI IPv6 TLS | 12:29:39 | 同上 `curl -6` | 失败：退出 6，`Could not resolve host`，没有建立 IPv6 TLS。不得写成 TLS 成功或归因于本次 IPv4 Reality 失败。 |
| VPS 与 Windows 时钟 | 12:22:12 / 12:29:40 / 12:34:41 / 12:37:17 | `date -u +%s.%N` 往返中点比较；`timedatectl status`；`timedatectl timesync-status`；`w32tm /query /status` | 实测差值：VPS 比 Windows 快 `43.598s`，修正后仍快 `43.577s`；VPS synchronized=yes、NTP active，timesync-status 的 timesync1 DBus 服务不可用；Windows Time 服务未启动，错误 `0x80070426`。未校时；原时差未变且修正后成功，不能认定它是本次根因。 |
| v0.1.x 生成/导出逻辑比较 | 12:18:28 / 12:37:17 | `git log -p v0.1.20..74b39c8 -- src/config/presets/reality.rs src/client.rs`；`git show v0.1.3:src/config.rs`；`git log -p -G 'max_time_diff\|generate_reality_keypair' v0.1.3..74b39c8 -- src/config.rs` | 通过（源码检查）：v0.1.20 至 MERGE_SHA 的 Reality preset 无改动；client.rs 的 H2MUX 提交 `1549692` 不启用 Reality/Vision 的 mux，实际导出无 multiplex。历史 v0.1.3 同样采用 X25519、base64url、VLESS Vision、short_ids、60 秒容差；SNI 默认与模块组织曾变化。未重跑历史版本，也未借用历史成功记录冒充本次验收。 |
| 用户授权的环境修正 | 12:34:37–12:34:38 | `nft get element inet passwall2 psw2_direct '{ <VPS_IPV4> }'`；`nft add element inet passwall2 psw2_direct '{ <VPS_IPV4> }'`；再次 get | 通过：原目标不在 direct 集合，新增唯一测试目标后查询成功。只改运行时 set，未修改 UCI、持久防火墙、全局嗅探设置或其它目标；未重启 Passwall2。此例外仍存在，重建防火墙/Passwall2 规则后可能丢失。 |
| 修正后大陆 Reality | 12:34:42–12:34:45 | 原 Windows sing-box 1.14.2、同一 outbound 配置、同一带认证 curl；同步 VPS tcpdump/journal | **通过（后续重测）**：curl 退出 0，用时 `2.609s`，出口与 VPS 公网 IP 一致；VPS NIC 上出现对应连接及双向数据。shoes MainPID 仍为 `2545078`，config/state 哈希保持不变。原失败记录不改写。 |

**Reality 根因分类：(a) 测试环境问题。** 已确认大陆 OpenWrt/Passwall2 的透明代理路径使该外部请求未到达目标 shoes 监听；同配置回环、HK 和仅增加测试目标直连例外后的大陆请求均成功。此证据不支持将本次 Reality 失败归为 ping-rust 缺陷或 shoes/sing-box 兼容失败。透明代理链中具体导致丢失的内部机制尚未验证；嗅探目标覆盖仅为线索。改进评估另见 [Reality 零输入部署预检提案](docs/REALITY_PREFLIGHT_PROPOSAL.md)，只写提案，未实现。

### 环境修正后恢复验收：Hot Reload 第 2 项失败

用户授权修正环境后恢复原验收；12:36:02 实际执行：

```sh
sudo ping-rust add socks5 --name acceptance-hot-reload --port 38231 --yes
```

- 命令退出 0，输出“部署成功，shoes 服务已启动”；生成的 SOCKS5 用户名和密码均非空，不启用无认证模式。
- 新增前 MainPID `2545078`；新增后 MainPID **`2546772`**；`ss -ltnp` 显示 Reality TCP `48662` 与新 SOCKS5 TCP `38231`，服务 active。
- VPS 原生 journal 时间 `12:36:47.733248+08:00` 为 `Stopping shoes.service`，`12:36:47.744175+08:00` 为 `Started shoes.service`，确认是 systemd 重启；不是仅凭 PID 猜测。
- 初步定位：安装来源实际是 `github-release` / shoes `v0.2.7`。`src/service.rs::capture_hot_reload_snapshot` 仅对 `verified-pin` 且 revision 等于现有 pin 的实例返回快照；该 Release 返回 None，`src/deployment.rs::plan_apply` 选择 Activate，随后 `activate_and_verify` 重启服务。源码与实际路径吻合；未换用 pin 构建掩盖默认安装路径的验收失败。

| 恢复后的验收项 | 最新结果 | 边界 |
|---|---|---|
| 1. 首次零输入部署 + Reality 外部请求 | 通过（后续重测） | 首次部署证据沿用前次实际执行；网络修正后原配置外部请求通过，初次失败继续保留。没有 purge/redeploy 或重新生成节点。 |
| 2a. 新增认证 SOCKS5，MainPID 不变 | **失败** | 新监听出现、认证存在，但 MainPID 改变；触发第 2 项停止闸门。 |
| 2b. 修改端口 | 未验证 | 新增子项失败后停止，未修改。 |
| 2c. 删除非最后节点 | 未验证 | 新增子项失败后停止，未删除；保留 Reality 和新增认证 SOCKS5 供定位。 |
| 3. 四种协议外部抽查 | 未验证 | 第 2 项闸门；创建 SOCKS5 不替代其外部请求验收。 |
| 4. Chain / Pool / 路由 / 断链 | 未验证 | 第 2 项闸门。 |
| 5. Update Center | 未验证 | 第 2 项闸门。 |
| 6. backup → 修改 → restore | 未验证 | 第 2 项闸门。 |
| 7. reboot 后恢复与 Reality | 未验证 | 第 2 项闸门。 |
| 8. 本次部署最终 purge | 未验证 | 第 2 项闸门；实例保留。 |

当前停止原因已从 Reality 第 1 项转为 **Hot Reload 第 2 项**。未继续验收、未修改代码、未创建修复或 release PR，未推 tag，未发布 GitHub Release/crates.io；阶段 4 全部未验证。等待用户处理这个新的失败闸门。

## Goal 4：H2MUX

| 项目 | 状态 | 证据 |
|---|---|---|
| VMess WS TLS / VLESS non-Vision WS TLS / Trojan TLS H2MUX | SUPPORTED | 固定 shoes pin 的本地 TCP 数据面测试：小 payload、1 MiB half-close、每协议 12 并发流；VMess H2MUX 同时通过双 hop Chain。 |
| VLESS Vision rejection | SUPPORTED | profile、Chain node、state load 和 export 验证拒绝冲突配置。 |
| Trojan Reality H2MUX | NOT_ENABLED | 尚无匹配产品传输的本地数据面验证。 |
| Shadowsocks / SS2022 + ShadowTLS / Snell v3 / 其它协议 H2MUX | NOT_IMPLEMENTED | 管理 UI 与状态校验不允许开启。 |
| server auto-detection | SUPPORTED | 固定 shoes 源码与本地测试；服务端 YAML 无 H2MUX 字段。 |
| sing-box export | SUPPORTED | `multiplex` JSON 单测；sing-box 1.14.2 `check` 验证三种导出。 |
| sing-box data E2E | SUPPORTED | sing-box 1.14.2 Trojan H2MUX 客户端连接固定 shoes 服务端，small/1 MiB half-close 本地流量通过。 |
| Mihomo H2MUX / NekoBox H2MUX | NOT_ENABLED | Mihomo 启用偏好时明确拒绝导出；NekoBox 普通分享链接不承载偏好。 |
| URI / QR H2MUX | NOT_IMPLEMENTED | 普通 URI/QR 不发明 mux 参数，UI 与 CLI 明确提示。 |
| profile preference service action / MainPID | SUPPORTED | 聚合 YAML 字节相同会选择既有 `NoServiceAction`；Ubuntu acceptance 验证配置 YAML 与 MainPID 均保持不变。 |
| Chain node H2MUX / multi-hop | SUPPORTED | 节点独立 H2MUX 配置；固定 shoes 本地 H2MUX + SOCKS 第二 hop 流量通过。 |
| padding / concurrent streams / half-close | SUPPORTED | Trojan padding=true、自定义 2/2；VMess/VLESS 默认 4/4；各协议 12 并发流及小/1 MiB half-close 通过。 |

H2MUX UDP 仍为 NOT_IMPLEMENTED。生产 shoes pin、依赖与 ping-rust 版本号保持不变；本 Goal 不发布。

## Goal 3：Chain Proxy 2.0 + Rule-based Routing

| 项目 | 状态 | 证据 |
|---|---|---|
| v1 state migration / disabled selection | LOCAL PASS | `load_state_from` 内存迁移为单跳默认 Chain；读取不改盘；禁用状态与出口在保存、重载后保留。 |
| Nodes / Pools / multi-hop Chains / whole-chain RR | LOCAL PASS | state 引用校验与有序渲染单测；固定 shoes 本地流量测试实际通过多跳、hop Pool 和多 Chain 轮询。 |
| CIDR / hostname / DIRECT / BLOCK / default | LOCAL PASS | 固定 shoes schema dry-run 与 `chain_v2_e2e` 的本地流量路径验证；IPv6 CIDR 已通过 schema dry-run。 |
| reference integrity / deletion / rule order / limits | LOCAL PASS | 状态单测覆盖缺失引用、重复、空对象、超限、删除保护及规则顺序 JSON 往返。 |
| UDP capability propagation | LOCAL PASS | 对 Chain、Pool 与 whole-chain RR 的所有可选 hop 作保守计算；单测覆盖混合能力。 |
| v1/v2 backup restore staging | LOCAL PASS | `prepare_managed_snapshot` 和 `validate_managed_snapshot` 接受 v1 与 v2 路由状态；v2 规则顺序保持。 |
| transaction rollback / Hot Reload boundary | LOCAL PASS | Chain 更新继续走现有 lock、候选校验、原子提交、service activate 与 rollback；profile Hot Reload 规划单测保持原边界。 |
| Ubuntu/Debian systemd acceptance | PASS | main acceptance 已通过真实 Ubuntu/Debian systemd 服务路径验证。 |
| feature CI / main CI / upstream drift | PASS | feature、main required checks 与手动 shoes-upstream-drift 均已通过。 |

Pool 与多 Chain 轮询均不是健康感知故障切换。生产 shoes revision 与 ping-rust 版本号保持不变；本 Goal 不发布。

## Goal 1：统一更新中心与 shoes upstream drift

| 项目 | 证据 |
|---|---|
| Update Center | 主菜单 `6` 提供 ping-rust 自更新、已验证 shoes pin、GitHub Release 高级安装和状态检查。 |
| self-update 旧进程退出 | 自更新 handler 返回明确的 Updated 信号；成功原子替换后交互菜单退出。 |
| shoes verified pin | `InstallMethod::Cargo` 使用固定 `SHOES_SCHEMA_REVISION` 与 `--locked`，并作为推荐项。 |
| Release 降级保护 | 已知较低 Release 默认拒绝，只有 `--allow-downgrade` 才允许；legacy unknown CLI 安装 fail-closed，高级菜单要求确认。 |
| provenance/status | `/var/lib/ping-rust/shoes-install.json` 原子记录来源、版本、revision/tag 与 binary digest；缺失、损坏或 digest 不匹配按 unknown 处理。 |
| upstream drift 检测 | `.github/workflows/shoes-upstream-drift.yml` 每周和手动运行，解析生产 pin 与 `cfal/shoes` master HEAD，绝不修改 pin。 |
| upstream 兼容验证 | drift 构建精确 upstream HEAD，执行共享 schema/协议矩阵与 chain proxy E2E，并写入 PASS/FAIL summary。 |
| upstream watcher 验收边界 | drift 的原子替换 watcher 测试使用 upstream shoes，但不覆盖 ping-rust 的 systemd 热重载流程；升级 pin 时必须按 `docs/SHOES_PIN_UPGRADE.md` 手动验证新增监听、MainPID 连续和监听切换。 |
| pin 一致性 | fixed schema CI 在构建前比较 runtime `SHOES_SCHEMA_REVISION` 与 workflow pin。 |

## Goal 2：shoes 原生 Hot Reload

| 项目 | 状态 | 证据 |
|---|---|---|
| atomic-write watcher compatibility | SUPPORTED | 固定 pin `386b115...` 的 shoes schema workflow 使用真实 `atomic_write` 加文件锚点，连续两次替换均完成 listener 切换；run [35965397288](https://github.com/Jyanbai/ping-rust/actions/runs/35965397288)。 |
| active add / edit-port / delete non-last | HOT_RELOAD | `service::hot_reload_and_verify` 要求服务 active、MainPID 不变，并检查 listener 集合；Ubuntu acceptance run [35981570098](https://github.com/Jyanbai/ping-rust/actions/runs/35981570098) 通过三种操作的 PID 连续性断言。 |
| runtime unchanged | NO_SERVICE_ACTION | 聚合 YAML 字节相同的 metadata edit 跳过 config 替换和服务动作。 |
| credential-only edit | FALLBACK_RESTART | 固定 shoes 没有稳定 reload acknowledgement；端口不可观测的凭据修改继续走可靠 restart。 |
| inactive / bootstrap | START | 没有 active MainPID 时保留现有 activation 语义。 |
| delete last | STOP | 最后一个 profile 仍停止 shoes。 |
| reload failure / crash | FALLBACK_RESTART | 超时、服务失活或 MainPID 改变使候选失败；Ubuntu acceptance run [35981570098](https://github.com/Jyanbai/ping-rust/actions/runs/35981570098) 用暂停 shoes 触发真实超时，验证 config/state/profiles/unit 哈希恢复、旧 listener 恢复和锚点重新绑定到恢复后的 PID。 |
| cert cleanup | SUPPORTED | 既有 `finish_update` / deletion finish 仍在 activation 成功后清理旧凭据。 |
| backup restore / chain / shoes update | NOT_ENABLED | 本 Goal 保留这些路径的既有 restart/activation 语义。 |

## Shadowsocks 2022 + ShadowTLS v3（v0.1.19 feature）

| 项目 | 状态 | 证据 |
|---|---|---|
| server config | SUPPORTED | 固定 shoes `386b11532424b8665ee3e46340c6236fb3c47595` 的 `tls.shadowtls_targets` 外层与内层 Shadowsocks 2022 |
| state lifecycle | SUPPORTED | 可选 `shadowtls` 凭据向后兼容；查看、删除、备份、恢复、聚合配置、回滚与健康检查复用既有受管生命周期 |
| edit | SUPPORTED | 名称、端口、公网地址、SS2022 cipher/key、ShadowTLS password、SNI、handshake |
| sing-box export | SUPPORTED | Shadowsocks outbound `detour` 到 ShadowTLS v3 outbound；JSON 结构测试覆盖 |
| Mihomo export | SUPPORTED | 官方 Shadowsocks `plugin: shadow-tls` + `plugin-opts` 结构；YAML 结构测试覆盖 |
| NekoBox | UNSUPPORTED | 未确认稳定专用导入 URI；不制造自定义格式 |
| URI | UNSUPPORTED | 标准 `ss://` 不能完整表达 ShadowTLS v3 参数 |
| QR | UNSUPPORTED | 没有标准 URI，因此不生成普通分享二维码 |
| UDP | NOT_IMPLEMENTED | shoes 内层支持 UoT，但 sing-box ShadowTLS outbound 为 TCP-only，首版不暴露 UDP |
| chain | NOT_IMPLEMENTED | 不扩展当前分享链接驱动的 chain 模型 |
| schema dry-run | SUPPORTED | workflow 覆盖默认配置、AES-128 2022 与自定义 handshake |
| TCP E2E | SUPPORTED | 固定 shoes 同时提供嵌套 ShadowTLS client/server，workflow 启动聚合 listener 并覆盖 TCP 路径 |
| acceptance | SUPPORTED | Ubuntu workflow 覆盖菜单 3 → ShadowTLS 模式、CLI `--shadowtls`、受管 YAML、active listener 和 info |

Plain Shadowsocks 命令、旧 state、SIP002 URI/QR 与现有导出保持原行为；顶层协议编号仍为 3，SOCKS5=11、Snell v3=12。

审计日期：2026-07-18

本文件把原始目标逐项映射到实现、自动化证据和外部验收边界。`已实现` 表示代码路径和自动化证据完整；Debian 12 与成功标准指定的 Ubuntu 24.04 均已完成独立实机验收。

## NaiveProxy 受管支持（v0.1.19 feature）

| 项目 | 状态 | 证据/边界 |
|---|---|---|
| server preset | SUPPORTED | 固定 shoes revision 的 TLS target、ALPN `h2` 与 `naiveproxy` inner protocol |
| TLS certificate lifecycle | SUPPORTED | 复用现有外部 cert/key、自签名 ownership、删除与回滚清理 |
| random auth | SUPPORTED | 随机 URL-safe username 与 password；显式凭据可保留 |
| padding | SUPPORTED | 默认开启，可在高级编辑中关闭 |
| fallback | SUPPORTED | 可选绝对静态目录路径；默认不配置 |
| UDP/UoT | NOT_IMPLEMENTED | server 字段存在，但尚无 sing-box/shoes UDP E2E 证据，产品不暴露启用路径 |
| sing-box | SUPPORTED | `type: naive`、Basic Auth、TLS server_name；自签名导出嵌入公钥证书且不导出私钥 |
| Mihomo | UNSUPPORTED | 当前未发现已合入的 NaiveProxy schema，不生成 generic HTTPS 冒充 |
| NekoBox | UNSUPPORTED | 未验证稳定 native Naive 导入路径 |
| standard URI | UNSUPPORTED | 不伪造 `naive+https` 或 `https://` 分享格式 |
| QR | UNSUPPORTED | 无稳定标准 URI |
| chain outbound | NOT_IMPLEMENTED | 当前 chain abstraction 不扩展 NaiveProxy |
| schema dry-run | SUPPORTED | 固定 shoes workflow 覆盖默认、自签、外部证书、padding、fallback 与 UDP 字段 schema；feature run `35862536331` PASS |
| TCP E2E | SUPPORTED | 固定 shoes workflow 验证 TLS h2 → NaiveProxy client/server → HTTP/TCP 目标；feature run `35862536331` PASS |
| UDP E2E | NOT_IMPLEMENTED | 明确不声称支持 |
| Ubuntu acceptance | SUPPORTED | 菜单 13 与 CLI、自签名测试 fixture、受管 YAML、active listener；feature run `35862631763` PASS |

## 需求映射

| 原始需求 | 状态 | 实现位置 | 当前证据 |
|---|---|---|---|
| Rust 2021、Rust 代码占绝对主导 | 已实现 | `Cargo.toml`、`src/` | 7,037 行 Rust / 241 行安装 shell，Rust 占 96.69%；代理、配置、服务、运维、自更新与快速部署事务核心均为 Rust |
| clap v4 子命令与数字菜单 | 已实现 | `src/cli.rs`、`src/menu.rs` | `prs` 主菜单固定 1..10，协议编号固定为连续的 1/2/3/4/5；采用 233boy 风格 `1)` 列表与 `请选择 [0-N]` 提示，主菜单 0 退出、所有子菜单 0 返回 |
| 快速添加与直接分享 | 已实现，Ubuntu 24.04 实测 | `src/fast_add.rs`、`src/deployment.rs`、`src/client.rs` | `add/a`、协议短别名、20000..=65535 高位随机端口/凭据、公网地址探测、`--yes/--plain`；真实 PTY 的 Reality/SS 添加、URI 与监听均通过 |
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
- 本地单测覆盖单 mapping 形状、确定性聚合、迁移幂等、改端口重命名、陌生文件保护、状态写失败目录回滚及延迟凭据清理；当前 66/66 tests、fmt/check、Clippy、release、rustdoc、RustSec、actionlint 与严格 clean-worktree crate dry-run 全部通过。
- 最终产品 HEAD `975799a` 的 CI `29647842963`、Ubuntu 24.04 acceptance `29647842938`、固定 shoes schema `29647842940` 全部成功。Ubuntu 真实覆盖五协议文件、旧版目录迁移、PTY 改名/查看/实际删除、目录故障回滚哈希、备份恢复和 systemd 运维；schema 完成全部协议 dry-run 矩阵。
- 严格验收还修复两项边界：root `0600` 备份必须以 root 读取；默认随机端口实现从原 445 下限收紧为文档承诺的 `20000..=65535` 高位范围。两项均保留安全约束，没有放宽测试掩盖。

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

## Milestone 7 Debian 12 VPS 证据（ping-rust v0.1.x；shoes v0.2.7）

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

## Milestone 9 Ubuntu 24.04 VPS 证据（ping-rust v0.1.x；shoes v0.2.7）

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
- `cargo package --locked` / `cargo publish --dry-run --locked`：提交后 strict clean-worktree 候选打包 32 个文件、379.8 KiB（压缩 90.2 KiB），隔离解包重编译与上传前校验通过
- `cargo-audit 0.22.2`：扫描当前 Cargo.lock 的 224 个依赖，RustSec 1166 条 advisory 中无命中
- `SOURCE_SNAPSHOT.md`：14/14 section、282,322 bytes，Cargo/主要 Rust（含 deployment/fast_add）/README 全部与真实文件逐字一致
- actionlint v1.7.12：`ci.yml`、`release.yml`、`shoes-schema.yml`、`ubuntu-acceptance.yml` 零诊断；ShellCheck v0.11.0 对一键安装器零诊断
- v0.1.8 产品提交 `960edde`：main CI `29645174662`、Ubuntu 24.04 acceptance `29645174670`、固定 shoes schema `29645174650` 全部成功；tag CI `29645387085` 与 schema `29645387104` 再次成功
- v0.1.8 Release run `29645387081`：双架构 MUSL、SHA256SUMS、公开一键安装默认 Reality 全部成功；crates.io 公开隔离安装返回 `ping-rust 0.1.8`
- v0.1.9 简洁菜单：CI `29646275985` 与 Ubuntu 24.04 acceptance `29646275983` 成功；真实 PTY 覆盖查看短名称/URI、删除菜单 0 返回且不误删
- v0.1.9 真实 profile 候选：最终产品 HEAD `975799a` 的 CI `29647842963`、Ubuntu 24.04 acceptance `29647842938`、shoes schema `29647842940` 全部成功；Ubuntu 覆盖真实文件、旧目录迁移、PTY 实际删除、事务回滚和备份恢复
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

历史公开稳定版 v0.1.19 已发布；当前源码对应 v0.2.0。v0.1.19 保持原 1–10 菜单编号不变，第 11 项 SOCKS5 为新建配置默认生成
安全随机用户名、随机密码和 UDP ASSOCIATE，只有高级/CLI 明确选择时才允许 no-auth，并显示公网滥用警告。
第 12 项为 Snell v3，默认 chacha20-ietf-poly1305、
随机密码和 UDP-over-TCP，支持 shoes 固定的三个 v3 cipher；Snell 配置继续使用统一的候选 dry-run、
原子提交、profile/state、服务激活、健康检查和回滚路径，支持查看、编辑、删除、备份恢复与 managed
filename。Mihomo/Clash Meta 仅对 AES-128-GCM 提供无损 v3 导出；sing-box v3、NekoBox、标准 URI、QR
和 Snell chain outbound 明确 NOT_SUPPORTED/NOT_IMPLEMENTED，不生成伪格式。固定 shoes workflow 覆盖
Snell 三种 cipher、UDP true/false、聚合 dry-run 和 Ubuntu 第 12 项菜单验收；SOCKS5 第 11 项及随机用户名
行为保持不变。

## v0.2.1 来源兼容矩阵（隔离 CI）

- 日期：2026-10-01；Ubuntu 24.04 GitHub hosted runner；未更改 prs-test。
- 测试提交：`c39c920`；[schema run 36819363691](https://github.com/Jyanbai/ping-rust/actions/runs/36819363691) 的两个 source-matrix job **通过**。原 dry-run job 因先提交的回归测试尚未实现而失败，整体 run 为失败；不把整体 run 写为成功。
- 默认 Release 实际 tag：`v0.2.7`，从官方 latest API 读取；musl 资产 SHA-256 校验通过。此二进制不支持 `--version`，以已校验的官方资产识别。
- verified-pin：`386b11532424b8665ee3e46340c6236fb3c47595`；构建时断言 runtime pin 一致，实际版本 shoes 0.2.8。
- 官方 sing-box 1.14.2 压缩包 SHA-256 校验通过；SOCKS 入口和上游均使用运行时生成的认证凭据。
- 命令：`cargo build --locked`；`python3 scripts/ci/shoes-source-matrix.py --source <SOURCE> --output <TEMP>`；`ping-rust generate <PROTOCOL> --output <TEMP>`；`shoes --dry-run <TEMP>`。

| 功能 | Release v0.2.7 路径 | verified-pin 路径 | 范围 / 输出摘要 |
|---|---|---|---|
| VLESS Reality Vision | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Hysteria2 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| TUIC v5 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Shadowsocks 2022 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| AnyTLS TLS | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| VLESS TLS Vision | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| VLESS WS TLS | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Trojan TLS | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Trojan Reality | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| VMess WS TLS | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Snell v3 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| 认证 SOCKS5 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| NaiveProxy 自签名 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| SS2022 + ShadowTLS v3 | 可用 | 可用 | 生成与 dry-run exit=0；不代表外部连接通过 |
| Chain 2.0 | 可用 | 可用 | 认证双 SS hop、Pool、BLOCK、DIRECT、默认 Chain 数据通过；停上游后 DIRECT 仍通过，默认 Chain 失败，无直连回退 |
| H2MUX | 可用 | 可用 | VMess/VLESS WS TLS、Trojan TLS 小 payload / 1 MiB half-close / 12 并发流；VMess 双 hop；sing-box Trojan 数据通过 |

H2MUX 在 Release v0.2.7 **可用**，不新增来源拦截。热重载 gating 保持固定 pin 限制。矩阵夹具此前两次失败保留：run `36818878517` 对不支持的 `shoes --version` 用法失败；run `36819105934` 的 Chain `localhost` 路径失败，未作为产品失败结论。改用明确的 IPv4 回环目标后，第三次矩阵的数据测试通过。

### 修复测试顺序

`484ce81` 先添加五类前置原因和 Release 回退提示测试；本地 `cargo test --locked hot_reload_reason` 在未实现符号处失败（exit=1）。实现后 `cargo test --locked hot_reload` 7/7 通过；`cargo test --locked --all-targets` 的 167 个单元测试通过。本地 Linux/systemd 数据测试未执行，跳过不作为实机证据。`cargo clippy --locked --all-targets --all-features -- -D warnings` 通过。FIX_SHA 和实机 R/P 验收尚未完成；未合并、未推 tag、未发布。

## v0.2.1 实机验收（VPS 对 VPS，R2 闸门停止）

本节追加新验收，不改写前述 Reality/Hot Reload 失败记录。测试 VPS 为非一次性机器，最终恢复仍待后续授权流程；原始配置备份保留。

### 目标与前置证据

- 日期：2026-10-01（Asia/Hong_Kong）；服务端实际 `/etc/debian_version` 为 **13.4**。客户端 HK 以 agent 身份运行（UID 1000），无 sudo；所有服务端 SSH 连接均经 ProxyJump HK。Windows 未运行代理客户端，未继续修改 OpenWrt。
- MERGE_SHA：`74b39c86d1065c1fb483c4c7c2f163976f120f2f`。
- 修复 [PR #19](https://github.com/Jyanbai/ping-rust/pull/19)，本次安装请求的 FIX_SHA：`bc56d62dcafc64a953be0ab91a0b1d8374539900`。13:37 本机采集的 GitHub head check rollup 为 23/23 completed/success。
- 成功 CI：PR CI [36820112370](https://github.com/Jyanbai/ping-rust/actions/runs/36820112370)，schema [36820112711](https://github.com/Jyanbai/ping-rust/actions/runs/36820112711)，来源矩阵 / 默认 Release acceptance [36820112476](https://github.com/Jyanbai/ping-rust/actions/runs/36820112476)；push CI [36820072298](https://github.com/Jyanbai/ping-rust/actions/runs/36820072298)，schema [36820072607](https://github.com/Jyanbai/ping-rust/actions/runs/36820072607)，性能基线 [36820072288](https://github.com/Jyanbai/ping-rust/actions/runs/36820072288) 重跑后通过。性能基线首次 Debian cold_install 失败，日志未公开具体 stderr，初次原因未定位；不抹去初次失败。
- 默认 Release systemd acceptance 实际覆盖零输入部署、认证 SOCKS 新增/改端口/非最后删除的受控重启与原因提示，以及菜单 H2MUX preference / sing-box 导出 / small 与 1 MiB half-close 数据；均通过。CI 证据不替代实机结果。
- Wiki 实际已更新提交 `7df6130`：Home、Installation、Operations、Protocols、Troubleshooting；明确固定 pin、默认 Release 重启、切换方式及源码编译时间/内存代价。
- 客户端 sing-box 1.14.2 官方资产与二进制 SHA-256 已核对；实际 `version` 输出含 with_quic / with_utls / with_naive_outbound。支持标志不代表协议实机通过。

### 阶段 0 / 安装记录

| 项目 | 时间（本机 HKT） | 状态 | 关键命令 / 脱敏输出摘要 |
|---|---|---|---|
| 撤销临时 OpenWrt 直连例外 | 13:04:06–13:04:07 | 通过 | 仅删除测试 VPS 的运行时集合成员；`nft get element inet passwall2 psw2_direct '{ <VPS_IPV4> }'` 随后非零，成员不存在；其它规则未修改。 |
| Windows 测试客户端和私有配置清理 | 13:04:08 | 通过 | 运行中测试客户端 0；删除 10 个含凭据的本地测试文件；原始备份目录保留。 |
| SSH ProxyJump / HK agent | 13:33:32 | 通过 | `ssh prs-test` 使用 ProxyJump HK；HK `id -u` 为 1000；sing-box version 为 1.14.2；curl / python3 可用。 |
| 服务基线 | 13:30:14 | 通过 | `systemctl show shoes.service -p MainPID -p ActiveState`：2546772 / active；来源 github-release v0.2.7。TCP 48662、38231。系统空间 746 MiB、RAM 1964 MiB、swap 3071 MiB；未清理其它软件。 |
| FIX_SHA 安装命令 | 13:38:08–13:40:33 | 通过（命令退出）；产物对应关系未验证 | `cargo install --git https://github.com/Jyanbai/ping-rust.git --rev <FIX_SHA> --locked` exit=0；`install-self --install-dir /usr/local/bin --quiet --no-bootstrap` exit=0。复用此前测试 build-dir，CARGO_BUILD_JOBS=1；构建仅 2.35 秒。安装后 MainPID、config/state 哈希与基线相同。后续只读检查发现产物缺少修复提示，不能把 exit=0 当作已验证 FIX_SHA 产物。 |

### R / P 实机结果

| 项目 | 时间（本机 HKT） | 状态 | 命令 / 脱敏输出与范围 |
|---|---|---|---|
| R1：HK Reality 请求 | 13:41:20–13:41:25 | 通过（请求）；FIX_SHA 产物对应关系未验证 | 服务端 `ping-rust export sing-box --profile <NODE_ID> --server <VPS>`；HK sing-box check exit=0，认证 loopback SOCKS + `curl --config <PRIVATE_CONFIG>` exit=0，请求约 1.8 秒；出口 IP 与 VPS 公网 IP 一致。未打印出口地址。 |
| R2：新增认证 SOCKS5 | 13:41:25–13:41:30 | **失败** | `sudo ping-rust add socks5 --name r2-auth-socks --port 55081 --yes` exit=0；认证字段非空。PID 2546772 → 2548522，TCP 55081 出现，48662 / 38231 保留，服务 active。受控重启行为正确，但 stdout/stderr 均没有 GitHub Release 来源 / 固定 pin / 受控重启 / 切换方法提示，违反 R2 要求。 |
| R2：改端口 / 删除非最后节点 | — | 未验证 | 新增步骤失败后按闸门停止；未执行。 |
| R3：Release H2MUX | — | 未验证 | R2 闸门后未执行；隔离 CI 数据通过，不借用为实机结果。 |
| 切换 verified-pin / 编译耗时与内存峰值 | — | 未验证 | 未执行 `update --method cargo`。pin 保持原值。 |
| P1：热重载新增/改端口/删除 | — | 未验证 | R2 闸门后未执行。 |
| P2：SS2022+ShadowTLS、认证 SOCKS、Hysteria2 UDP、H2MUX、NaiveProxy | — | 未验证 | R2 闸门后未执行；不能以客户端构建标志替代数据面验收。 |
| P3：Pool / 双 hop Chain / BLOCK / DIRECT / 默认 Chain / 故障探针 / 断链失败 | — | 未验证 | 实机未执行；来源矩阵为隔离 CI 证据。计划两个上游同 VPS，出口 IP 本身不能区分是否经 Chain。 |
| P4：Update Center 状态与拒绝降级 | — | 未验证 | R2 闸门后未执行。 |
| P5：backup / 修改 / restore / 哈希一致 | — | 未验证 | R2 闸门后未执行；原始备份保留。 |
| P6：真实重启与 Reality 再握手 | — | 未验证 | 未执行 reboot。 |
| 合并、v0.2.1 tag / Release / crates.io、发版后冒烟与最终恢复 | — | 未验证 | 修复 PR 未合并；未创建 release PR；未推 tag / 发布；停止等待用户处理。 |

### R2 初步定位（只读，未修正环境 / 未重测）

13:42:40–13:44:00 采集：

1. `sudo sh -c 'command -v ping-rust; readlink -f ...; sha256sum ...'` 实际使用 `/usr/local/bin/ping-rust`；它与 `/root/.cargo/bin/ping-rust` 哈希相同：`a3131804c611815126dcfff4c1623c632598ca34a346c4fd777d0545d8267726`。排除 sudo 选择了另一路径的二进制这一解释。
2. `/root/.cargo/.crates2.json` 声称安装 revision 为 FIX_SHA；Git checkout HEAD 也确认为 FIX_SHA，`src/service.rs` 包含两条修复提示字符串。
3. Python 按 UTF-8 字节检查实际两份二进制：`has_restart_notice=false`、`has_release_reason=false`。说明安装元数据与实际提示内容不吻合；**FIX_SHA 二进制来源尚未验证**。
4. 安装日志没有 Compiling 阶段，`Finished release ... in 2.35s`；设置的 `CARGO_BUILD_BUILD_DIR` 复用了 MERGE_SHA 验收时的目录。初步怀疑旧构建产物复用；尚未隔离 build-dir 重建，未确认为 Cargo 缺陷或 ping-rust 缺陷。
5. 来源仍是 github-release v0.2.7，unit 路径正确、DropInPaths 为空，服务 active。追加节点保持原状，未继续删除、修改、切换内核或重启机器。
6. 实际 config SHA-256：`56882c35a952aefca474f19f1c8f2c19a81cf96a9b2ef5e1f8805098c9aa60d8`；state SHA-256：`9b4dfb8eac131d1cfd0e261d81394cb69a9ca41ebd2403de1d3c268805277871`。

本轮 R2 **失败保留**。下一步候选为使用全新的隔离 build-dir 重建同一 FIX_SHA，核对实际修复符号后从 R1 重验；此步骤尚未执行，等待用户决定。


### 闸门后审计与 CI 状态追加

审计提交 `aeb0b34` 推送后触发新 head 检查。来源 workflow run `36821437871` 的 Default Release systemd acceptance job `110237660177` 在 **2026-10-01 05:47:38 UTC** 于 `ping-rust bootstrap` 失败；日志仅显示命令退出导致断言失败，私有 stdout/stderr 未公开，原因**未定位**。这不改写 FIX_SHA 当时的 23/23 绿检查，也不能把历史绿检查视为新 head 全绿。已在 PR #19 追加报告，未重跑或修正。

13:48:01 HKT 从 HK agent 只读确认：`find /home/agent/prs-v021-acceptance -maxdepth 1 -type f` 无输出，`pgrep -u agent -x sing-box` 无匹配；本轮临时客户端凭据和进程已清理。原始本机配置 / full 备份仍存在。按用户 R2 失败闸门停止，非一次性服务端保持当前测试状态，最终 purge / 原始环境恢复尚未执行。
