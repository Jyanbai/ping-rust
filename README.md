# ping-rust

`ping-rust` 是一个纯 Rust 编写的 [cfal/shoes](https://github.com/cfal/shoes) 安装与管理工具。它提供类似 233boy 脚本的数字菜单，在 Linux VPS 上完成 shoes 安装、十种经过约束的成品协议配置、systemd 管理和日常运维。

核心逻辑全部位于 Rust 源码中；`scripts/install.sh` 负责下载、校验并安装官方预编译二进制，随后调用 Rust 的安全首次部署入口。

> 当前已发布稳定版为 `v0.1.14`；本仓库源码为 `v0.1.15` 发布候选。两者均支持 VLESS-Reality-Vision、Hysteria2、TUIC v5、Shadowsocks、AnyTLS、VLESS-TLS-Vision、VLESS-WS-TLS、Trojan-TLS、Trojan-Reality 和 VMess-WS-TLS。用户只选择完整协议，不需要理解或手动组合传输层、安全层与内层协议。

完整文档：[Wiki](https://github.com/Jyanbai/ping-rust/wiki) · [快速开始](https://github.com/Jyanbai/ping-rust/wiki/Quick-Start) · [链式代理](https://github.com/Jyanbai/ping-rust/wiki/Chain-Proxy) · [故障排查](https://github.com/Jyanbai/ping-rust/wiki/Troubleshooting)

## 一键安装（推荐）

无需预装 Rust。在 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 等 systemd Linux 上执行：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)
```

这一个命令会继续自动下载 shoes、选择随机可用端口、生成全部安全凭据、启动 systemd，并直接输出可导入 v2rayN 的 `vless://` 链接，不询问协议或端口。部署完成后使用 `sudo prs` 进入日常管理菜单。

安装指定版本或目录：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --version v0.1.14

bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --install-dir /usr/local/bin --quiet --no-bootstrap
```

安装器自动识别 x86_64/aarch64，从 GitHub Releases 下载对应 musl 静态包，强制验证 `SHA256SUMS` 和二进制版本后原子安装到 `/usr/local/bin/ping-rust`，并安全创建 `prs → ping-rust` 符号链接。默认调用 Rust `bootstrap` 完成首次 Reality 部署；检测到已有配置时自动跳过，`--no-bootstrap` 可用于只安装管理工具。若系统已有其它 `prs` 命令，安装器会保留它并提示改用 `ping-rust`，绝不强制覆盖；升级时只会移除确实指向 `ping-rust` 的旧 `sb` 链接，不会删除用户自己的 `sb` 程序。写入系统目录时会调用 `sudo`；令牌、密码和代理配置都不会被上传。

## 功能

- 从 GitHub Release 下载 shoes，自动匹配 x86_64/aarch64 与 GNU/musl，强制校验官方 SHA-256 digest；GNU 资产不兼容时安全回退 static musl
- 使用 cargo 从与 schema CI 相同的 cfal/shoes 固定源码提交编译安装；低于 1 GiB 内存时自动单任务并关闭 LTO，避免换页风暴
- 生成十种已验证协议预设的 shoes 服务端配置；每项均是可直接部署的完整协议栈
- `prs` 数字菜单与 `prs add/a` 快捷命令：自动端口、自动凭据、部署完成直接输出分享链接
- 在 Rust 内生成 X25519 Reality 密钥、UUID、short ID、随机密码和自签名证书
- Reality 未显式指定 SNI 时，从与本地 233boy 脚本一致的 Amazon、eBay、PayPal、Cloudflare 域名列表中随机选择（不含 Apple）；客户端指纹与该脚本一致固定为 `chrome`
- 在同目录候选文件上调用 `shoes --dry-run`，通过后才原子提交并启用 systemd 服务
- 多配置添加、列表、删除、端口冲突保护
- 全局链式代理：从分享链接导入受支持的上游节点，选择、启停、测试和删除；启用后所有受管入站经当前节点转发
- 跨进程配置锁、配置/sidecar 精确回滚，更新与恢复保留服务原运行状态
- 服务启停、重启、状态、journalctl 日志、更新与卸载
- BBR、TCP/UDP 端口检查、敏感配置备份与安全恢复
- 导出 Clash Meta、sing-box 和 Nekobox 分享链接
- Rust 原生更新 ping-rust 自身：GitHub Release + `SHA256SUMS` 双重校验、版本探针、原子替换与失败回滚

## 支持环境

| 系统 | 架构 | Release 安装 | cargo 安装 |
|---|---|---:|---:|
| Ubuntu 22.04 / 24.04 | x86_64 / aarch64 | 是 | 是 |
| Debian 12 | x86_64 / aarch64 | 是 | 是 |
| Rocky Linux 9 / AlmaLinux 9 | x86_64 / aarch64 | 是 | 是 |

要求系统使用 systemd。一键安装 ping-rust 与 shoes Release 安装都不要求服务器预装 Rust；只有 cargo 安装方式需要稳定版 Rust 工具链。

## 其他安装方式

使用 cargo 安装前，最小 VPS 需要 C linker 和常用构建工具：

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y build-essential pkg-config git ca-certificates

# Rocky Linux / AlmaLinux
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config git ca-certificates
```

从 [crates.io](https://crates.io/crates/ping-rust) 安装已发布的稳定版本：

```bash
cargo install ping-rust --locked
sudo ping-rust
```

直接从已公开的 GitHub `main` 安装：

```bash
cargo install --git https://github.com/Jyanbai/ping-rust.git --locked
sudo ping-rust
```

从当前源码安装：

```bash
git clone https://github.com/Jyanbai/ping-rust.git
cd ping-rust
cargo install --path . --locked
sudo ping-rust
```

首次启动、生成系统配置、管理 systemd、BBR、备份恢复和卸载都需要 root。生成到自定义路径、查看帮助和本地端口检查不要求 root。

## 233boy 风格快速部署

执行一键安装命令后，无需再输入任何内容：

```text
$ bash <(curl -fsSL https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)

首次安装：自动部署 VLESS-REALITY
正在自动安装 shoes、选择随机端口并生成安全凭据……

部署成功，shoes 服务已启动。

-------------- VLESS-REALITY-30060.yaml -------------
协议 (protocol)         = vless
端口 (port)             = 30060
传输层安全 (TLS)        = reality
------------- 链接 (URL) -------------
vless://...security=reality...pbk=...&sid=...#VLESS-REALITY-30060
------------- 二维码 (QR) -------------
（终端在这里显示可直接扫描的块字符二维码）
------------- END -------------
```

安装脚本只在配置文件和管理状态都不存在时触发默认部署。Rust `bootstrap` 会自动下载 shoes、选择随机可用端口、生成 UUID/X25519 密钥/short ID、执行 `shoes --dry-run`、启动并确认 systemd 服务，然后输出可直接导入 v2rayN 的链接；检测到任何已有配置时绝不覆盖。通过 cargo 安装的用户第一次运行 `sudo prs` 时也会执行同一安全入口。

部署完成后的常规菜单如下：

```text
$ sudo prs

------------- ping-rust v0.1.15 -------------
shoes: running
项目: https://github.com/Jyanbai/ping-rust

1) 添加配置
2) 更改配置
3) 查看配置
4) 删除配置
5) 运行管理
6) 更新
7) 卸载
8) 帮助
9) 其他
10) 关于
0) 退出

请选择 [0-10]: 1

选择协议:

1) TUIC
2) Hysteria2
3) Shadowsocks
4) VLESS-REALITY（推荐）
5) AnyTLS
6) VLESS-TLS-Vision
7) VLESS-WS-TLS
8) Trojan-TLS
9) Trojan-REALITY
10) VMess-WS-TLS
0) 返回

请选择 [0-10]: 4
输入端口（直接回车自动选择随机端口）:

部署成功，shoes 服务已启动。
-------------- VLESS-REALITY-25448.yaml -------------
协议 (protocol)         = vless
端口 (port)             = 25448
------------- 链接 (URL) -------------
vless://...security=reality...pbk=...&sid=...#VLESS-REALITY-25448
------------- 二维码 (QR) -------------
（终端在这里显示可直接扫描的块字符二维码）
------------- END -------------
```

菜单 `2. 更改配置` 会先选择现有配置，再按协议提供端口、名称、公网地址、凭据、Reality SNI、Shadowsocks cipher 或 AnyTLS 用户密码等修改项。新配置必须通过真实 `shoes --dry-run` 才会原子提交；服务重启失败时自动恢复修改前的配置与 systemd 状态，成功后直接输出新的分享链接。

每个节点都会保存为 `/etc/shoes/profiles/` 下的真实独立 YAML 文件；查看、更改和删除时直接显示该文件名，例如 `VLESS-REALITY-53453.yaml`。分享 URI 的 `#` 后也使用同一个文件基名，例如 `#VLESS-REALITY-53453`，复制或扫码导入 v2rayN 后即可看到协议与端口。添加配置成功和 `3) 查看配置` 都会在 URL 后直接显示对应的终端二维码并退出菜单；只有一个配置时自动选中，多个配置时才显示数字列表。shoes 继续加载由 Rust 确定性聚合的 `/etc/shoes/config.yaml`，内部 UUID 仅用于安全定位。

### 链式代理

从主菜单进入 `9) 其他 → 1) 链式代理`：

```text
------------- 链式代理管理 -------------
状态：○ 未启用
当前出口：未选择
节点数量：0

1) 添加节点（分享链接）
2) 选择出口节点
3) 启用链式代理
4) 测试节点（完整代理）
5) 查看节点
6) 删除节点
0) 返回
```

第一版支持 SOCKS5、HTTP/HTTPS、Shadowsocks、VLESS TCP/TLS/Reality/WebSocket 和 Trojan TLS/WebSocket 分享链接。由于当前 shoes 内核没有对应客户端实现，Hysteria2、TUIC、WireGuard/WARP 不能作为链式出口；ping-rust 会返回明确错误，不会生成近似配置。HTTP、SOCKS5 和 Trojan 出口不支持 UDP-over-TCP，启用或切换时会再次警告；相关 UDP 请求会失败，不会自动回退直连。

“测试节点（完整代理）”严格复用当前节点生成临时 shoes SOCKS5 入口，再通过该入口访问 `https://www.gstatic.com/generate_204`。只有地址可达、协议认证/Reality 握手和 HTTP 出口全部成功才报告节点可用；测试进程和权限为 `0600` 的临时配置随后立即删除。它不会修改当前出口或线上 systemd 服务。

添加第一个节点时会自动选为当前出口，但不会自动启用。启用后，受支持的 TCP 流量使用同一个上游节点；关闭或删除正在使用的节点会恢复 `allow-all-direct`。固定 shoes 0.2.8 的 Hysteria2/TUIC UDP 服务端路径会忽略 client chain 并直接创建 UDP socket，因此只要当前存在 Hysteria2 或 TUIC 入站，ping-rust 就会拒绝启用全局链式代理，避免静默直连泄漏；链式代理已经启用时也不能新增这两类入站。节点凭据保存在权限为 `0600` 的管理状态和配置文件中，备份同样包含这些敏感信息。

CI 在 Debian 12 与 Ubuntu 24.04 的真实 systemd 环境中，从 PTY 菜单完成添加、完整协议测试、选择、启用、切换、关闭和删除。两个隔离网络命名空间提供可区分的 Shadowsocks 出口；测试会核对 HTTP 服务观察到的源地址，并验证 systemd 重启后仍使用所选出口、上游离线时请求失败且不会静默直连。该测试覆盖稳定 TCP 路径，不代表 shoes 已支持 UDP 链式转发。

首次安装流程是：`install.sh → 自动安装 ping-rust/shoes → 自动随机端口部署 VLESS-REALITY → 复制 URL`，中间零输入。Reality 未指定 `--server-name` 时会从 `www.amazon.com`、`www.ebay.com`、`www.paypal.com`、`www.cloudflare.com`、`dash.cloudflare.com`、`aws.amazon.com` 中随机选择 SNI；列表不含 Apple，客户端指纹固定为本地 233boy 脚本使用的 `chrome`。后续日常流程是：`prs → 1 → 选择协议 → 输入端口/直接回车随机 → 复制 URL 到 v2rayN`；Shadowsocks 会额外选择加密方式和密码，SS 2022 密码不符合所选 cipher 的 Base64 密钥长度时会警告并自动替换。其余协议自动生成 UUID、密码、Reality 密钥、WebSocket 路径或证书。十个协议都会输出公网地址、端口、客户端所需凭据、协议参数和分享链接。添加或查看配置成功后直接退出 `prs`；主菜单输入 `0` 退出，任意子菜单输入 `0` 返回主菜单。自动端口从 `20000..=65535` 的高位范围选择；协议选择固定使用连续编号 `1..=10`。链接只会在配置通过 `shoes --dry-run`、原子写入、systemd 启动且确认为 active 后输出；失败会恢复原配置和服务状态。

非交互方式：

```bash
# 自动安装 shoes、随机端口和凭据；标准输出只返回一行链接
sudo prs add reality --yes --plain

# 233boy 风格短别名和指定端口
sudo prs a r 443
sudo prs add ss 8388

# 自动随机端口也可显式写出；指定公网地址可跳过自动探测
sudo prs add reality --random-port --server-address 203.0.113.10
```

高级用户原有的 `generate` 命令全部保留，可精细指定 cipher、证书、Reality fallback、AnyTLS 用户等参数。

新增协议也可直接使用短命令，无需组合底层参数：

```bash
sudo prs add vless-tls
sudo prs add vless-ws-tls
sudo prs add trojan-tls
sudo prs add trojan-reality
sudo prs add vmess-ws-tls
```

WebSocket 路径默认安全随机生成；需要固定路径时可使用完整命令：

```bash
sudo ping-rust generate vless-ws-tls --port 443 \
  --server-name proxy.example.com --websocket-path /vless
```

重新显示已保存链接（多个配置时使用名称或 UUID）：

```bash
sudo prs info
sudo prs url reality-main
sudo prs qr reality-main
```

添加配置、`qr` 与菜单中的 `3) 查看配置` 使用内置 Rust 编码器在终端生成二维码，不依赖 `qrencode`，也不会把含凭据的 URL 发送给第三方网站。`add --plain` 和 `url` 始终只输出一行链接，适合脚本调用。

## Hysteria2 与 TUIC

快速生成：

```bash
sudo ping-rust generate hysteria2 --name hy2 --port 8443 --server-name proxy.example.com
sudo ping-rust generate tuic --name tuic --port 10443 --server-name proxy.example.com
```

未指定证书时会创建自签名证书。工具导出客户端配置时会设置相应的跳过校验字段，并显示风险提示；生产环境推荐使用受信任证书：

```bash
sudo ping-rust generate hysteria2 \
  --name hy2 \
  --port 8443 \
  --server-name proxy.example.com \
  --cert /etc/letsencrypt/live/proxy.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/proxy.example.com/privkey.pem
```

`--cert` 与 `--key` 必须同时提供。

## Shadowsocks 与 AnyTLS

Shadowsocks 默认使用 shoes 推荐列表中的 2022 AES-256-GCM，并生成标准 Base64 编码的 32 字节密钥：

```bash
sudo ping-rust generate shadowsocks --name ss-main --port 8388

# 指定其它 shoes 支持的 cipher；2022 密码会严格检查解码后长度
sudo ping-rust generate shadowsocks \
  --name ss-aes128 \
  --port 8389 \
  --cipher 2022-blake3-aes-128-gcm
```

AnyTLS 默认使用普通 TLS 外层；`--user` 可重复，格式为 `[名称:]密码`。未提供用户时自动创建一个随机密码用户：

```bash
sudo ping-rust generate anytls \
  --name anytls-main \
  --port 9443 \
  --server-name proxy.example.com \
  --user alice:'replace-with-a-long-random-password' \
  --user bob:'another-long-random-password' \
  --padding stop=8 \
  --padding 0=30-30 \
  --padding 1=50-100 \
  --fallback 127.0.0.1:80
```

不指定 `--cert/--key` 时会生成自签名证书。高级 Reality+AnyTLS 组合使用：

```bash
sudo ping-rust generate anytls \
  --name anytls-reality \
  --port 10443 \
  --anytls-mode reality \
  --server-name www.cloudflare.com \
  --dest www.cloudflare.com:443 \
  --user default:'replace-with-a-long-random-password'
```

`padding_scheme` 必须包含且只包含一个 `stop=N`；非法范围会在写配置前被拒绝。Reality short ID 可用 `--short-id` 指定，否则安全随机生成。

## 常用命令

```bash
ping-rust --help
sudo ping-rust info
sudo prs url <配置名或 UUID>
sudo prs qr <配置名或 UUID>
sudo ping-rust service status
sudo ping-rust service restart
sudo ping-rust logs -n 200
ping-rust check-port 443 --kind both
sudo ping-rust enable-bbr
sudo ping-rust update --method release
sudo ping-rust self-update
```

`update` 只更新 shoes 内核；`self-update` 更新 ping-rust 本身。默认安装最新 Release，也可以指定版本；显式指定旧版本表示受控降级：

```bash
sudo ping-rust self-update --version v0.1.14
sudo ping-rust self-update --version v0.1.14 --force
```

自更新支持 Linux x86_64/aarch64，下载对应 musl 静态包，校验 GitHub API digest 与 `SHA256SUMS`，确认新二进制版本后才替换当前程序。程序位于 `/usr/local/bin` 时通常需要 `sudo`；用户目录内可写的 cargo 安装则不需要。

多个配置使用不同端口。查看 ID 后删除：

```bash
sudo ping-rust info
sudo ping-rust delete <配置-UUID> --yes
```

## 客户端导出

```bash
sudo ping-rust export clash-meta --profile <配置-UUID> --server 203.0.113.10 --output clash.yaml
sudo ping-rust export sing-box --profile <配置-UUID> --server proxy.example.com --output sing-box.json
sudo ping-rust export nekobox --profile <配置-UUID> --server 203.0.113.10
```

只有一个配置时可以省略 `--profile`。十种菜单协议均能生成 sing-box 配置及 v2rayN 可导入链接；新增的 VLESS、Trojan 和 VMess 预设同时支持 Clash Meta。普通 TLS AnyTLS 和 Shadowsocks 也支持 Clash Meta 与 Nekobox 标准 URI。Mihomo 明确不支持 AnyTLS+Reality，标准 AnyTLS URI也无法表达 Reality 公钥，因此这两个导出会返回中文错误，不会生成伪配置。所有 Reality 导出都只包含公钥，永远不包含服务器私钥。

## 备份与恢复

```bash
sudo ping-rust backup ./shoes-backup.tar.gz
sudo ping-rust restore ./shoes-backup.tar.gz
```

备份包含私钥、UUID 和密码，文件权限为 `0600`，请加密保存。恢复过程拒绝绝对路径、`..`、符号链接和特殊文件；新配置未通过 shoes 校验时会自动恢复旧目录。成功恢复后，旧目录仍保留为 `/etc/shoes.pre-restore-<时间戳>`，确认无误后再手动清理。

## 文件位置与权限

| 路径 | 用途 | 权限 |
|---|---|---:|
| `/usr/local/bin/shoes` | shoes 内核 | `0755` |
| `/usr/local/bin/prs` | 指向 ping-rust 的安全短命令符号链接 | symlink |
| `/etc/shoes/profiles/<协议>-<端口>.yaml` | 每个节点的真实独立配置文件 | `0600` |
| `/etc/shoes/config.yaml` | Rust 从全部节点确定性聚合、供 shoes 实际加载的配置 | `0600` |
| `/etc/shoes/ping-rust-state.json` | 多配置元数据与客户端导出凭据 | `0600` |
| `/etc/shoes/cert-*.pem` | 自动生成证书 | `0644` |
| `/etc/shoes/key-*.pem` | 自动生成证书私钥 | `0600` |
| `/run/lock/ping-rust.lock` | 配置操作进程间互斥 | `0600` |
| `/etc/systemd/system/shoes.service` | systemd unit | `0644` |

卸载默认保留 `/etc/shoes`。只有 `uninstall --purge` 或菜单二次确认才会删除配置。

## 故障排查

查看服务和日志：

```bash
sudo systemctl status shoes --no-pager
sudo journalctl -u shoes -n 200 --no-pager
sudo /usr/local/bin/shoes --dry-run /etc/shoes/config.yaml
```

- `Address already in use`：运行 `ping-rust check-port <端口>`，换用未占用端口。
- Reality 连接失败：检查 VPS 防火墙、安全组、UUID、公钥、short ID、SNI 和 fallback 是否一致，并用 `timedatectl status` 确认客户端与服务端时钟已同步。
- Hysteria2/TUIC 失败：确认 UDP 端口已放行，并检查证书域名。
- Shadowsocks 2022 导入失败：确认客户端 cipher 使用标准名称，且 Base64 密钥解码长度与 AES-128（16 字节）或 AES-256/ChaCha20（32 字节）一致。
- AnyTLS 失败：确认选择的 TLS/Reality 模式、SNI、密码与证书校验设置一致；AnyTLS+Reality 请使用 sing-box 导出。
- 链式节点显示端口可达但不能使用：进入 `9) 其他 → 1) 链式代理 → 4) 测试节点（完整代理）`；新版测试会验证密码/UUID、TLS/Reality 握手和真实 HTTP 出口，不再只测 TCP 端口。
- `systemctl` 不存在：当前系统不是 systemd 环境，服务管理功能无法使用。
- GitHub API 限流：稍后重试，或使用 `install --method cargo`。
- 自更新提示权限不足：若当前程序位于 `/usr/local/bin`，改用 `sudo ping-rust self-update`；不要手工覆盖正在更新的文件。
- cargo 安装版本较旧：GitHub Release 与 crates.io 的发布时间可能不同，优先选择 Release。
- cargo 编译很慢：低内存 VPS 上源码模式可能需要数十分钟；这是回退通道，默认部署应优先使用 Release。

## 开发与验证

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo doc --no-deps
```

本仓库开发阶段已完成：

- Rust 单元测试覆盖密钥/YAML、归档解包、原子写入、systemd unit、端口检查、客户端三格式和恢复路径安全。
- 自更新单元测试覆盖版本、架构、checksum 重复/缺失和严格单文件归档；Release job 还会真实执行一次强制自更新并复核版本。
- `shoes-schema.yml` 固定 cfal/shoes commit `386b11532424b8665ee3e46340c6236fb3c47595`（0.2.8），对十协议单独配置、十协议联合配置、全部六种 Shadowsocks cipher 和 Reality+AnyTLS 执行真实 `shoes --dry-run`，并启动十协议聚合配置检查 TCP/UDP 监听。
- 通过 cargo-zigbuild + Zig 生成 x86_64/aarch64 Linux GNU release ELF，最高 GLIBC 需求为 2.34，覆盖 Rocky/Alma 9 及更新的目标发行版基线。
- CI 覆盖 Ubuntu 22.04/24.04，并在 Debian 12、Rocky Linux 9、AlmaLinux 9 容器中执行锁定依赖测试和 release 构建；shoes schema 作业实际启动十协议聚合监听，Ubuntu 24.04 acceptance 继续覆盖 root 路径、systemd 和核心管理流程。
- 独立链式代理验收在 Ubuntu 24.04 主机和 Debian 12 特权 systemd 容器中运行，使用真实 PTY 菜单、两条隔离 Shadowsocks 出口和 HTTP 源地址核验覆盖完整生命周期与无直连回退。
- 使用 RustSec `cargo audit` 扫描锁定依赖，当前未报告安全公告。
- 在一台干净代理环境的 Debian 12 x86_64 VPS 上完成原生安装与运行验收：Release 路径约 2 秒完成 shoes v0.2.7 musl 安装，三协议同时通过 dry-run 并由 systemd 启动，外部 Reality 客户端的代理出口与 VPS 公网 IP 一致。
- 实机完成 9 份客户端导出解析、BBR、端口检查、日志、备份恢复、inactive 状态保持和 Release 更新；详细证据见完成度审计。
- 在 Ubuntu 24.04.3 x86_64 VPS 上从干净基线完成 crates.io、Git 固定提交与一键 Release 三种安装入口；Reality 从 shoes 安装到 systemd active/listening 用时约 2 秒，三协议、9 份客户端导出、备份恢复、更新、数字菜单、逐配置删除和卸载均通过。
- Ubuntu VPS 真实重启后 shoes 自动恢复为 enabled/active，Reality TCP 443、Hysteria2 UDP 8443、TUIC UDP 9443 均恢复监听；官方 sing-box 客户端在重启前后两次完成公网 Reality 握手，代理出口均为该 VPS。

逐项需求、修复记录、ELF 哈希和外部验收边界见 [COMPLETION_AUDIT.md](COMPLETION_AUDIT.md)。

全新 Ubuntu 24.04 x86_64 VPS 已完成以下实机验收：

1. `cargo install --path . --locked`。
2. Release 与 cargo 两种 shoes 安装方式各测试一次。
3. 三种协议分别生成、启动，并从外部客户端连接。
4. 重启 VPS，确认 `shoes.service` 自动启动。
5. 验证更新、日志、BBR、备份恢复、删除和卸载。

上述清单已全部通过。测试结束后执行 `uninstall --purge`，并移除测试目录、导出文件、备份和回滚目录；测试期间安装的 Ubuntu 官方构建依赖与 Rust 工具链保留，便于后续源码测试。

## 截图建议

发布 README 时建议补充三张终端截图：

1. 主数字菜单全景。
2. Reality 生成完成画面（必须遮盖私钥、UUID 和 short ID）。
3. `systemctl status shoes` 与客户端连通性测试。

## 仓库结构

```text
ping-rust/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── .gitignore
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── menu.rs
│   ├── installer.rs
│   ├── config.rs
│   ├── service.rs
│   ├── client.rs
│   ├── operations.rs
│   ├── self_update.rs
│   └── utils.rs
├── examples/
│   ├── reality.yaml
│   ├── hysteria2.yaml
│   ├── tuic.yaml
│   ├── shadowsocks.yaml
│   └── anytls.yaml
├── systemd/
│   └── ping-rust.service
└── scripts/
    └── install.sh
```

## 项目仓库

源码仓库：[Jyanbai/ping-rust](https://github.com/Jyanbai/ping-rust)

## 许可证

[MIT License](LICENSE)
