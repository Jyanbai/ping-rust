# ping-rust

`ping-rust` 是一个纯 Rust 编写的 [cfal/shoes](https://github.com/cfal/shoes) 安装与管理工具。它提供类似 233boy 脚本的数字菜单，在 Linux VPS 上完成 shoes 安装、VLESS-Reality-Vision、Hysteria2、TUIC v5、Shadowsocks、AnyTLS 配置、systemd 管理和日常运维。

核心逻辑全部位于 Rust 源码中；`scripts/install.sh` 只负责下载、校验并安装官方预编译二进制。

> v0.1.6 已包含 VLESS-Reality-Vision、Hysteria2、TUIC v5、Shadowsocks 和 AnyTLS 五协议，并提供简短的 `prs` 快速入口。

## 一键安装（推荐）

无需预装 Rust。在 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 等 systemd Linux 上执行：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)
sudo prs
```

安装指定版本或目录：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --version v0.1.6

bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --install-dir /usr/local/bin --quiet
```

安装器自动识别 x86_64/aarch64，从 GitHub Releases 下载对应 musl 静态包，强制验证 `SHA256SUMS` 和二进制版本后原子安装到 `/usr/local/bin/ping-rust`，并安全创建 `prs → ping-rust` 符号链接。若系统已有其它 `prs` 命令，安装器会保留它并提示改用 `ping-rust`，绝不强制覆盖；升级时只会移除确实指向 `ping-rust` 的旧 `sb` 链接，不会删除用户自己的 `sb` 程序。写入系统目录时会调用 `sudo`；令牌、密码和代理配置都不会被上传。

## 功能

- 从 GitHub Release 下载 shoes，自动匹配 x86_64/aarch64 与 GNU/musl，强制校验官方 SHA-256 digest；GNU 资产不兼容时安全回退 static musl
- 使用 `cargo install shoes` 从 crates.io 编译安装；低于 1 GiB 内存时自动单任务并关闭 LTO，避免换页风暴
- 生成 VLESS-Reality-Vision、Hysteria2、TUIC v5、Shadowsocks、AnyTLS 服务端配置
- `prs` 数字菜单与 `prs add/a` 快捷命令：自动端口、自动凭据、部署完成直接输出分享链接
- 在 Rust 内生成 X25519 Reality 密钥、UUID、short ID、随机密码和自签名证书
- 在同目录候选文件上调用 `shoes --dry-run`，通过后才原子提交并启用 systemd 服务
- 多配置添加、列表、删除、端口冲突保护
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

从 [crates.io](https://crates.io/crates/ping-rust) 安装已发布的 `0.1.6`：

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

```text
$ sudo prs

ping-rust · shoes 管理工具
────────────────────────────
请选择操作
  1. 添加配置
  2. 更改配置
  3. 查看配置
  4. 删除配置
  5. 运行管理
  6. 更新
  7. 卸载
  8. 帮助
  9. 其他
  10. 关于
  0. 退出
请输入序号: 1

选择协议
  1. TUIC
  2. Hysteria2
  3. Shadowsocks
  4. VLESS-REALITY（推荐）
  5. AnyTLS
  0. 返回
请输入序号: 4
输入端口（直接回车自动选择随机端口）:

部署成功，shoes 服务已启动。
------------- URL 链接 -------------
vless://...security=reality...pbk=...&sid=...
```

实际日常流程就是：`prs → 1 → 4（VLESS）或 3（SS）→ 输入端口/直接回车随机 → 复制 URL 到 v2rayN`。所有协议选择固定使用连续编号 `1/2/3/4/5`；主菜单输入 `0` 退出，任意子菜单输入 `0` 返回主菜单。首次使用时若 shoes 未安装，菜单会询问是否自动从 Release 安装；UUID、Reality 密钥、short ID 或 SS 2022 密码全部安全随机生成。链接只会在配置通过 `shoes --dry-run`、原子写入、systemd 启动且确认为 active 后输出；失败会恢复原配置和服务状态。

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

重新显示已保存链接（多个配置时使用名称或 UUID）：

```bash
sudo prs info
sudo prs url reality-main
sudo prs qr reality-main
```

`qr` 使用本机 `qrencode` 在终端生成二维码，不会把含凭据的 URL 发送给第三方网站；未安装 `qrencode` 时会退化为原样输出 URL。

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
sudo ping-rust self-update --version v0.1.5
sudo ping-rust self-update --version v0.1.5 --force
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

只有一个配置时可以省略 `--profile`。五种协议均支持 sing-box；普通 TLS AnyTLS 和 Shadowsocks 也支持 Clash Meta 与 Nekobox 标准 URI。Mihomo 明确不支持 AnyTLS+Reality，标准 AnyTLS URI也无法表达 Reality 公钥，因此这两个导出会返回中文错误，不会生成伪配置。所有 Reality 导出都只包含公钥，永远不包含服务器私钥。

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
| `/etc/shoes/config.yaml` | shoes 配置 | `0600` |
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
- `shoes-schema.yml` 固定 cfal/shoes commit `386b11532424b8665ee3e46340c6236fb3c47595`（0.2.8），对五协议单独配置、五协议联合配置、全部六种 Shadowsocks cipher 和 Reality+AnyTLS 执行真实 `shoes --dry-run`。
- 通过 cargo-zigbuild + Zig 生成 x86_64/aarch64 Linux GNU release ELF，最高 GLIBC 需求为 2.34，覆盖 Rocky/Alma 9 及更新的目标发行版基线。
- CI 覆盖 Ubuntu 22.04/24.04，并在 Debian 12、Rocky Linux 9、AlmaLinux 9 容器中执行锁定依赖测试和 release 构建；Ubuntu 24.04 acceptance 还会实际管理 root 路径、systemd 与五协议监听端口。
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
