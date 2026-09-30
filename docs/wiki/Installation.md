# 安装说明

## 支持环境

- Ubuntu 22.04 / 24.04
- Debian 12
- Rocky Linux 9 / AlmaLinux 9
- x86_64 与 aarch64
- systemd

## 一键安装（推荐）

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)
```

默认流程：

1. 检测 CPU 架构；
2. 下载对应的 musl 静态二进制；
3. 验证 `SHA256SUMS`；
4. 原子安装到 `/usr/local/bin/ping-rust`；
5. 创建 `prs` 快捷命令；
6. 安装 shoes；
7. 自动部署随机端口 VLESS-REALITY 并输出分享链接。

## 安装选项

```bash
# 指定版本
bash scripts/install.sh --version v0.2.0

# 只安装管理工具，不部署 Reality
bash scripts/install.sh --no-bootstrap

# 指定目录
bash scripts/install.sh --install-dir /usr/local/bin
```

## 从 crates.io 安装

```bash
cargo install ping-rust --locked
sudo ping-rust
```

该方式需要 Rust、C linker、Git、CA 证书和常用构建工具。低内存 VPS 更推荐使用预编译静态二进制。

## 验证

```bash
ping-rust --version
command -v prs
sudo systemctl status shoes.service
```

