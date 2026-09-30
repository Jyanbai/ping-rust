# ping-rust Wiki

`ping-rust` 是使用 Rust 编写的 [cfal/shoes](https://github.com/cfal/shoes) 安装与管理工具，提供接近 233boy 的数字菜单体验。当前稳定版为 **v0.2.0**。

v0.2.0 提供 13 种受管协议、Verified Hot Reload、Chain Proxy 2.0、Update Center 与实验性 H2MUX 客户端偏好。协议兼容边界见[支持协议](Protocols)，验证方式见主仓库的 [COMPLETION_AUDIT.md](https://github.com/Jyanbai/ping-rust/blob/main/COMPLETION_AUDIT.md)。

## 一键安装

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)
```

安装脚本会下载经过 SHA-256 校验的静态二进制，自动安装 shoes，并在首次安装时零输入部署随机端口 VLESS-REALITY。完成后运行：

```bash
sudo prs
```

## 文档导航

- [安装说明](Installation)
- [快速开始](Quick-Start)
- [支持协议](Protocols)
- [链式代理](Chain-Proxy)
- [运维管理](Operations)
- [故障排查](Troubleshooting)

- 项目主页：[Jyanbai/ping-rust](https://github.com/Jyanbai/ping-rust)
- 最新版本：[GitHub Releases](https://github.com/Jyanbai/ping-rust/releases/latest)
- crates.io：[ping-rust](https://crates.io/crates/ping-rust)

