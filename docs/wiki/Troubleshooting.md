# 故障排查

## shoes 无法启动

```bash
sudo systemctl status shoes.service --no-pager
sudo journalctl -u shoes.service -n 100 --no-pager
sudo shoes --dry-run /etc/shoes/config.yaml
```

ping-rust 正常情况下会在写入前 dry-run，并在激活失败时回滚。如果配置被手工修改，先备份再检查 `/etc/shoes/config.yaml` 与 `/etc/shoes/state.json` 是否一致。

## 端口已被占用

```bash
sudo ss -lntup
```

通过菜单更改端口，或添加新配置时直接回车让 ping-rust 选择随机高位端口。

## 客户端无法连接

依次检查：

1. VPS 防火墙和云平台安全组是否放行端口；
2. `shoes.service` 是否为 active；
3. 分享链接中的公网地址是否正确；
4. 自签名 TLS 协议是否在客户端开启“允许不安全连接”；
5. Reality 的 SNI、public key 与 short ID 是否完整。

## 链式代理启用后 UDP 失败

HTTP、SOCKS5 和 Trojan 链式出口在当前 shoes 内核中只支持 TCP。需要 UDP-over-TCP 时请选择已验证的 Shadowsocks 或 VLESS 出口。若受管入站包含 Hysteria2/TUIC，ping-rust 会拒绝启用全局链式代理，避免 UDP 静默直连。

## 链式节点端口可达但无法使用

进入 `9) 其他 → 1) 链式代理 → 7) 测试节点 / Chain → 1) 测试节点`。该测试会通过临时 shoes 入口验证密码或 UUID、TLS/Reality 握手和真实 HTTP 出口；只有端口开放并不代表节点协议可用。

Pool 可通过 `9 → 1 → 7 → 3) 测试 Pool 内全部节点` 手动逐个检查；输出会列出每个节点的结果、失败原因和耗时。Pool 不提供自动健康检查或故障切换。

## 热重载失败

查看 `shoes.service` 日志和当前监听。ping-rust 只有在 MainPID 不变、服务 active、目标监听出现且旧监听消失时才承认热重载成功；超时会恢复旧配置和服务状态。凭据等无法用监听证明的修改继续使用受控重启。

## 低内存编译时间过长

低于 1 GiB 内存的 VPS 不建议从源码编译，优先使用 GitHub Release 的 musl 静态二进制。一键安装脚本不要求预装 Rust。

## GitHub 无法访问

安装器会重试下载，但无法绕过网络封锁。可以在可访问 GitHub 的设备下载 Release 资产和 `SHA256SUMS`，验证后再传到 VPS。

