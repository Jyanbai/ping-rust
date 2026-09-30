# 支持协议（v0.2.0）

| 菜单 | 协议 | 分级 |
|---:|---|---|
| 1 | TUIC v5 | 稳定 |
| 2 | Hysteria2 | 稳定 |
| 3 | Shadowsocks（含 SS2022 + ShadowTLS v3） | 稳定 |
| 4 | VLESS-REALITY-Vision | 稳定 |
| 5 | AnyTLS | 稳定 |
| 6 | VLESS-TLS-Vision | 稳定 |
| 7 | VLESS-WS-TLS | 稳定 |
| 8 | Trojan-TLS | 稳定 |
| 9 | Trojan-REALITY | 稳定 |
| 10 | VMess-WS-TLS | 稳定 |
| 11 | SOCKS5 | 稳定 |
| 12 | Snell v3 | 实验性 |
| 13 | NaiveProxy | 实验性 |

Snell v3 和 NaiveProxy 的导出面受限，客户端兼容范围较窄。Snell v3 没有统一 URI；只对 Mihomo v3 明确支持的 `aes-128-gcm` 配置提供无损导出。NaiveProxy 的 sing-box 原生客户端依赖特定平台/构建，自签名证书仅适合测试。

H2MUX 客户端偏好也标为实验性：仅 VMess WebSocket TLS、VLESS WebSocket TLS 和 Trojan TLS 在已验证范围内开放；sing-box 导出携带设置，普通分享 URI/QR 不携带，Mihomo H2MUX 导出明确拒绝。

每个菜单项都是完整协议栈。候选配置先通过 `shoes --dry-run`，再原子提交；激活失败回滚。无法无损表达的客户端格式会返回明确错误，不生成伪 URI 或近似配置。

