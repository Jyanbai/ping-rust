# 发版说明草稿（未发布）

- 新增 VLESS-ENC 预设：菜单第 14 项及 `prs add vless-enc`；原生 TCP，不套 TLS/Reality，安全性完全依赖 VLESS Encryption。支持 native/xorpub/random（random 关闭 TCP splice）、x25519/mlkem768、可选 Vision 和 Mihomo 导出；不支持 sing-box、NekoBox、链式出口或 H2MUX。客户端版本要求以 CI 实测为准，固定测试目标 Xray v26.6.27、Mihomo v1.19.33，互通结果待 C 阶段报告确认。

- shoes 默认版本升级到 v0.3.6；旧 Chain 2.0 通配符规则在升级时从 state 重新生成，升级事务先 dry-run，再提交配置和重启服务，失败时回滚。
- Snell v3 新节点默认使用 `aes-128-gcm`。Mihomo 客户端仅支持 `aes-128-gcm`；`aes-256-gcm` 和 `chacha20-ietf-poly1305` 仍可在高级选项中手动选择，但未经客户端验证。
- 已有 Snell 节点不会自动改 cipher。已有的 chacha20 或 aes-256 Snell 节点如果使用 Mihomo 客户端，需要改为 `aes-128-gcm` 并重新导出客户端配置。
- 上述 Mihomo 连通性测试不能说明 shoes salt 改动的影响。
