# 发版说明草稿（未发布）

- shoes 默认版本升级到 v0.3.6；旧 Chain 2.0 通配符规则在升级时从 state 重新生成，升级事务先 dry-run，再提交配置和重启服务，失败时回滚。
- Snell v3 新节点默认使用 `aes-128-gcm`。Mihomo 客户端仅支持 `aes-128-gcm`；`aes-256-gcm` 和 `chacha20-ietf-poly1305` 仍可在高级选项中手动选择，但未经客户端验证。
- 已有 Snell 节点不会自动改 cipher。已有的 chacha20 或 aes-256 Snell 节点如果使用 Mihomo 客户端，需要改为 `aes-128-gcm` 并重新导出客户端配置。
- 上述 Mihomo 连通性测试不能说明 shoes salt 改动的影响。
