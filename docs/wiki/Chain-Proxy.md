# Chain Proxy 2.0

从 `sudo prs → 9) 其他 → 1) 链式代理` 进入。当前菜单：

```text
1) 节点管理
2) Pool 管理
3) Chain 管理
4) 路由规则
5) 默认路由
6) 启用 / 禁用
7) 测试节点 / Chain
8) 查看当前拓扑
0) 返回
```

Nodes 是从受支持分享链接导入的上游；Pool 在单个 hop 内轮询节点；Chain 按顺序连接多个 hop。路由规则按菜单顺序匹配 CIDR、精确主机名或通配主机名，目标可为 DIRECT、BLOCK、Chain 或多 Chain 轮询。未命中规则时使用默认路由，新建 v2 状态默认 DIRECT。

Pool 和多 Chain 轮询不提供健康检查、自动故障切换或延迟选择。可通过 `7) 测试节点 / Chain → 3) 测试 Pool 内全部节点` 手动逐个排查，结果包含可用性、失败原因与耗时。单节点完整代理测试路径为 `7 → 1`，完整 Chain 为 `7 → 2`。

测试复用临时 shoes SOCKS5 入口，先执行 `shoes --dry-run`，再请求 `https://www.gstatic.com/generate_204`；HTTP 204 才算可用。临时配置权限 `0600`，测试结束即关闭临时进程并删除配置。测试只读，不切换线上出口、不修改 systemd、不自动剔除节点。

当前支持 SOCKS5、HTTP/HTTPS、Shadowsocks、VLESS TCP/TLS/Reality/WebSocket、Trojan TLS/WebSocket，以及 ping-rust 生成的 VMess WebSocket TLS 分享链接。Hysteria2、TUIC、WireGuard/WARP 缺少对应 shoes 客户端实现，会明确拒绝。HTTP、SOCKS5、Trojan 出口的 UDP 请求会失败，不会静默回退直连。当前 Hysteria2/TUIC 入站与全局 Chain 组合仍受安全限制。

修改 Chain 或路由时继续使用候选 dry-run、原子提交、systemd 激活与失败回滚。旧 `active_node` 状态在内存中迁移为单跳 Chain，读取不会改写文件；受引用的节点、Pool、Chain 不允许删除。

