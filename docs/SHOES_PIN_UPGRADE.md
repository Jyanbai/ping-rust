# shoes pin 升级检查清单

目标 pin：shoes v0.3.7，commit `ee44a397e6850193e86a1ae66639f037f963822d`（上一个 pin：v0.3.6，`3737e07467387044e677ae7cf8b1c16d291f1b68`）。

1. 在独立分支同步 `src/installer.rs` 与所有 workflow 的 Release tag、源码 commit、下载 URL 和 SHA-256 digest。
2. 用 `shoes --version` 记录实际运行版本；用 `shoes --dry-run` 检查 `examples/*.yaml`、生成协议、Chain、Pool、ShadowTLS 和 H2MUX。
3. v0.3.6 watcher 监听配置父目录，源码中的去抖窗口为 5 秒（背景资料约称 3 秒）。配置必须从同一目录原子替换；不要再创建或触碰额外锚点文件，因为它会制造重复事件。
4. Hot Reload acceptance 要验证新增节点、修改端口、删除非最后节点：服务保持 active，MainPID 不变，旧监听消失且新监听出现。超时必须恢复旧配置和服务状态，并从 journal 统计实际重载次数。
5. Reality 使用 Xray 26.x 客户端逐个握手默认六个 SNI。文档说明客户端至少需要 Xray 25.5.16，链式代理 Reality 出口不再模拟 Chrome 指纹。
6. Snell v3 使用 Mihomo 对三个 cipher 各做一次真实连接测试，并记录 v0.3.3 salt 长度变化对旧节点的迁移影响。
7. 兼容夹具从 v0.2.7 升级到 v0.3.6 走 dry-run；Update Center 从 v0.2.7 升级时应判定为升级，配置文件保持不变，服务正常运行。
8. `global_limits` 继续省略，保持不限制的现有语义；需要限流时再显式写入。

v0.3.6 对规则通配主机名不再接受旧的 `masks: '*.example.com'` 字符串；生成配置使用 `masks: {domain_pattern: ['*.example.com']}`。兼容夹具中的旧 UUID 也已统一为 version 4/标准 variant，满足 v0.3.6 的严格校验。

## v0.3.7 升级记录

- 上游 v0.3.6..v0.3.7 共 46 个提交，配置模块大幅重写（compiler / lower / resolved），schema 兼容性以 CI 的 dry-run、兼容夹具和验收结果为准。
- `src/process.rs` 的 `RELOAD_DEBOUNCE` 仍为 5 秒；`src/reality/reality_target_flight.rs` 与 v0.3.6 完全相同。
- `--version` 输出变为 `shoes <版本>` + `target:` + `compiler:` 三行（上游 #282）；ping-rust 只取首行，记录的版本来自 `SHOES_SCHEMA_VERSION` 常量。从源码编译时版本为 `0.3.7+g<commit>`。
- `rust-version` 仍为 1.99.1，源码编译的工具链要求不变。
- 必需检查名 "Debian 12 v0.2.2 to shoes v0.3.6 migration" 是规则集里登记的名称，未改名；实际迁移目标是当前 pin。

## watcher 验收结论（v0.3.6）

shoes v0.3.6 监听聚合配置的父目录并对事件去抖；上游源码 `RELOAD_DEBOUNCE` 为 5 秒。ping-rust 使用同目录原子替换，等待时间为 10 秒，覆盖该窗口。旧的硬链接锚点通知已移除，避免临时文件和候选文件写入造成额外重载。最终结果以 MainPID、监听集合和 journal 计数为证据；未实际运行的外部握手、Mihomo 连接或 Update Center 路径必须标记为“未验证”。
