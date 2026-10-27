# shoes v0.3.6 升级报告（B 阶段）

## 范围

本阶段只升级 shoes 内核来源和兼容层，不新增 VLESS Encryption，不合并、不发版、不推 tag。

- Release tag：`v0.3.6`
- 上游 commit：`3737e07467387044e677ae7cf8b1c16d291f1b68`
- x86_64 musl 资产 SHA-256：`d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707`
- 上游源码的 `RELOAD_DEBOUNCE`：5 秒
- ping-rust `HOT_RELOAD_TIMEOUT`：10 秒

## 实际验证矩阵

所有 Rust 构建和测试均在 bero 完成，本机没有运行 cargo 编译或测试。

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 通过 | `ping-rust-v036-fmt-5`，退出码 0，0.39 秒，峰值 55,876 KB |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 | `ping-rust-v036-clippy-7`，退出码 0，3.80 秒，峰值 432,660 KB |
| `cargo test --locked` | 通过 | `ping-rust-v036-test-10`，207 passed、0 failed、2 ignored，退出码 0 |
| Release digest、`shoes --version` | 通过 | `shoes 0.3.6`，资产 digest 校验通过 |
| upstream examples dry-run | 通过 | 20 个 `examples/*.yaml`，退出码 0 |
| 兼容与 Chain 夹具 dry-run | 通过 | 18 个 YAML 夹具，退出码 0；单 profile 夹具按 v0.3.6 顶层数组格式包装后验证 |
| GitHub Actions systemd / 链式代理验收 | 通过 | draft PR #36 的默认 Release、source matrix（Release/pin）、dry-run、多发行版和链式代理 jobs 全部通过 |
| v0.2.1 backward-compat 读取新状态 | 通过 | 旧版本读取新配置和 exports 通过；比较器只允许版本探针的已知差异 |
| Xray 26.x 外部 Reality 六个 SNI 握手 | 未验证 | 本阶段未运行外部客户端 |
| Mihomo 三种 Snell cipher 实际连通 | 未验证 | 本阶段未运行外部客户端 |
| Update Center v0.2.7 → v0.3.6 | 未验证 | 本阶段未运行实机升级 |

直接用 v0.2.7 二进制重跑的对照项没有执行，避免把静态兼容推断写成运行结果。现有 ping-rust 单元和夹具测试在 v0.3.6 目标上通过。

## 兼容性和破坏性变化

1. 默认 Release 和源码 pin 已同步到 v0.3.6；Update Center 的 `installed_version` 改为执行 `shoes --version`，显示内核真实版本。
2. v0.3.6 的规则解析器拒绝旧的 `masks: '*.example.com'`。Chain 规则现在写成 `masks: {domain_pattern: ['*.example.com']}`；已有配置会在候选配置生成时转换。
3. v0.3.6 对 UUID 的 version/variant 校验更严格。兼容夹具中的历史非标准 UUID 已统一为 version 4 和标准 variant；新生成节点本来就使用随机 version 4 UUID。用户若保留外部手工写入的非标准 UUID，需要重新生成凭据。
4. v0.3.3 起 Snell salt 长度变化，影响 `aes-128-gcm`、`aes-256-gcm` 和默认的 `chacha20-ietf-poly1305`。升级后用 Mihomo 分别测试；失败时重新生成密码并替换客户端配置，不要混用旧密码和新 cipher。
5. REALITY 使用 rustls 实现；客户端要求 Xray 25.5.16 及以上。链式代理的 Reality 出口不再模拟 Chrome 指纹。
6. `global_limits` 继续省略。这样保持现有“不限制”语义，不给老用户引入隐式限流；需要限制时再由用户显式写入 YAML。

## 热重载结论

shoes v0.3.6 监听配置父目录，事件静默窗口为 5 秒。ping-rust 等待 10 秒，满足超时大于去抖窗口的前提；候选配置仍先 dry-run，再通过同目录原子替换提交。

旧的硬链接锚点通知机制已移除。新 watcher 已覆盖创建、修改和删除事件，继续触碰额外锚点会把临时文件或候选文件写入变成额外事件，可能重复重载。workflow 已加入 journal 中 `Servers ready` 的单次增量检查，并对新增、改端口、删除非最后节点检查 MainPID 不变和监听集合变化。draft PR #36 的 GitHub Actions 已通过这些 gate。

## bero 磁盘记录

清理范围仅为 `/home/agent/cargo-target`，使用 `bero-root` 执行；没有清理其它缓存或数据。

| 时点 | target 清理前 | `/` 可用空间清理前 | 清理后 target | `/` 可用空间清理后 |
| --- | ---: | ---: | ---: | ---: |
| 第一次构建前 | 1,383,747,584 B | 4,278,104,064 B | 0 B | 5,661,851,648 B |
| 测试退出码 75 后 | 1,374,760,960 B | 4,268,130,304 B | 0 B | 5,642,891,264 B |
| clippy 退出码 75 后 | 1,352,843,264 B | 4,289,314,816 B | 0 B | 5,642,158,080 B |
| 后续测试退出码 75 后 | 1,377,378,304 B | 4,264,644,608 B | 4,096 B | 5,642,018,816 B |

最后一次远端任务结束时：target 为 1,030,664,192 B，`/` 可用空间为 4,610,191,360 B，仍高于 4 GiB 停止线。

## 建议

- 后续安排 Xray、Mihomo 和 Update Center 实机验收；这些项目当前仍标记为未验证。
- C 阶段若继续扩展协议预设，应沿用 v0.3.6 的 typed rule 写法，并为新增客户端连接测试单独留证据。
