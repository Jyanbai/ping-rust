# shoes pin 升级检查清单

升级 `SHOES_SCHEMA_REVISION` 前，先在独立分支完成以下检查。生产 pin 保持不变，直到全部证据可复现。

1. 从上游取得目标 commit，确认 commit SHA、版本和 `cargo build --locked` 可重复；同步 `src/installer.rs` 与 workflow 中的 pin，绝不使用浮动分支。
2. 运行 `shoes --dry-run`：逐个检查 `examples/*.yaml`、生成的十三种受管协议、联合配置、Chain/Pool 路由和 ShadowTLS/H2MUX 形状。
3. 检查 watcher 行为：配置文件必须以同一目录内的原子替换完成；替换后 watcher 能重新打开新 inode，连续两次替换都能更新监听；文件锚点通知不能被忽略或去抖到超时。
4. 执行 hot reload acceptance：新增节点、修改监听端口、删除非最后节点时，服务保持 active、MainPID 不变、旧监听消失且新监听出现；凭据修改仍走受控重启；超时或崩溃必须恢复旧配置和服务状态。
5. 执行 Chain systemd acceptance：Pool、multi-hop Chain、规则路由以及在线/离线 Pool 手动探针都必须保持无直连回退。
6. 检查 `shoes --version`、systemd unit、日志和导出客户端的兼容性；确认 state 文件格式无需迁移，或补充向后兼容迁移测试。
7. 在 PR 中记录目标 SHA、workflow 名称、测试名和结果。任何未实际执行的项目标为“未验证”，不得写成通过。

## 热重载依赖的 watcher 行为

ping-rust 依赖固定 shoes watcher 监听聚合配置文件的内容变化，并能在原子替换后重新打开文件。ping-rust 同时维护文件锚点通知和 MainPID/监听集合验证；只要 watcher 不重新加载新 inode、丢失锚点事件、或无法在短时间内应用新监听，ping-rust 就会进入失败回滚路径。该依赖只适用于可观察的监听变更，不能证明凭据等不可观测字段已经生效。
