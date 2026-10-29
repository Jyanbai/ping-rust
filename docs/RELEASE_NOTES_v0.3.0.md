# ping-rust v0.3.0

## 客户端兼容要求

- Reality 客户端需要 Xray **25.5.16 及以上**。旧版 v2rayN 内置的 Xray 版本过低时会连不上 Reality，请先升级客户端及其 Xray 内核。
- Snell v3：Mihomo 只支持 `aes-128-gcm`。新节点默认改为 `aes-128-gcm`，已有节点不自动修改；已有的 chacha20 或 aes-256 节点若使用 Mihomo，需要手动修改 cipher 并重新导出配置。

## 升级与配置迁移

- 默认 shoes 版本为 **v0.3.6**。通配符路由规则在升级时自动迁移为 shoes v0.3.6 支持的格式；候选配置先验证，应用失败会回滚。
- 新版 ping-rust 搭配旧 shoes 时，修改配置会提示先升级 shoes。
- 升级顺序：先执行 `self-update` 更新 ping-rust，再执行 `update` 把 shoes 升级到 v0.3.6：

```bash
sudo ping-rust self-update --version v0.3.0
sudo ping-rust update --method release
```

自更新成功后旧进程会退出，请重新运行 ping-rust，再执行第二条命令。安装了更新但未经验证的 shoes 版本时，请按工具提示决定是否显式允许降级。

## 新增 VLESS-ENC 预设

- 菜单第 **14** 项，或执行 `sudo prs add vless-enc`。默认使用 x25519、native、0rtt、600s，Vision 默认关闭。
- 原生 TCP，**不套 TLS 或 Reality**，安全性完全依赖 VLESS Encryption。支持 native/xorpub/random 外观、x25519/mlkem768 认证和可选 Vision；random 外观会关闭 TCP splice。
- 支持 Mihomo 导出；**不支持 sing-box 或 NekoBox**，不支持链式出口或 H2MUX。
- 客户端版本以 **CI 实测**为准：Xray **v26.6.27**、Mihomo **v1.19.33**。Xray 已验证 x25519 的三种外观与 Vision 开关六种组合，以及 native/mlkem768/Vision 关闭；Mihomo 已验证 native/x25519 的 Vision 关闭和开启。其他版本或组合未验证。
- 更改外观、认证或重新生成密钥后，需要重新导入客户端配置。mlkem768 链接较长，可能无法通过二维码导入。

## 降级限制

添加 VLESS-ENC 节点后**不能降级到 v0.2.x**，旧版无法读取包含该节点的管理状态。若必须降级，请先在 v0.3.0 中删除全部 VLESS-ENC 节点并备份配置，再执行降级。
