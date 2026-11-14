# ping-rust v0.3.2

> 在 v0.3.1 基础上的修复版本：不改变 shoes pin（v0.3.7）、受管协议、state 格式或状态兼容规则。发布以 tag 对应提交的全部 push 检查和 Release 门禁结果为准。

## 本版变更

- **自动升级不支持 Sudoku 的 shoes 内核**（#112）：实际受管的 shoes 可能仍是旧版本，会拒绝 `sudoku_mask`。添加或修改仍需 Sudoku 的节点时，先对 `/usr/local/bin/shoes` 做有界 dry-run 能力检测，不兼容时沿用现有固定 Release 升级事务升级到 v0.3.7，下载后、替换前再次验证能力；删除或关闭最后一个 Sudoku 节点不要求升级。保留 digest 校验、未知来源与降级保护以及迁移、配置、服务的失败回滚。无效的修改请求在升级前先校验，不会留下升级、迁移或重启。
- **统一终端菜单与返回行为**（#114）：主菜单按“协议 - 端口”显示节点；数字空输入停留，无效输入统一提示“无效序号！”；添加、查看及常规操作完成后在结果页回车返回主菜单，不再退出。首次默认部署的连接信息、二维码或失败原因在主菜单清屏前保留到回车确认；启动检查失败的诊断与恢复指引在每次清屏后仍显示；菜单导出 NekoBox 时恢复 H2MUX 客户端偏好丢失提示。`prs info` 输出保持与 v0.2.1 兼容。
- **依赖安全**（#117）：quinn-udp 升级到 0.5.16，修复 RUSTSEC-2026-0538；未添加任何审计忽略项。
- **CI 与流程**：PR 合并门禁和 Release 门禁支持显式步骤别名（#118），增加 Agent Pipeline 规划与独立审查规则（#115、#116），调整 linguist 统计（#109）。不放宽任何门禁。

以下客户端兼容范围沿用既有文档记录，本次未改变客户端导出逻辑；实际结果以 tag 对应提交的 Actions 为准。

## 客户端兼容要求

- Reality 客户端：CI 实测 Xray **v25.5.16** 和 **v26.6.27** 可以连接，建议使用 Xray 25.5.16 及以上。更早的版本未验证，可能连不上（例如旧版 v2rayN 内置的 Xray），请先升级客户端及其 Xray 内核。
- Snell v3：Mihomo 只支持 `aes-128-gcm`。新节点默认改为 `aes-128-gcm`，已有节点不自动修改；已有的 chacha20 或 aes-256 节点若使用 Mihomo，需要手动修改 cipher 并重新导出配置。

## 升级与配置迁移

- 默认 shoes 版本为 **v0.3.7**。通配符路由规则在升级时自动迁移为 shoes v0.3.6 支持的格式；候选配置先验证，应用失败会回滚。
- 新版 ping-rust 搭配旧 shoes 时，修改配置会提示先升级 shoes。
- 升级顺序：先执行 `self-update` 更新 ping-rust，再执行 `update` 把 shoes 升级到 v0.3.7：

```bash
sudo ping-rust self-update --version v0.3.2
sudo ping-rust update --method release
```

自更新成功后旧进程会退出，请重新运行 ping-rust，再执行第二条命令。安装了更新但未经验证的 shoes 版本时，请按工具提示决定是否显式允许降级。

## VLESS-ENC 兼容要求

- 在统一协议菜单中选择 VLESS-ENC，或执行 `sudo prs add vless-enc`。默认使用 x25519、native、0rtt、600s，Vision 默认关闭。
- 原生 TCP，**不套 TLS 或 Reality**，安全性完全依赖 VLESS Encryption。支持 native/xorpub/random 外观、x25519/mlkem768 认证和可选 Vision；random 外观会关闭 TCP splice。
- 未开启 Sudoku 时支持 Mihomo 导出；**不支持 sing-box 或 NekoBox**，不支持链式出口或 H2MUX。
- 客户端版本以 **CI 实测**为准：Xray **v26.6.27**、Mihomo **v1.19.33**。Xray 已验证 x25519 的三种外观与 Vision 开关六种组合，以及 native/mlkem768/Vision 关闭；Mihomo 已验证 native/x25519 的 Vision 关闭和开启。其他版本或组合未验证。
- 开启 Sudoku 后需要支持 Xray FinalMask Sudoku 的客户端；Mihomo、sing-box、NekoBox 导出均拒绝。XHTTP 同样仅支持 Xray / v2rayN，不支持 Vision 或 H2MUX。
- 更改外观、认证或重新生成密钥后，需要重新导入客户端配置。mlkem768 链接较长，可能无法通过二维码导入。

## 降级限制

添加 VLESS-ENC 节点后**不能降级到 v0.2.x**，旧版无法读取包含该节点的管理状态。若必须降级，请先在 v0.3.2 中删除全部 VLESS-ENC 节点并备份配置，再执行降级。删除 VLESS-ENC 节点后再降级的其他行为未验证。

XHTTP、VLESS-Sudoku 节点保存在独立 state 扩展中，v0.2.1 可忽略扩展读取原有节点，但不支持管理这些新协议或包含它们的运行配置。降级前应先用新版删除新协议节点并备份配置，不能将“旧版能读取原有节点”理解为完整降级兼容。
