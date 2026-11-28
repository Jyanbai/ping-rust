# ping-rust v0.3.4

> 在 v0.3.3 基础上的安全与可靠性版本：sing-box 导出对自签 TLS 节点改为证书固定，修复 VMess-WS-TLS 在 sing-box 中无法连通，增删改及其他受管写入保留手工添加的 shoes 字段。不改变 shoes pin（v0.3.7）、受管协议、state 格式或状态兼容规则。发布以 tag 对应提交的全部 push 检查和 Release 门禁结果为准。

## 本版变更

- **sing-box 导出固定证书公钥**（#155、#184）：未提供 `--cert/--key` 的 TLS 节点（Hysteria2、TUIC、Trojan-TLS、VLESS-Vision、VLESS-WS、VMess-WS、AnyTLS）使用自签证书。导出 sing-box 时改为 `tls.certificate_public_key_sha256` 固定该节点叶证书的公钥，不再设置 `insecure`；证书文件缺失或损坏时明确报错，不回退为跳过校验。使用外部证书的节点保持系统信任链校验，不受影响。
- **修复 VMess-WS-TLS 无法连通**（#176、#179）：sing-box 在 TLS 下把 `security: auto` 解析为 `zero`，shoes 不接受；分享链接、二维码、Clash Meta、sing-box、NekoBox 统一导出 `aes-128-gcm`。服务端配置不变。
- **保留手工添加的 shoes 字段**（#145、#174、#182）：新增、编辑、删除、`socks5 secure`、链式代理规则更新、shoes 升级迁移和菜单补建节点文件，只修改目标条目，其他节点 ping-rust 不认识的字段（例如 VLESS-ENC 节点手工加的 `encryption_limits`）原样保留。备份恢复仍会用备份**整体替换** `/etc/shoes`（恢复前的目录另存为 `/etc/shoes.pre-restore-<时间>`），备份之后对任何节点做的修改都不会保留；本版只保证备份中的手工字段在恢复与补建节点文件时不再丢失。聚合配置与节点文件对同一节点不一致时拒绝提交，提示只含文件名、节点序号和脱敏字段路径。
- **菜单内自更新自动切换**（#168、#170）：更新中心“更新 ping-rust”成功后，按回车直接进入新版本菜单；切换失败时退出并提示重新运行 `sudo prs`。
- **`socks5 secure` 修复**：不再把其他服务在不相交具体地址上的同号端口当成冲突（#146、#178）；shoes 预检期间按 Ctrl-C 或收到 SIGTERM/SIGHUP 时清理含凭据的候选配置文件（#152、#183）。
- **CI 与流程**：七种自签 TLS 协议用固定 sing-box v1.14.2 做真实连通、错误凭据、证书校验和异钥证书四类验收，并纳入 PR 合并门禁与 Release 门禁（#156、#173、#175、#184）；修复多处 CI 偶发失败（#161、#164、#167）。不放宽任何门禁。

## 升级后需要你操作的事项

- **重新导出 sing-box 配置**：v0.3.4 只改变导出结果，已分发的旧配置仍是跳过证书校验。证书固定只在 sing-box JSON 导出中生效；“查看配置”里的分享链接和二维码**不会**启用固定。请用 `sudo prs` → 9) 工具 → 1) 导出客户端配置 → 选择 sing-box，或命令行 `sudo ping-rust export sing-box --server <VPS 公网域名或 IP> --profile <节点 UUID>`（只有一个节点时可省略 `--profile`；节点 UUID 可用 `prs info` 查看），把生成的 JSON 重新导入客户端。sing-box 客户端版本以 CI 实测的 **v1.14.2** 为准；更早版本未验证，可能不识别 `certificate_public_key_sha256`。
- **重新导出 VMess-WS-TLS 节点**：旧导出在 sing-box 中无法连通，升级后重新导出导入即可，无需改服务端。新版 VMess 分享链接带 `scy=aes-128-gcm`，**尚未升级的旧版 ping-rust 链式代理可能无法导入**，请两端都升级到 v0.3.4。个别域名和 WebSocket 路径很长的 VMess 节点，链接变长后可能不再生成终端二维码，可直接复制链接。
- **从 v0.3.3 在菜单内更新**：v0.3.3 的菜单不会自动切换，更新完成后请退出菜单，重新运行 `sudo prs`。v0.3.4 及以后在菜单内更新会自动切换。

## 已知问题

- **Clash Meta、分享链接 / 二维码、NekoBox 仍跳过证书校验**（#187）：这些格式对自签 TLS 节点仍导出 `skip-cert-verify` / `insecure=1` / `allowInsecure=1`，存在中间人风险，计划在 v0.3.5 按各客户端实测结果改为证书固定或明确拒绝。对安全有要求时请使用 sing-box 导出，或用 `--cert/--key` 提供真实证书。
- **`socks5 secure` 取消信号时序**（#186）：信号恰好在预检结束、提交开始的瞬间到达时，命令会完成提交并重启服务后再以信号码退出；配置不会半写。

以下客户端兼容范围沿用既有文档记录；实际结果以 tag 对应提交的 Actions 为准。

## 客户端兼容要求

- Reality 客户端：CI 实测 Xray **v25.5.16** 和 **v26.6.27** 可以连接，建议使用 Xray 25.5.16 及以上。更早的版本未验证，可能连不上（例如旧版 v2rayN 内置的 Xray），请先升级客户端及其 Xray 内核。
- Snell v3：Mihomo 只支持 `aes-128-gcm`。新节点默认改为 `aes-128-gcm`，已有节点不自动修改；已有的 chacha20 或 aes-256 节点若使用 Mihomo，需要手动修改 cipher 并重新导出配置。

## 升级与配置迁移

- 默认 shoes 版本为 **v0.3.7**。通配符路由规则在升级时自动迁移为 shoes v0.3.6 支持的格式；候选配置先验证，应用失败会回滚。
- 新版 ping-rust 搭配旧 shoes 时，修改配置会提示先升级 shoes。

先执行 `self-update` 更新 ping-rust：

```bash
sudo ping-rust self-update --version v0.3.4
```

命令行自更新成功后会退出。可用 `/usr/local/bin/shoes --version` 检查已安装的内核版本。已使用 shoes v0.3.7 时，只需更新 ping-rust；不要执行内核更新，以免重装同版本并重启共享的 `shoes.service`。

仅在已安装的 shoes 低于 v0.3.7 且确需升级时，才在自更新成功后执行以下命令；升级会重启正在运行的 `shoes.service`，请安排维护窗口：

```bash
sudo ping-rust update --method release
```

安装了更新但未经验证的 shoes 版本时，请按工具提示决定是否显式允许降级。

## VLESS-ENC 兼容要求

- 在统一协议菜单中选择 VLESS-ENC，或执行 `sudo prs add vless-enc`。默认使用 x25519、native、0rtt、600s，Vision 默认关闭。
- 原生 TCP，**不套 TLS 或 Reality**，安全性完全依赖 VLESS Encryption。支持 native/xorpub/random 外观、x25519/mlkem768 认证和可选 Vision；random 外观会关闭 TCP splice。
- 未开启 Sudoku 时支持 Mihomo 导出；**不支持 sing-box 或 NekoBox**，不支持链式出口或 H2MUX。
- 客户端版本以 **CI 实测**为准：Xray **v26.6.27**、Mihomo **v1.19.33**。Xray 已验证 x25519 的三种外观与 Vision 开关六种组合，以及 native/mlkem768/Vision 关闭；Mihomo 已验证 native/x25519 的 Vision 关闭和开启。其他版本或组合未验证。
- 开启 Sudoku 后需要支持 Xray FinalMask Sudoku 的客户端；Mihomo、sing-box、NekoBox 导出均拒绝。XHTTP 同样仅支持 Xray / v2rayN，不支持 Vision 或 H2MUX。
- 更改外观、认证或重新生成密钥后，需要重新导入客户端配置。mlkem768 链接较长，可能无法通过二维码导入。

## 降级限制

添加 VLESS-ENC 节点后**不能降级到 v0.2.x**，旧版无法读取包含该节点的管理状态。若必须降级，请先在 v0.3.4 中删除全部 VLESS-ENC 节点并备份配置，再执行降级。删除 VLESS-ENC 节点后再降级的其他行为未验证。

XHTTP、VLESS-Sudoku 节点保存在独立 state 扩展中，v0.2.1 可忽略扩展读取原有节点，但不支持管理这些新协议或包含它们的运行配置。降级前应先用新版删除新协议节点并备份配置，不能将“旧版能读取原有节点”理解为完整降级兼容。
