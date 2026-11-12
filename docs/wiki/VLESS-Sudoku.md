# VLESS-Sudoku（无加密）

**VLESS-Sudoku 没有任何加密和认证。** Sudoku 只是混淆，下行打包编码没有密钥，上行置换种子空间有限；普通 VLESS 的 UUID、目标地址、非 HTTPS 内容都能在链路上被还原。需要加密时请使用 VLESS-ENC + Sudoku 或 VLESS-REALITY。

shoes v0.3.7 的 `sudoku_mask` 是 Xray FinalMask Sudoku TCP 外层混淆，不是独立隧道，也不是 Mihomo 的 `sudoku` 协议。最外层是掩码，最内层是普通 VLESS；没有 encryption/decryption、Vision、TLS 或 REALITY。

高级协议列表的 **16) VLESS-Sudoku（无加密）** 在已有 1–15 之后，主菜单不变。添加前显示安全说明和代价，然后询问：

```text
仍要添加无加密的 VLESS-Sudoku 节点？ [y/N]（输入 0 返回）：
```

默认 N；0 返回。CLI 不读取 stdin，添加时安全说明写到 stderr：

```sh
sudo prs add vless-sudoku --server-address 203.0.113.10
sudo prs add vless-sudoku --sudoku-ascii ascii --sudoku-padding-min 0 --sudoku-padding-max 10
```

Sudoku 始终开启，无需 `--sudoku`。复用 VLESS-ENC 的 Sudoku 参数：`--sudoku-password` 按原样使用，不 trim；省略时安全随机生成 24 位字母数字。`--sudoku-ascii` 可选 `prefer-entropy`（默认）、`entropy`、`prefer-ascii`、`ascii`，配置和链接用下划线形式。padding 默认 0–0，范围 0–100，max 不得小于 min。不开放自定义布局表。

上行约 4 倍（无 padding），10% padding 约 4.5 倍，单次写入最多约 9 倍；下行约 1.33 倍。关闭原始 TCP splice，每条连接多占约 64 KiB 缓冲。只支持 TCP，没有 UDP/QUIC 掩码；TCP 内转发的 UDP 仍可用。客户端需要 **Xray ≥ v26.3.27** 或基于它的 v2rayN。

分享链接和二维码一致，使用 `encryption=none&security=none&type=tcp&fm=`，`fm` 是 URL 编码的紧凑 `streamSettings.finalmask` JSON。Xray 配置为 `network: raw`、`security: none`。Clash Meta / Mihomo、sing-box、NekoBox 导出均拒绝：

```text
该客户端导出不支持 Xray FinalMask Sudoku，请用分享链接导入 v2rayN 或 Xray ≥ v26.3.27
```

`prs info` 明示“加密：无”与 Sudoku ascii、padding 范围。菜单“2 更改配置”支持修改端口、ascii、padding 和重新生成 Sudoku 密码；密码重置提示旧分享链接失效，默认 N。padding 编辑先确认（0 返回），输入值时 0 是合法百分比；无效范围会重新询问。变更走原有 dry-run、原子提交、服务激活与失败回滚流程。

新节点写到 state 顶层 `sudoku_profiles` 扩展，记录绝对位置并保持与 XHTTP 等协议混排的顺序。已有协议输出不变，v0.2.1 可忽略扩展并读取旧节点；降级管理配置前先用新版删除新协议节点并备份。配置和 state 写入权限 0600。

CI 验收脚本覆盖 prefer_entropy、ascii 的 Xray 通流；错误掩码密码、完全不带掩码的普通 VLESS 客户端必须失败。真实通流结果以对应提交的 Actions 为准。

格式依据：[shoes v0.3.7 Sudoku 文档](https://github.com/cfal/shoes/blob/v0.3.7/docs/src/content/docs/zh-cn/protocols/sudoku.md)。
