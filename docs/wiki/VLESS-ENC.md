# VLESS-ENC

快速和高级添加菜单第 **5) VLESS-ENC** 项，或运行 `sudo prs add vless-enc`。默认使用 x25519、native、0rtt、600s，Vision 默认关闭。密钥由已安装的 shoes 生成。

**此预设不套 TLS 或 Reality；安全性完全依赖 VLESS Encryption。** 服务端为原生 TCP，客户端为 `security=none&type=tcp`。decryption 只写入权限 0600 的节点 profile 和聚合运行配置；state、分享链接及客户端导出仅保存客户端 encryption。

| 外观 | 区别 |
| --- | --- |
| native | 原生 VLESS Encryption 握手外观，默认选项 |
| xorpub | 对公钥采用 XOR 外观处理 |
| random | 随机外观；会关闭 TCP splice |

添加和更改配置均提供外观、x25519/mlkem768 认证、Vision 和重新生成密钥。mlkem768 链接约 1.6 KB，二维码可能无法扫描；链接超过 1200 字节时终端不生成二维码，并说明原因。更改外观、认证或重新生成密钥后必须更新客户端链接。

```bash
sudo prs add vless-enc
sudo prs add vless-enc --encryption-mode xorpub --vision
sudo prs add vless-enc --encryption-auth mlkem768
```

支持 Mihomo 的 `encryption` 字段，Vision 开启时同时导出 `flow: xtls-rprx-vision`。**不支持 sing-box 或 NekoBox 导出，不支持用作链式出口，也不提供 H2MUX 开关。**

客户端请使用 CI 实测通过的 Xray **v26.6.27** 或 Mihomo **v1.19.33**；未验证更旧版本，不能据此推断其可用。Xray 已通过三种外观 × Vision 开关的 x25519 六种组合及一次 mlkem768；Mihomo 已通过 native/x25519 的 Vision 关闭和开启两种组合。结果和 run/job ID 见主仓库的 `docs/VLESS_ENC_REPORT.md`。VLESS-ENC 与其他协议使用相同的热重载资格：固定 pin 构建支持热重载，GitHub Release 来源使用受控重启。

### 可选的 Sudoku 外观

默认关闭，已有节点升级后不会自动开启。添加时用 `--sudoku`，或在菜单中回答“启用 Sudoku 外观？”（默认 N，输入 0 返回）。例如：

```sh
sudo prs add vless-enc --sudoku
sudo prs add vless-enc --sudoku --sudoku-ascii ascii --sudoku-padding-min 0 --sudoku-padding-max 10 --vision
```

`--sudoku-password` 省略时安全随机生成 24 位字母数字；显式密码按原样比较，不做 trim。`--sudoku-ascii` 可选 `prefer-entropy`（默认）、`entropy`、`prefer-ascii`、`ascii`，服务端及分享链接使用下划线形式。padding 默认 `0–0`，范围 `0–100`；max 小于 min 会报错。使用默认熵布局，不开放 `custom_tables`。

Sudoku 是混淆，不是加密或认证，传输安全仍由 VLESS Encryption 提供。上行约 4 倍（无 padding），10% padding 约 4.5 倍，单次写入最多约 9 倍；下行约 1.33 倍。关闭原始 TCP splice，每条连接多占约 64 KiB 缓冲。只支持 TCP，没有 UDP/QUIC 掩码；在 TCP 内转发的 UDP 仍可用。

客户端需要 **Xray ≥ v26.3.27** 或 v2rayN 等基于它的客户端。分享链接以 URL 编码的紧凑 JSON `fm=` 携带整个 `streamSettings.finalmask` 对象，二维码内容与链接相同。开启后拒绝 Clash Meta / Mihomo、sing-box 和 NekoBox 导出，并提示：“该客户端导出不支持 Xray FinalMask Sudoku，请用分享链接导入 v2rayN 或 Xray ≥ v26.3.27”。关闭时保持原导出行为。

在“2 更改配置”中可开启或关闭 Sudoku，或重新生成 Sudoku 密码。重新生成密码会使旧分享链接失效，确认默认 N；变更沿用 dry-run、原子提交和失败回滚流程。`prs info` 显示 ASCII 模式和 padding 范围，不额外显示服务端 decryption。

格式参考：[shoes v0.3.7 文档](https://github.com/cfal/shoes/blob/v0.3.7/docs/src/content/docs/zh-cn/protocols/sudoku.md)、[shoes 与 Xray 互通测试](https://github.com/cfal/shoes/blob/v0.3.7/tests/cases/optional_peer/vless_encryption/sudoku_mask.rs)、[v2rayN 分享链接处理](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/BaseFmt.cs)。
