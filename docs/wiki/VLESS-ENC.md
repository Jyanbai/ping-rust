# VLESS-ENC（开发分支，未发版）

菜单第 **14** 项，或运行 `sudo prs add vless-enc`。默认使用 x25519、native、0rtt、600s，Vision 默认关闭。密钥由已安装的 shoes v0.3.6 生成。

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

客户端请使用 CI 实测通过的 Xray **v26.6.27** 或 Mihomo **v1.19.33**；未验证更旧版本，不能据此推断其可用。Xray 已通过三种外观 × Vision 开关的 x25519 六种组合及一次 mlkem768；Mihomo 已通过 native/x25519 的 Vision 关闭和开启两种组合。结果和 run/job ID 见 主仓库的 `docs/VLESS_ENC_REPORT.md`。新增 VLESS-ENC 时，带完整来源记录、且二进制摘要仍匹配的 shoes v0.3.6 Release 可使用受验证热重载；来源未知或不匹配时使用现有受控重启流程。已有协议的 Release 重启策略保持不变。
