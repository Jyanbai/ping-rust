# VLESS-XHTTP-REALITY

shoes v0.3.7 原生 XHTTP（SplitHTTP）放在 REALITY 目标内部，XHTTP 内承载 VLESS。无需自己的域名或证书；SNI 自动检测、密钥和 short_id 的生成沿用 REALITY。

```bash
sudo prs add vless-xhttp-reality
sudo prs add vless-xhttp-reality --port 443 --xhttp-path /my-path
```

也可进入 `9) 工具 → 2) 高级添加配置 → 15) VLESS-XHTTP-REALITY`。原有 1–14 项编号保持不变，主菜单不变。`generate vless-xhttp-reality` 同样接受 `--xhttp-path`。

默认 path 为 `/` 加 16 位安全随机小写十六进制；自定义 path 必须以 `/` 开头，只接受 ASCII 字母、数字、`/ - . _ ~`，拒绝空格、查询参数、片段和百分号编码。服务端固定 `mode: auto`。`2) 更改配置` 支持端口、SNI 和 path；更改 path 会使旧链接失效，确认默认 N，输入 `0` 返回。修改遵循 dry-run、原子提交、热重载或受控重启、失败回滚流程。

只支持 **v2rayN / Xray** 客户端。复制 `prs url` 的分享链接导入，或扫描 `prs qr` 的二维码，两者内容相同。`prs info` 显示 path 与 mode。链接包含 `security=reality`、`type=xhttp`、URL 编码的 path、`mode=auto` 和 REALITY 公钥/short_id，不含 `flow`。

默认 `auto` 模式下 REALITY 客户端走 **stream-one**；上游也支持 H2 下的 stream-up 和 packet-up。**XHTTP 不支持 Vision**：预设固定 `vision: false`，不提供 Vision 或 H2MUX 开关。Clash Meta / Mihomo（v1.19.33）、sing-box、NekoBox 导出一律拒绝：

```text
该客户端不支持 XHTTP，请用分享链接导入 v2rayN 或 Xray
```

公网监听建议显式配置 XHTTP 的 `limits`，按资源预算采用上游的公网部署建议；生成器不默认开启，也不默默替换客户端不支持的选项。具体限制字段、单位和配置示例请参照 [shoes v0.3.7 XHTTP 文档](https://github.com/cfal/shoes/blob/v0.3.7/docs/src/content/docs/zh-cn/protocols/xhttp.md)、[XHTTP 示例](https://github.com/cfal/shoes/blob/v0.3.7/examples/xhttp.yaml) 和 [配置类型](https://github.com/cfal/shoes/blob/v0.3.7/src/config/types/xhttp.rs)。这些链接固定到 v0.3.7；手动修改运行配置前请备份，并先执行 `shoes --dry-run` 校验。

新协议使用独立的 `VlessXhttpReality` state 结构；旧协议的序列化不变。v0.2.1 不认识该枚举，添加此协议后不能直接降级读取 state；只有显式添加此协议才会写出该结构，升级不会替换已有节点。降级前请用新版删除 XHTTP 节点并保留备份。
