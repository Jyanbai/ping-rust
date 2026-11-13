# SNI 选择

Reality 和 ShadowTLS v3 的握手目标会影响节点可用性。以下三种方式由用户选择；升级和检测都不会自动替换已有 SNI，也没有后台或定时检测、在线更新名单。

| 方式 | 检测范围 | 适用情况 |
| --- | --- | --- |
| 自动选择（默认） | 内置名单，DNS、TCP、TLS 1.3、h2、公共根证书及域名校验；每个候选整体 3 秒 | 首次部署、零输入安装。取最快至多三个通过者随机选择，不发 HTTP 请求 |
| 检测与推荐 | 上述握手，加 HTTPS GET 和真实 shoes 本机预检 | 希望自己挑目标、排除跨主机跳转或 Cloudflare、验证这台 VPS 上的实际兼容性 |
| 手动输入 | 一次握手检测，失败只警告，仍使用指定值 | 已自行验证目标，或需要保留特定站点；输入者承担失败风险 |

快速和高级添加均可在 `7) AnyTLS` 内选择 TLS / REALITY，在 `3) Shadowsocks` 内选择 SS2022 / ShadowTLS v3。AnyTLS TLS 不探测 SNI；REALITY 不需要 TLS 证书，且应使用 sing-box 导出（没有标准分享 URI，Mihomo / NekoBox 不支持）。

新建 VLESS Reality、Trojan Reality、AnyTLS Reality 或 ShadowTLS v3 节点时，SNI 一步会显示以上三项。检测与推荐提供默认名单、现有节点 SNI、用户输入、导入本地扫描 CSV 和 VPS 扫描五种来源。所有来源使用同一检测流程。

## 只检测，不改配置

```sh
# 默认名单和现有节点的 SNI
prs sni check

# 给定域名，用 Reality 本机预检
prs sni check www.example.com other.example.com

# 使用 ShadowTLS v3 服务端和客户端预检
prs sni check www.example.com --protocol shadow-tls
```

检测按顺序执行，失败即停止该候选的后续步骤：

1. 经证书验证的 TLS 1.3 + h2 握手，整体最多 3 秒。
2. 对 `https://<域名>/` 发一次 GET，最多 5 秒，不跟随跳转，不读取响应体。跨主机的 3xx、无效跳转地址、`cf-ray` 或 `server: cloudflare` 会被拒绝；同主机跳转会标明。
3. 在权限 0700 的临时目录里写入权限 0600 的配置，新生成独立凭据；启动只监听 `127.0.0.1` 随机端口的 shoes 服务端和 SOCKS5 客户端，经代理请求 `https://www.gstatic.com/generate_204`，必须返回 204。含 dry-run、启动和请求，整体最多 10 秒。Reality 使用 Reality 服务端/客户端，ShadowTLS 使用 ShadowTLS v3 + SS2022。
4. 扫描来源还会排除没有具体 ORIGIN 的通配符证书，以及 DNS 解析结果不在实际扫描 /24 内的域名。DNS 过滤最多 3 秒。

失败会给出中文原因，例如缺少 shoes 时先运行 `prs install`。临时进程与文件在正常结束、失败、超时或 Ctrl+C 时清理，不改变已有服务。测试可用 `PING_RUST_SNI_TEST_URL`（兼容 `PING_RUST_CHAIN_TEST_URL`）覆盖 204 探测地址。

结果表显示域名、来源、握手耗时、TLS1.3/h2、跳转、Cloudflare、shoes 预检、结论和说明。通过者在前，按握手耗时升序。未通过前一步的后续列标为“未检测”。本机预检通过仅说明当时 VPS 到目标及代理数据面可用，不能保证外部客户端的路由和防火墙可达性。

## 在自己电脑上运行 RealiTLScanner

推荐在自己电脑扫描，再将 CSV 上传到 VPS。菜单“在自己电脑上扫描并导入 CSV”会检测 VPS IPv4 并输出可复制命令。下面使用文档保留地址，运行时换成自己的 VPS IPv4：

```sh
RealiTLScanner -addr 203.0.113.42/24 -port 443 -thread 5 -timeout 5 -out out.csv
scp out.csv user@vps.example.com:~/out.csv
```

需要自行从 [XTLS/RealiTLScanner v0.2.3](https://github.com/XTLS/RealiTLScanner/releases/tag/v0.2.3) 安装适合自己电脑的版本。该工具是采用 **MPL-2.0** 许可的 XTLS 项目。ping-rust 不修改、不再分发该二进制。

在 VPS 上导入；必须填写 CSV 实际扫描的 IPv4 /24，不能填其他网段来绕过过滤：

```sh
prs sni check --csv ~/out.csv --subnet 203.0.113.0/24
prs sni check --csv ~/out.csv --subnet 203.0.113.0/24 --protocol shadow-tls
```

也可在菜单输入上传后的 CSV 路径及扫描网段，检测后输入通过条目的编号。解析支持带引号、含逗号的 issuer 字段；应保留原始表头和 UTF-8 编码。

同 ASN 的证书是 Reality 的目标选择建议；扫描附近 /24 只能提供候选，不能证明 ASN、站点规模或长期稳定性。DNS 不在该 /24 的结果表示邻居机器平时并不服务此域名，会被跳过。

## 可选的 VPS 扫描

**RealiTLScanner 作者建议在本地电脑运行，云端扫描可能导致 VPS 被标记。部分服务商条款禁止扫描。请优先选择本地扫描后导入 CSV。**

```sh
# 终端显示风险后，只有明确输入 y 才开始，默认 N
prs sni scan

# 非终端运行必须明确接受风险，否则报错退出，不读取 stdin
prs sni scan --yes
```

仅支持 Linux amd64、arm64 及带 IPv4 的 VPS；仅 IPv6 的 VPS 请使用默认名单、输入域名或导入其他 IPv4 网段的 CSV。

程序临时下载固定 **v0.2.3**，以固定 SHA-256 校验通过后才执行，下载和扫描整体最多 5 分钟，显示进度。扫描参数为 VPS IPv4 `/24`、443、5 线程、5 秒单目标超时。程序不常驻安装扫描器，用完删除。下载失败、摘要不符、超时均不影响已有配置。扫描结束后，候选仍需通过全部检测，扫描命令只输出结果。

## 选择和应用

新建节点检测后输入通过条目的编号，将其作为这次新建节点的 SNI；输入 `0` 返回候选来源，再返回可重新选择 SNI 方式。

已有节点在主菜单 `2. 更改配置` 选中节点后使用“检测与推荐 SNI”。选择后还需再次确认，默认不应用；确认后先将配置备份到 `/var/backups/ping-rust-sni-*.tar.gz`，再走原有 dry-run、原子提交、热重载或受控重启、失败回滚流程。默认的 `<旧 SNI>:443` 目标会同步更新，自定义目标保留。更改后需同步客户端配置和分享链接。

扫描来源每条结果都会提示以下风险：站点规模未知，每条代理连接都会对它握手一次；该站宕机或限流，节点就连不上。扫描结果里常有别人的代理节点，选择前请在浏览器打开，确认是正常网站。一次通过不代表永久可用。
