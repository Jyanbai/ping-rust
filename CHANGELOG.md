# 更新日志

## 0.3.4

- TLS 证书固定（sing-box）：自签证书的 TLS 节点导出 sing-box 配置时改用 `certificate_public_key_sha256` 固定叶证书公钥，不再设置 `insecure`；外部 `--cert/--key` 节点不变。Clash Meta、分享链接和 NekoBox 仍为跳过证书校验，计划在 v0.3.5 处理（#155、#184、#187）。
- 修复 VMess-WS-TLS：sing-box 在 TLS 下 `security: auto` 实际使用 `zero`，被 shoes 拒绝；所有客户端格式统一导出 `aes-128-gcm`（#176、#179）。
- 保留手工添加的 shoes 字段：新增、编辑、删除、`socks5 secure`、链式代理规则、shoes 升级迁移和备份恢复只修改目标条目，其他节点的原始字段原样保留；聚合配置与节点文件不一致时拒绝提交并给出脱敏提示（#145、#174、#182）。
- 菜单内自更新成功后，按回车自动切换到新版本菜单；切换失败则退出并提示重新运行 `sudo prs`（#168、#170）。
- `socks5 secure`：不再把不相交具体地址上的同号端口误判为冲突（#146、#178）；shoes 预检期间被中断时清理含凭据的候选配置（#152、#183）。
- CI 与流程：七种 TLS 协议用固定 sing-box v1.14.2 做真实连通、错误凭据、证书校验和异钥证书验收，并纳入合并与 Release 门禁（#156、#173、#175、#184）；修复 schema 验收、L1 旧版升级限流和 Ubuntu 22.04 的偶发失败（#161、#167、#164、#165、#169、#171）。不放宽任何门禁。
- Cargo.toml、Cargo.lock 和当前版本文档同步为 0.3.4；不改变 shoes pin（v0.3.7）、受管协议、state 格式或状态兼容规则。

升级要求与已知问题见 [v0.3.4 发版说明](docs/RELEASE_NOTES_v0.3.4.md)。

## 0.3.3

- SOCKS5 安全加固：新建的无认证 SOCKS5 默认只监听回环地址（`127.0.0.1`，IPv6 场景为 `::1`），节点文件生成、聚合渲染和编辑端口统一校验；已有节点保留原监听地址，并在启动、status 和菜单中显示风险警告；启用认证后撤销旧的公网无认证豁免（#126、#128）。
- 新增 `prs socks5 secure <节点> [--auth | --local] [--dry-run] [--yes]`，一键加固旧版公网无认证 SOCKS5：`--auth` 保留监听地址并生成新凭据，`--local` 改为只监听回环；先做 shoes 预检，提交期间屏蔽中断信号，重启验证失败自动回滚（#127、#133）。
- 恢复快速添加、高级添加和更改配置成功页的连接参数、分享链接与二维码；`prs generate` 补全 VLESS-ENC Sudoku 外观输出（#122、#123）。
- 依赖：url 升级到 2.5.9，修复 RUSTSEC-2026-0592（#135）。
- CI 与流程：真实 systemd 上验收 v0.3.2 旧节点执行 `socks5 secure`（#153、#160）；修复 pipefail 下 `grep -q`/`head` 的 SIGPIPE 偶发失败（#137、#154）；Rocky Linux 9 容器显式设置 PATH（#129）；增加手动触发的 crates.io Trusted Publishing 发布工作流（#121）；Codex 自动化切换到 CPA 通道、失败原因归类、增量审查且只拦截 P0/P1（#132、#134、#141、#147、#149）。不放宽任何门禁。
- Cargo.toml、Cargo.lock 和当前版本文档同步为 0.3.3；不改变 shoes pin（v0.3.7）、受管协议、state 格式或状态兼容规则。

升级要求与已知问题见 [v0.3.3 发版说明](docs/RELEASE_NOTES_v0.3.3.md)。

## 0.3.2

- 受管 shoes 不支持 Sudoku 时，添加或修改仍需 Sudoku 的节点会先做有界能力检测，并通过现有固定 Release 升级事务自动升级到 v0.3.7；替换前再次验证能力，保留 digest 校验、未知来源与降级保护及失败回滚。无效的修改请求先校验，不触发升级、迁移或重启（#112）。
- 统一终端菜单：节点按协议与端口显示，空输入停留、无效输入统一提示，添加、查看等操作完成后在结果页回车返回主菜单；首次默认部署的结果或失败原因在清屏前保留到回车确认；菜单导出 NekoBox 时恢复 H2MUX 偏好丢失提示（#114）。
- 依赖：quinn-udp 升级到 0.5.16，修复 RUSTSEC-2026-0538（#117）。
- CI 与流程：PR 合并门禁和 Release 门禁支持显式步骤别名（#118）；增加 Agent Pipeline 规划与独立审查规则（#115、#116）；调整 linguist 统计（#109）。不放宽任何门禁。
- Cargo.toml、Cargo.lock 和当前版本文档同步为 0.3.2；不改变 shoes pin（v0.3.7）、现有协议或状态兼容规则。

升级要求与限制见 [v0.3.2 发版说明](docs/RELEASE_NOTES_v0.3.2.md)。

## 0.3.1

- shoes 固定为 v0.3.7；增加 VLESS-XHTTP-REALITY、VLESS-Sudoku 和 VLESS-ENC Sudoku 外观。
- 统一协议菜单，支持快速 AnyTLS REALITY，完善 SNI 检测与菜单错误恢复。
- 扩充终端菜单、旧版本升级、外部客户端及真实 systemd 验收。
- 增加按精确提交核验的 PR 合并与 Release 门禁，验证产物架构、SHA-256、公开下载、一键安装及自更新。
- Cargo.toml、Cargo.lock 和当前版本文档同步为 0.3.1；不改变现有协议、状态兼容规则或安全策略。

升级要求与限制见 [v0.3.1 发版说明](docs/RELEASE_NOTES_v0.3.1.md)。

## 0.3.0

历史兼容说明见 [v0.3.0 发版说明](docs/RELEASE_NOTES_v0.3.0.md)。
