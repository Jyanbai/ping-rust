# ping-rust v0.3.3

> 在 v0.3.2 基础上的安全修复版本：收紧无认证 SOCKS5 的默认监听，并提供一键加固旧节点的命令。不改变 shoes pin（v0.3.7）、受管协议、state 格式或状态兼容规则。发布以 tag 对应提交的全部 push 检查和 Release 门禁结果为准。

## 本版变更

- **无认证 SOCKS5 默认只监听回环**（#126、#128）：新建的无认证 SOCKS5 默认监听 `127.0.0.1`（IPv6 场景为 `::1`），节点文件生成、聚合渲染和编辑端口统一校验，回环节点的分享链接、二维码和客户端导出只允许实际监听地址。使用认证的 SOCKS5 保持随机凭据和原监听策略。
- **一键加固旧版公网无认证 SOCKS5**（#127、#133）：新增 `sudo prs socks5 secure <节点名称或 UUID> [--auth | --local] [--dry-run] [--yes]`。提交前先用 shoes 预检候选配置，提交期间屏蔽 SIGINT、SIGHUP、SIGTERM，重启后核对服务、监听和 SOCKS5 握手，任一步失败自动恢复原配置并重启验证。
- **配置成功页恢复连接详情**（#122、#123）：快速添加、高级添加和更改配置成功后重新显示连接参数、分享链接与二维码；`prs generate` 补全 VLESS-ENC Sudoku 外观输出。
- **依赖安全**（#135）：url 升级到 2.5.9，修复 RUSTSEC-2026-0592；未添加任何审计忽略项。
- **CI 与流程**：在真实 systemd 上验收“v0.3.2 公网无认证旧节点 → 升级 → `socks5 secure`”全流程（#160）；修复 pipefail 下的 SIGPIPE 偶发失败（#154）；Rocky Linux 9 容器显式设置 PATH（#129）；增加手动触发的 crates.io Trusted Publishing 发布工作流（#121）；Codex 自动化切换到 CPA 通道、增量审查且只拦截 P0/P1（#132、#134、#141、#147、#149）。不放宽任何门禁。

## 行为变化

- **新建的无认证 SOCKS5 默认只能本机访问**。需要从其他机器连接时，请启用用户名/密码认证；SOCKS5 本身不加密传输，公网使用务必启用认证。
- **已有节点不会被自动修改**：升级后旧的公网无认证 SOCKS5 保留原监听地址，只在启动、status 和菜单中显示风险警告，需要手动执行下面的加固命令。

## 加固旧版公网无认证 SOCKS5

先按下文“升级与配置迁移”完成 `self-update`，然后对每个公网无认证 SOCKS5 节点：

```bash
# 1. 预览脱敏后的配置差异，不写入任何文件
sudo prs socks5 secure <节点名称或 UUID> --auth --dry-run

# 2a. 保留公网监听，生成新的用户名和密码（客户端需要重新导入）
sudo prs socks5 secure <节点名称或 UUID> --auth

# 2b. 或者改为只监听回环地址（远端客户端将无法连接）
sudo prs socks5 secure <节点名称或 UUID> --local
```

- 应用时会重启共享的 `shoes.service`，同机其他节点的连接可能短暂中断。
- `--auth` 成功后会输出新的连接信息；`--local` 不会修改防火墙，曾为该端口开放的规则请另行检查。
- 无终端或使用 `--yes` 时必须指定 `--auth` 或 `--local`。已经启用认证或只监听回环的节点会提示无需修复，不做任何改动。
- 加固要求 `shoes.service` 是 ping-rust 生成的标准 unit（无自定义 drop-in、无待重载配置），且正在运行的 shoes 与磁盘上的二进制一致；不满足时会拒绝执行并说明原因。
- 使用 `--local` 前请备份整个 `/etc/shoes`。降级到 v0.2.1 后仍可查看和导出这些节点，但 v0.2.1 不会阻止为回环节点导出公网地址，用旧版导出时请手动把 `--server` 指定为实际监听的回环地址。

## 已知问题

- **菜单自更新后仍在运行旧版本**（#168）：从 v0.3.3 或更早版本的菜单升级时，磁盘上的程序会更新，但当前菜单仍是旧进程。菜单内自更新后请退出并重新运行 `sudo prs`。
- **未受管字段会被覆盖**（#145）：添加、编辑、删除或加固任意节点时，ping-rust 会按自己建模的字段重新生成全部节点配置，手工写进 profile 或运行配置、ping-rust 不认识的 shoes 字段（例如 VLESS-ENC 节点手工添加的 `encryption_limits`）会丢失。该问题 v0.3.2 已存在，计划在 v0.3.4 修复；手工改过配置的用户操作前请先备份 `/etc/shoes`。
- **自签证书节点的客户端导出仍跳过证书验证**（#155）：未提供 `--cert`/`--key` 的 TLS 节点使用自签证书，导出时带 `insecure` / `allowInsecure` / `skip-cert-verify`，客户端不校验证书，存在中间人风险。对安全有要求时请用 `--cert`/`--key` 提供真实证书；计划在 v0.3.4 改为证书固定。
- **监听检查把不相交地址上的同号端口当成冲突**（#146）：若同一端口在另一具体地址上被其他服务监听，`socks5 secure` 会超时并保持原配置，不会损坏节点。
- **预检阶段中断可能留下候选配置文件**（#152）：在 shoes 预检期间按 Ctrl-C，`/etc/shoes` 下可能残留一个 0600 的 `.ping-rust-candidate-*.yaml`，可手动删除；加固本身不会提交。

以下客户端兼容范围沿用既有文档记录，本次未改变客户端导出逻辑；实际结果以 tag 对应提交的 Actions 为准。

## 客户端兼容要求

- Reality 客户端：CI 实测 Xray **v25.5.16** 和 **v26.6.27** 可以连接，建议使用 Xray 25.5.16 及以上。更早的版本未验证，可能连不上（例如旧版 v2rayN 内置的 Xray），请先升级客户端及其 Xray 内核。
- Snell v3：Mihomo 只支持 `aes-128-gcm`。新节点默认改为 `aes-128-gcm`，已有节点不自动修改；已有的 chacha20 或 aes-256 节点若使用 Mihomo，需要手动修改 cipher 并重新导出配置。

## 升级与配置迁移

- 默认 shoes 版本为 **v0.3.7**。通配符路由规则在升级时自动迁移为 shoes v0.3.6 支持的格式；候选配置先验证，应用失败会回滚。
- 新版 ping-rust 搭配旧 shoes 时，修改配置会提示先升级 shoes。

先执行 `self-update` 更新 ping-rust：

```bash
sudo ping-rust self-update --version v0.3.3
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

添加 VLESS-ENC 节点后**不能降级到 v0.2.x**，旧版无法读取包含该节点的管理状态。若必须降级，请先在 v0.3.3 中删除全部 VLESS-ENC 节点并备份配置，再执行降级。删除 VLESS-ENC 节点后再降级的其他行为未验证。

XHTTP、VLESS-Sudoku 节点保存在独立 state 扩展中，v0.2.1 可忽略扩展读取原有节点，但不支持管理这些新协议或包含它们的运行配置。降级前应先用新版删除新协议节点并备份配置，不能将“旧版能读取原有节点”理解为完整降级兼容。
