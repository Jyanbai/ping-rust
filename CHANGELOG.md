# 更新日志

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
