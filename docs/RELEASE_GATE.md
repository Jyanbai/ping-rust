# 严格 Release 发版门禁

不自行创建 tag、Release、crates.io 发布或操作真实服务器。只有用户明确授权后创建的 tag 才进入真实发版流程；Codex 额度不足不影响 Actions 门禁，但不能冒充独立 Codex Review 已完成。

## 验证步骤

1. verify-tag：tag 必须为严格 vX.Y.Z；tag commit 属于 main 历史，Cargo.toml 与 Cargo.lock 版本一致。
2. verify-required-checks：按照 scripts/ci/release_gate_policy.json 对该 SHA 的 push Actions 全量验收。固定的 CI、E2E、兼容性、安全审计和门禁回归全部必须真实执行成功；失败、缺失、取消、超时、跳过均拒绝。对只重跑失败 job 的 attempt 保留较早成功 job 证据；最新失败覆盖旧成功；发布前再读 API。
3. 构建：沿用现有两个 musl 平台构建、QEMU 执行和静态依赖检查；发布前校验恰好两份归档、ELF 架构、大小、成员可执行性、SHA256SUMS。
4. 发布：不覆盖任何已有 Release；通过所有验证后先建立未公开 draft，确认附件后再转为公开。公开后无 token 下载三个附件、核对 checksums、执行既有一键安装和自更新测试。若发布后验证失败，将刚公开的版本退回 draft 并报告；回退失败需人工处理，不得宣称发布成功。

## 重要界限

本 PR 合入 main 后才会影响未来 tag；旧 tag 不受这套工作流保护。测试 PR 的绿灯不等于 tag SHA 的正式发版证据。保留原有发版环境、tag Rulesets 及全部安全策略，不自动合并或发版。
