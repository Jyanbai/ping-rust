# G1 阶段报告（授权恢复后，远端验证通过，CI 待运行）

日期：2026-10-30（Asia/Hong_Kong）。

## 工作区与范围

- 原工作区未修改；按用户追加授权创建独立 worktree：`D:\dev\ping-rust-g1`。
- 分支：`fix/unknown-shoes-source-guidance`。
- 开工 HEAD 与 origin/main 均为 `14ce31e631163080cb81682522da216f61875020`；开工状态干净。
- 已提取来源未知提示的纯函数，新增回归测试，替换指定的 CLI 与菜单文案，添加指定 README 段落。
- 已新增 `.github/workflows/legacy-upgrade.yml` 和 `scripts/ci/legacy-upgrade.sh`，尚未运行。设计覆盖 L1、C2，记录旧安装实际选择的 shoes Release、摘要、来源文件状态、更新退出码及服务和原端口状态。
- 未实现方案 3，未新增 CLI 参数，未改兼容夹具、已有 workflow、已有脚本、发布说明或 Wiki。
- 未提交、推送、创建 PR、合并、推 tag 或发布。

## 新测试：旧文案预期失败

bero 任务：`g1-red`。

命令：`cargo test --locked unknown_shoes_source_guidance_explains_one_time_override -- --nocapture`。

保留旧文案，仅提取纯函数后运行，输出：

```text
running 1 test
thread panicked at src/installer.rs:750:9:
当前 shoes 来源未知，无法证明目标 Release 不会造成降级；请使用 --allow-downgrade 明确允许安装。
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 228 filtered out
[job] 耗时 31.61s，峰值内存 637468KB，退出码 101
```

此失败是任务要求的预期失败证据。结束时共享 target 显示 1.5G，根分区可用 5.4G。

## fmt：实际失败并停止

bero 任务：`g1-fmt`。

命令：`cargo fmt --all -- --check`。

```diff
-        assert!(message.contains("无法确认当前 shoes 的安装来源"), "{message}");
+        assert!(
+            message.contains("无法确认当前 shoes 的安装来源"),
+            "{message}"
+        );
```

```text
[job] 耗时 0.54s，峰值内存 56024KB，退出码 1
```

结束状态：

```text
du -sh ~/cargo-target: 1.5G
du -s -B1 ~/cargo-target: 1512972288 bytes
df -h /: Size 20G, Used 14G, Avail 5.4G, Use 71%
df -B1 /: Avail 5795143680 bytes
```

按任务规则第 8 条，当时停止。用户随后明确授权只调整新增断言的换行并从 fmt check 恢复；已确认该次修改仅有空白/换行变化，断言比较对象、期望值及语义均未改变。

## 授权恢复后的远端验证

- fmt：`g1-fmt-authorized`，`cargo fmt --all -- --check`。
  `[job] 耗时 0.29s，峰值内存 56424KB，退出码 0`
  结束 target：1.5G（1512972288 字节）；根分区可用 5.4G（5796868096 字节）。
- clippy：`g1-clippy`，`cargo clippy --locked --all-targets -- -D warnings`，无警告。
  `[job] 耗时 11.30s，峰值内存 542896KB，退出码 0`
  结束 target：1.5G（1593974784 字节）；根分区可用 5.4G（5713920000 字节）。
- test：`g1-test`，`PING_RUST_TEST_SHOES=/home/agent/tools/shoes-v036/shoes cargo test --locked`。
  `[job] 耗时 10.31s，峰值内存 592772KB，退出码 0`
  单元测试 226 passed / 0 failed / 3 ignored；集成测试合计 6 passed / 0 failed / 2 ignored；总计 232 passed / 0 failed / 5 ignored。
  结束 target：1.5G（1516642304 字节）；根分区可用 5.4G（5793075200 字节）。
- 新测试 `unknown_shoes_source_guidance_explains_one_time_override` 已从旧文案上的失败变为通过。
- v0.3.6 shoes 归档 SHA-256：`d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707`，与现有 CI 固定值一致。
- 归档内二进制与本次测试使用文件 SHA-256 一致：`a21e179d9c031f2eededf2d828201db35f285a23325cacf3bd1886d9de6eca9e`。
- 构建测试都在 bero 后台 job 中运行，Nice=19、idle I/O、Cargo jobs=1、磁盘守护启用；未清理缓存。

## 尚未验证

- L1、C2 全部步骤：未运行；退出码、stderr、来源文件权限/摘要、服务和端口结果均未验证。
- v0.1.20 实际装上的 shoes 版本：未验证，不根据 latest 推测。
- PR 检查、ubuntu-acceptance、chain-systemd 手动运行：待执行。
- 合并 SHA、合并后 main workflow：不适用，当前没有合并授权，PR 将保持 draft。

## 建议

未发现其他已验证的任务外问题。
