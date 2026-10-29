# VLESS-ENC C 阶段报告（进行中）

本阶段进行中；最终互通与 CI 结果尚未确认，不合并、不推 tag、不发版。

## 基线检查（2026-10-29）

- 本机工作区：`D:\dev\ping-rust`；开工时 main 和 origin/main 均为 `66d0407433f5120f77050f8b1294eacb86ac1e61`，工作区干净。
- #36 和 #37 均已合并；旧功能分支相对 main 独有提交数为 0，已重建到最新 main。
- 当前 main 的 CI：run `40665027854`，success；兼容工作流：run `40665027974`，success；Ubuntu acceptance：run `40665027995`，success。
- bero 连接成功。初始根分区可用 5,150,879,744 B，共享 target 为 407,351,296 B；本轮未清理缓存。

## shoes v0.3.6 参数证据

下载固定 v0.3.6 x86_64 musl 资产，SHA-256 校验通过：`d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707`。

实际执行 `shoes generate-vless-encryption --help`，退出码 1，原文：

```text
VLESS encryption generation failed: VLESS generator option requires a value
```

该版本没有生成子命令的 help 开关。实际执行顶层 `shoes --help` 也返回 1；其生成命令用法原文如下（其他全局选项省略）：

```text
    generate-vless-encryption [options]             Generate matched VLESS encryption credentials
      --auth x25519|mlkem768 (repeatable), --mode native|xorpub|random
      --rtt 0rtt|1rtt, --lifetime 600s|N-Ms|0s
```

适配器显式传入 auth、mode、rtt 0rtt、lifetime 600s。Rust 只检查输出结构和密钥编码长度，不实现加密。

## 已验证的基础测试

测试先于实现编写。已有断言和历史兼容夹具未修改。

| bero job | 实际结果 | 耗时 | 峰值内存 | 退出码 |
| --- | --- | ---: | ---: | ---: |
| ping-rust-c-chain-red | 预期失败：原错误提示不符合要求 | 76.77 s | 706152 KB | 101 |
| ping-rust-c-parser-red | 2 passed、2 failed：链式提示及解析成功路径预期失败 | 6.03 s | 600308 KB | 101 |
| ping-rust-c-foundation-green | 4 passed、0 failed | 5.19 s | 615796 KB | 0 |
| ping-rust-c-generator-test | 6 passed、0 failed，显式包含真实生成器测试 | 4.58 s | 590016 KB | 0 |
| ping-rust-c-foundation-fmt | 新代码存在格式差异，已在本机按差异修正 | 0.34 s | 54464 KB | 1 |
| ping-rust-c-foundation-fmt2 | cargo fmt --check 通过 | 0.33 s | 54748 KB | 0 |
| ping-rust-c-preset-test | 8 passed、0 failed、1 ignored | 13.40 s | 832440 KB | 0 |
| ping-rust-c-preset-options-test | 11 passed、0 failed、1 ignored | 12.10 s | 822984 KB | 0 |
| ping-rust-c-full-unit | 222 passed、0 failed、3 ignored | 4.99 s | 584840 KB | 0 |
| ping-rust-c-integrated-fmt | cargo fmt --check 通过 | 0.33 s | 54944 KB | 0 |
| ping-rust-c-integrated-clippy | 发现新增测试的 err_expect 和新增 options 初始化风格问题，已修正；未放宽 lint | 5.89 s | 539772 KB | 101 |
| ping-rust-c-integrated-clippy2 | cargo clippy --locked --all-targets -- -D warnings 通过 | 9.59 s | 542612 KB | 0 |
| ping-rust-c-harness-syntax | Python 互通脚本 py_compile 通过 | 0.05 s | 12984 KB | 0 |
| ping-rust-c-integrated-test | 完整 cargo test 被磁盘守护中止，测试结果未验证 | 18.03 s | 717472 KB | 75 |

最后一项实际调用校验过的 shoes 二进制，覆盖 native、xorpub、random 各自的 x25519 和 mlkem768，共 6 次生成；输出仅在进程内解析，没有打印生成凭据。它验证密钥生成，不证明代理互通。

其他基础覆盖：严格两行解析、缺行、多余行、顺序错误、非法编码/长度/模式/认证、子进程参数、失败输出不进入错误，以及链式导入重复 encryption 参数不能覆盖非 none 值。

最后任务资源原文：

```text
[job] 耗时 4.58s，峰值内存 590016KB，退出码 0
1000M /home/agent/cargo-target
/dev/sda1 20G 15G 4.2G 78% /
```

根分区可用 4,473,872,384 B；target 精确大小 1,047,646,208 B。磁盘守护始终启用。

## 存储约束澄清

用户确认允许 decryption 同时写入节点 profile YAML 和聚合 config.yaml，两者权限均为 0600；不得进入 state 元数据、展示、日志或 artifact。

## 最新磁盘停止事件

完整测试启动前 `/` 可用 4,383,526,912 B，target 为 1,137,053,696 B，低于清理阈值 1.5 GiB，故未提前清理。任务被磁盘守护中止：

```text
[disk] / 可用 4289638400 字节，低于 4GiB，立即停止任务
[job] 耗时 18.03s，峰值内存 717472KB，退出码 75
1.2G /home/agent/cargo-target
/dev/sda1 20G 15G 4.0G 79% /
```

结束后根分区可用 4,291,420,160 B，target 精确大小 1,229,115,392 B。遵守退出码 75 的停止规则，本轮未清理、未继续构建或测试、未提交或创建 PR。不能将这次完整测试记为通过；前面的 222 passed 仅对应当时的完整单元测试快照。

## 尚未验证或交付

续跑恢复：重新 fetch 后 main 仍为相同基线、CI 全绿，本地改动均属于 C 阶段。bero 初次检查可用 4,289,359,872 B，未发现 cargo/rustc 或运行中的 job；仅删除共享 `~/cargo-target`。紧邻删除前的 df 为 4,295,602,176 B（空间在检查之间小幅波动），删除后为 5,524,717,568 B；未清理其他数据。随后从空 target 重新运行完整测试。

预设、添加及更改菜单、CLI 高级选项、YAML/链接/二维码/导出、9 项互通工作流、MainPID 和保密断言、Ubuntu PTY 用例、README/Release draft/Wiki 文稿已写入当前工作区；互通矩阵、真实 MainPID、最终 clippy/test、全部既有 CI、分支手动 Ubuntu acceptance、Wiki 发布、draft PR 和 #35 更新仍未完成。

当前完整单元测试需要校验过的 shoes；测试进程通过仅在 `cfg(test)` 生效的 `PING_RUST_TEST_SHOES` 指定二进制。生产构建仍固定调用已安装路径。3 个 ignored 中包含新增的显式真实生成器测试，该测试已在前述 generator job 单独包含执行；其余为既有 ignored 项。

历史兼容夹具未修改。原有“夹具覆盖所有预设”断言保留，向待比较的协议列表增加独立 `vless-enc/state.json` 夹具，以覆盖第 14 项；原有 13 种协议的语义比较和凭据重生成断言均保留。

热重载接入说明：原流程仅允许固定源码 pin。本阶段新增完整来源记录的 v0.3.6 Release 资格（精确 tag/version，加上启动前重新核对的二进制摘要），供实际 Release 二进制完成 VLESS-ENC MainPID 验收。缺少来源或摘要、摘要不匹配、其他 Release 和错误 pin 继续拒绝；原有拒绝路径断言未放宽。互通 CI 的来源记录如实标为 `github-release`，没有伪装成源码 pin。

## 建议

最终报告需明确区分真实密钥生成测试和 Xray/Mihomo 流量互通测试；客户端版本要求应由后者的实际结果填写。
