# VLESS-ENC C 阶段验证报告

功能代码提交为 `d5f0285`；日志下载参数修正为 `53a2740`。draft PR #38 保持草稿；本阶段不合并、不推 tag、不发版。后续文档提交不改变功能代码。完整交付检查以 PR 的最终检查结果和交付记录为准。

## 九项真实代理互通与保密审计

run **`40804965892`** 已通过，客户端 job **`123221593909`**，独立审计 job **`123222688284`**。固定客户端为 Xray **v26.6.27**、Mihomo **v1.19.33**，服务端为 shoes **v0.3.6**；三份下载资产均通过工作流内固定 SHA-256 校验。

| 客户端 | 外观 | 认证 | Vision | 实际流量结果 | 端点收到请求 | 新增 MainPID |
| --- | --- | --- | --- | --- | ---: | --- |
| Xray v26.6.27 | native | x25519 | 关闭 | PASS | 1 | 不变 |
| Xray v26.6.27 | native | x25519 | 开启 | PASS | 1 | 不变 |
| Xray v26.6.27 | xorpub | x25519 | 关闭 | PASS | 1 | 不变 |
| Xray v26.6.27 | xorpub | x25519 | 开启 | PASS | 1 | 不变 |
| Xray v26.6.27 | random | x25519 | 关闭 | PASS | 1 | 不变 |
| Xray v26.6.27 | random | x25519 | 开启 | PASS | 1 | 不变 |
| Xray v26.6.27 | native | mlkem768 | 关闭 | PASS | 1 | 不变 |
| Mihomo v1.19.33 | native | x25519 | 关闭 | PASS | 1 | 不变 |
| Mihomo v1.19.33 | native | x25519 | 开启 | PASS | 1 | 不变 |

上表每一行均对应同一 run/job（`40804965892` / `123221593909`）。每项由当前 ping-rust CLI 生成并提交真实节点；Mihomo 使用 CLI 实际导出的配置。curl 经 SOCKS 代理访问本地端点，响应标记和端点计数同时匹配。没有把密钥生成或 dry-run 当作流量互通。

逐项验证了节点 profile 和聚合配置权限 0600、state 不含 decryption、默认 encryption_limits 未写入、原生 TCP 不套 TLS/Reality、链接的 encryption/security/type/flow、详情展示，以及 sing-box/NekoBox 明确拒绝。上传前对进程输出、journal 和实际 artifact 目录进行检查；独立 job 再下载已上传 artifact 和已完成客户端 job 的完整日志扫描，实际结论：

```text
Uploaded artifact and completed job log: no decryption strings; all nine cases passed.
```

## 最终 bero 验证

以下均针对最终功能代码，使用原有单任务配置、Nice=19、idle I/O 和磁盘守护，未在本机编译或测试。

| job | 命令与实际结果 | 耗时 | 峰值内存 | 退出码 |
| --- | --- | ---: | ---: | ---: |
| ping-rust-c-info-final-fmt | cargo fmt --all -- --check：通过 | 0.40 s | 56488 KB | 0 |
| ping-rust-c-info-final-clippy | cargo clippy --locked --all-targets -- -D warnings：通过 | 5.14 s | 431308 KB | 0 |
| ping-rust-c-info-final-test | cargo test --locked --release：225 单元、3 集成通过；3 单元和 2 集成 ignored | 199.45 s | 1163564 KB | 0 |

最终资源记录：

| 任务结束 | du -sh ~/cargo-target | target 精确字节 | df -h / | / 可用字节 |
| --- | --- | ---: | --- | ---: |
| clippy | 876M | 918450176 | 20G / 15G used / 4.3G avail / 77% | 4601487360 |
| test | 876M | 918450176 | 20G / 15G used / 4.3G avail / 77% | 4605489152 |
| fmt | 876M | 918450176 | 20G / 15G used / 4.3G avail / 77% | 4601253888 |

```text
[job] 耗时 0.40s，峰值内存 56488KB，退出码 0
[job] 耗时 5.14s，峰值内存 431308KB，退出码 0
[job] 耗时 199.45s，峰值内存 1163564KB，退出码 0
```

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
| ping-rust-c-clean-test | 完整 cargo test：224 单元测试和 3 集成测试通过；3 单元、2 集成 ignored | 106.09 s | 727908 KB | 0 |
| ping-rust-c-final-fmt | cargo fmt --all -- --check 通过 | 0.45 s | 56012 KB | 0 |
| ping-rust-c-final-clippy | 编译检查结束后磁盘守护返回 75，不能记为任务通过 | 48.42 s | 568476 KB | 75 |
| ping-rust-c-final-clippy-cold | 从空缓存运行 clippy --locked --all-targets -- -D warnings 通过 | 65.12 s | 571680 KB | 0 |
| ping-rust-c-release-policy-red | 新增旧协议重启策略回归测试按预期失败：0 passed、1 failed | 226.04 s | 1117720 KB | 101 |
| ping-rust-c-final-release-test | 修复策略后完整 release 测试：225 单元和 3 集成通过；3 单元、2 集成 ignored | 244.73 s | 1034028 KB | 0 |
| ping-rust-c-policy-final-fmt | cargo fmt --all -- --check 通过 | 0.49 s | 55708 KB | 0 |
| ping-rust-c-info-final-clippy | 最新功能代码 clippy --locked --all-targets -- -D warnings 通过 | 5.14 s | 431308 KB | 0 |

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

## 续跑与实现说明

续跑恢复：重新 fetch 后 main 仍为相同基线、CI 全绿，本地改动均属于 C 阶段。bero 初次检查可用 4,289,359,872 B，未发现 cargo/rustc 或运行中的 job；仅删除共享 `~/cargo-target`。紧邻删除前的 df 为 4,295,602,176 B（空间在检查之间小幅波动），删除后为 5,524,717,568 B；未清理其他数据。随后从空 target 重新运行完整测试。

预设、添加及更改菜单、CLI 高级选项、YAML/链接/二维码/导出、互通及保密断言、Ubuntu PTY 用例均已实现。README、Release draft 和 Wiki 写明无 TLS、三种外观及 random 的 splice 提示、mlkem768 长链接提示，以及实际测试的客户端版本。Wiki 已发布到独立 Wiki 仓库提交 `cd342a4`，标明开发分支未发版，并更新协议表和侧栏。

当前完整单元测试需要校验过的 shoes；测试进程通过仅在 `cfg(test)` 生效的 `PING_RUST_TEST_SHOES` 指定二进制。生产构建仍固定调用已安装路径。3 个 ignored 中包含新增的显式真实生成器测试，该测试已在前述 generator job 单独包含执行；其余为既有 ignored 项。

另外两个单元 ignored 是既有夹具生成工具 `derive_yaml_fixtures` 和 `regenerate_yaml_fixtures`，未执行，历史夹具未重写。两个集成 ignored 需要 root/systemd 环境；性能基线已在 Actions run `40803991396` 验证，链式 systemd 验收另在本功能分支运行 `40806048459`，其最终结果见 PR 交付记录。

历史兼容夹具未修改。原有“夹具覆盖所有预设”断言保留，向待比较的协议列表增加独立 `vless-enc/state.json` 夹具，以覆盖第 14 项；原有 13 种协议的语义比较和凭据重生成断言均保留。

热重载接入说明：原流程仅允许固定源码 pin。本阶段仅在新增 VLESS-ENC 时增加完整来源记录的 v0.3.6 Release 资格（精确 tag/version，加上启动前重新核对的二进制摘要），供实际 Release 二进制完成 MainPID 验收。其他协议的 Release 重启策略保持不变。缺少来源或摘要、摘要不匹配、其他 Release 和错误 pin 继续拒绝；原有拒绝路径断言未放宽。互通 CI 的来源记录如实标为 `github-release`，没有伪装成源码 pin。

## 建议

- 未验证更旧的 Xray/Mihomo、其他客户端平台、所有 mlkem768 外观/Vision 组合、公网长时间运行、二维码在真实手机上的可扫描性和性能；不要外推本报告的九项结果。
- sing-box、NekoBox 和链式加密出口是本阶段明确拒绝的能力；H2MUX 不开放。没有用替代协议绕过这些限制。
- 尚未做新版本发布、用户机器升级验收或多平台发布；这些属于后续阶段。
- Wiki 其他历史页面的旧基线描述可在后续统一核对；本阶段仅新增 VLESS-ENC 页面和入口。
- 添加菜单选择返回时的取消提示还可统一为正常返回菜单，作为后续交互整理。

## 验证过程与失败修复记录

- 完整测试 `ping-rust-c-clean-test` 结束时 target 为 1,050,275,840 B（1002M），根分区可用 4,470,177,792 B。
- `ping-rust-c-final-fmt` 结束时 target 为 1,050,275,840 B，根分区可用 4,470,157,312 B。
- `ping-rust-c-final-clippy` 的 `[job]` 退出码为 75；结束时 target 为 1,236,729,856 B（1.2G），根分区可用 4,281,593,856 B。当轮立即停止，未自行清理。
- 再次续跑先确认没有 cargo/rustc 或活动 job，仅删除 `~/cargo-target`；删除前可用 4,283,596,800 B，删除后可用 5,520,326,656 B。空缓存 clippy 结束时 target 为 455,897,088 B（435M），根分区可用 5,064,273,920 B。没有更改 Cargo 配置或关闭磁盘守护。
- draft PR #38 已创建。首个互通 run `40802351107` 因验收脚本漏入提交失败；补交后 run `40802760541` 在建立端点时因 Python 模块名被局部变量遮蔽失败，尚未执行九项流量用例。两次失败均不能记为互通通过。
- 原有 Release 生命周期验收检测到热重载资格扩大改变了旧协议的重启策略（run `40802760562`，job `123214472447`）；保留该验收断言，补回归测试后修正代码。
- 新增策略回归测试在修复前按预期失败。结束时 target 为 832,258,048 B（794M），根分区可用 4,687,896,576 B。本阶段新增的 Release 资格测试改为显式传入“新增 VLESS-ENC”操作标记，三条资格断言保持原要求；main 已有测试和断言均未修改。完整测试使用 `cargo test --locked --release`，减少 debug 测试产物与 clippy 缓存叠加的磁盘占用，未更改 Cargo 配置。
- 修复策略后完整 release 测试结束时 target 为 844,369,920 B（806M），根分区可用 4,674,191,360 B；随后 fmt 结束时 target 相同、可用 4,675,502,080 B。补上 `prs info` 详情展示后的 clippy 结束时 target 为 918,450,176 B（876M），可用 4,601,487,360 B。
- 手动 Ubuntu acceptance run `40802367496` 已通过：Debian job `123213205313`，Ubuntu job `123213205620`。日志明确记录第 14 项 PTY、两类运行配置 0600、公开 state 和 MainPID 不变为 PASS，原有激活失败和热重载超时回滚也通过。
- 互通 run `40803997437`（job `123218462133`）新增服务成功且 MainPID 不变，但 `prs info` 缺少模式及 Encryption，首例在客户端流量前失败；没有将它计为流量通过。已让该 CLI 路径复用通过单元测试的完整详情渲染，保留互通断言。
- 互通 run `40804477686` 的九项流量已通过，但独立审计 job `123221135200` 被新版 gh 的 ANSI 日志输出保护拦截，扫描未执行。仅在重定向到待扫描文件的日志下载命令上添加 `--allow-escape-sequences`，没有取消或放宽审计；后续 run `40804965892` 九项和独立审计全部通过。
- source compatibility run `40804965967` 的固定 pin 子任务在 SOCKS5 生成阶段单次失败，原始子进程输出被既有脚本抑制，根因未验证。同一功能代码的 run `40804477604` 及 schema run `40804477683` 均完整通过；未为这次失败修改源码、断言或历史夹具。最终文档提交重新运行全部 PR 检查，交付状态以最终 PR 检查为准。

## 已通过的既有 CI 证据

下列提交之间功能代码未变，仅日志下载和文档有改动。最终文档提交的检查结果在 PR 交付记录另附，避免把尚在运行的检查提前记为成功。

| 检查 | run ID | job ID / 范围 | 已观察结果 |
| --- | --- | --- | --- |
| CI，Ubuntu 22.04/24.04、Debian 12、Rocky 9、Alma 9 | 40804965901 | 123221594124、123221594184、123221594250、123221594378、123221594418 | 全部通过 |
| v0.2.2 → shoes v0.3.6 升级及回滚 | 40804965901 | 123221594231 | 通过 |
| Xray Reality、Mihomo Snell 默认 AES-128-GCM | 40804965901 | 123221594304 | 通过 |
| v0.2.1 Release 反向读取 | 40804965958 | 123221594118 | 通过 |
| shoes 两种来源和 Release 生命周期/H2MUX | 40804477604 | 123220001373、123220001557、123220001635 | 全部通过 |
| shoes 完整 schema、重复原子替换、两来源矩阵 | 40804477683 | 123220001579、123220001810、123220001871、123220002008 | 全部通过 |
| 手动 Ubuntu acceptance，含第 14 项和两种失败回滚 | 40802367496 | 123213205313、123213205620 | 全部通过 |
| Linux 性能与可靠性基线 | 40803991396 | 123218442976、123218443174 | 全部通过 |

最终功能代码的手动 Ubuntu 复核为 run `40804961453`（jobs `123221583678`、`123221583915`）；最终结果见 PR 交付记录。本阶段没有修改 Cargo.toml/Cargo.lock，也没有触发 release 工作流或构建发布资产。
