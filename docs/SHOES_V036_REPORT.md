# shoes v0.3.6 升级报告（B 阶段）

## 范围

本阶段只完成 shoes v0.3.6 的迁移、兼容夹具和外部客户端验收；不合并、不发版、不推 tag，也没有开始 C 阶段。

- Release：`v0.3.6`
- shoes schema revision：`3737e07467387044e677ae7cf8b1c16d291f1b68`
- x86_64 musl SHA-256：`d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707`
- PR #36 最终提交：`aae96d2`

## GitHub Actions 结果

最终 PR CI run `40638414214` 通过，包含 Ubuntu 22.04/24.04、Debian 12、Rocky 9、AlmaLinux 9、systemd 迁移和外部客户端 job。关联的兼容 run 也通过：schema `40638414055`、source `40638414147`、v0.2.1 backward compatibility `40638414207`。

### 老用户升级路径

systemd 容器 job `Debian 12 v0.2.2 to shoes v0.3.6 migration`（run `40638414214`，job `122650654382`）实际结果：

- 固定下载并校验 ping-rust v0.2.2 Release：SHA256SUMS 和资产均通过；旧 Release 安装 shoes v0.2.7。
- Reality、Snell（默认 cipher）和 Chain 2.0 通配符规则均建立；旧 shoes 服务 active。
- 只替换 ping-rust 后，`info` 的配置数量、名称、凭据和服务状态一致；v0.2.7 不支持 `--version` 时，新版本现在保留 `shoes（CLI 未提供版本参数）` 的兼容显示。
- 新 ping-rust 尝试新增节点时，v0.2.7 拒绝 typed rule，服务不受影响；原始记录为：`请先升级 shoes 到 v0.3.6 后再修改配置：... invalid rules: data did not match any variant of untagged enum NoneOrSome`。
- 升级事务安装 v0.3.6、从 state 重写配置、以新二进制 dry-run、原子提交并重启均通过。升级前后 state hash 保持一致，config hash 由 `7b2875065773ecd3180aa2f99c3b940672b881a592b47deca2cf4610e49b06b5` 变为 `0b9d0a7901fe1732cab34d21b7d300f067b291f867867be46e6df6fe890c3541`；MainPID `2721 → 2819`，服务 active，监听 24431/24432，规则已变成 `domain_pattern`。

### 夹具和迁移必要性

`tests/fixtures/yaml/chain-v2/` 已恢复为 main 上的 v0.2.x 磁盘格式；新写法放在 `tests/fixtures/yaml/chain-v036/`。新增测试覆盖：

- 旧 state 重新生成得到 `domain_pattern`；
- 旧 `config.yaml` 交给 v0.3.6 dry-run 被拒绝。

v0.3.6 对旧 fixture 的 dry-run 原文还先报告了缺失的历史证书文件：`certificate file '/etc/shoes/fixtures/cert-00000000.pem': No such file or directory`；因此该测试只断言拒绝，不把错误顺序误写成规则错误。单独的无效 UUID dry-run 原文为：`UUID is not version 4: 85296b07-fa5c-63a7-d8f2-cdef418defa3`。这是把夹具中的脱敏占位 UUID 更正为 RFC 4122 v4 的原因。ping-rust 新生成 UUID 的代码位置包括 `src/config/presets/reality.rs:25`、`src/config.rs:920` 和 `src/config.rs:1708`，均调用 `Uuid::new_v4()`。

### Reality 与 Xray

外部客户端 job（job `122650654615`，run `40638414214`）固定 Xray `v26.6.27` 和最低版本 `v25.5.16`，逐个覆盖六个文档 SNI。握手探针和本地 HTTP marker 结果实际记录为：六个 SNI 以及最低版本 Xray 均 `FAIL`；Xray 日志显示客户端 SOCKS 请求已建立但 marker 请求被 reset。该结果按真实运行记录保留，未宣称通过。

### Snell 与 Mihomo

同一 job 固定 Mihomo `v1.19.33`，结果为：`aes-128-gcm=FAIL`、`aes-256-gcm=FAIL`、`chacha20-ietf-poly1305=FAIL`。AES-128-GCM 的客户端 YAML 来自 `ping-rust export clash-meta`；另外两个 cipher 使用 Mihomo schema 手写。Mihomo 日志显示请求到达代理但 shoes 端连接失败，结果保留为真实发现。

### 其他 CI

最终 CI 中 fmt、clippy、全量测试、Release 安装协议、source matrix、schema dry-run、热重载和多发行版 jobs 均通过。Rust 构建/测试仍按项目规则在 bero 完成；systemd 和外部客户端验收在 GitHub Actions 完成。

## bero 磁盘记录

清理只涉及 `/home/agent/cargo-target`；每次删除前确认没有 cargo 进程，并记录根分区精确可用字节数。没有删除其它文件。

| 事件 | 删除前 `/` 可用 | 删除前 target | 删除后 `/` 可用 |
| --- | ---: | ---: | ---: |
| 首次测试退出码 75 | 4,297,568,256 B | 1,336,283,136 B | 5,633,851,392 B |
| 后续测试退出码 75 | 4,264,329,216 B | 1,362,337,792 B | 5,626,667,008 B |
| Release 退出码 75 | 4,291,174,400 B | 1,332,899,840 B | 5,624,074,240 B |

最后一次清理后 `~/cargo-target` 不存在（按 0 B 计），根分区可用空间约 5.624 GiB，高于 4 GiB 停止线。

## 代码变更

`update --method release/cargo` 现在把安装二进制、state 重生成 typed config、新二进制 dry-run、原子替换和服务重启作为一个可回滚事务；任一步失败都会恢复二进制、配置和服务状态。旧 shoes 的 `--version` 探针也保持兼容显示。