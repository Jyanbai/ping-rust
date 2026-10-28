# shoes v0.3.6 升级报告（B 阶段）

## 范围

本阶段只完成 shoes v0.3.6 的迁移、兼容夹具和外部客户端验收；不合并、不发版、不推 tag，也没有开始 C 阶段。

- Release：`v0.3.6`
- shoes schema revision：`3737e07467387044e677ae7cf8b1c16d291f1b68`
- x86_64 musl SHA-256：`d09a9f5915ae8c3fc933bd86c025f2d8878d45e1dee8f0e2bb404c920de8c707`

## GitHub Actions 结果

[CI run 40653499936](https://github.com/Jyanbai/ping-rust/actions/runs/40653499936) 通过，包含 Ubuntu 22.04/24.04、Debian 12、Rocky 9、AlmaLinux 9、systemd 迁移和外部客户端 job。systemd 与外部客户端记录分别保存在 `shoes-upgrade-migration-records` 和 `external-client-acceptance-records` artifact。Xray `v26.6.27`/`v25.5.16`、Mihomo `v1.19.33`、旧 ping-rust `v0.2.2` 和 shoes `v0.3.6` 均固定版本并校验 SHA-256；校验失败时脚本立即中止。

### 老用户升级路径

systemd 容器 job `Debian 12 v0.2.2 to shoes v0.3.6 migration`（run `40653499936`，job `122698908987`）实际结果：

- 固定下载并校验 ping-rust v0.2.2 Release：SHA256SUMS 和资产均通过；旧 Release 安装 shoes v0.2.7。
- Reality、Snell（默认 cipher）和 Chain 2.0 通配符规则均建立；旧 shoes 服务 active。
- 只替换 ping-rust 后，`info` 的配置数量、名称、凭据和服务状态一致；v0.2.7 不支持 `--version` 时，新版本现在保留 `shoes（CLI 未提供版本参数）` 的兼容显示。
- 新 ping-rust 尝试新增节点时，v0.2.7 拒绝 typed rule，服务不受影响；原始记录为：`请先升级 shoes 到 v0.3.6 后再修改配置：... invalid rules: data did not match any variant of untagged enum NoneOrSome`。
- 升级事务安装 v0.3.6、从 state 重写配置、以新二进制 dry-run、原子提交并重启均通过。升级前后 state SHA-256 保持 `af8a3e5b8370b2fc6aef4abfacc59ea800f8e6cb8f99906460f4e21e9c016ddc`，config SHA-256 由 `8660be2bd431f367be6ed5e35393e2b886756a6c87d86e472e80e56114fc3984` 变为 `0910a4ed7c5c2ee3dcc908e717dd84b4f2b1326276bbe2fc38a5ec88e70ddc44`；MainPID `2716 → 2814`，服务 active，监听 24431/24432，规则已变成 `domain_pattern`。
- 迁移后的 Reality 节点完整代理探测通过（81 ms），完整 Chain 探测通过（42 ms）；本地 HTTP 204 端点记录两次 GET。

### 夹具和迁移必要性

`tests/fixtures/yaml/chain-v2/` 已恢复为 main 上的 v0.2.x 磁盘格式；新写法放在 `tests/fixtures/yaml/chain-v036/`。新增测试覆盖：

- 旧 state 重新生成得到 `domain_pattern`；
- 旧 `config.yaml` 交给 v0.3.6 dry-run 被拒绝。

在 CI 提供历史绝对路径所需的证书、以 root 执行原样旧夹具的 dry-run 后，v0.3.6 报：`legacy wildcard mask "*.example.com" is unsupported; use subdomains or domain_pattern`。独立的旧通配符最小配置报：`legacy wildcard mask "*.example.test" is unsupported; use subdomains or domain_pattern`，证明规则迁移必要。旧夹具还包含脱敏占位 UUID；单独的无效 UUID dry-run 原文为：`UUID is not version 4: 85296b07-fa5c-63a7-d8f2-cdef418defa3`。新夹具的 UUID 改动是**脱敏占位数据的更正**。ping-rust 新生成 UUID 的代码位置包括 `src/config/presets/reality.rs:25`、`src/config.rs:920` 和 `src/config.rs:1708`，均调用 `Uuid::new_v4()`。

### Reality 与 Xray

外部客户端 job（job `122698909183`，run `40653499936`）固定 Xray `v26.6.27` 和最低版本 `v25.5.16`，逐个覆盖六个文档 SNI：`www.amazon.com`、`www.ebay.com`、`www.paypal.com`、`www.cloudflare.com`、`dash.cloudflare.com`、`aws.amazon.com`。六项均 **PASS**：完成 Reality 握手并经代理取得本地 HTTP marker。最低版本 `v25.5.16` 对 `www.cloudflare.com` 的同一探测也 **PASS**。

### Snell 与 Mihomo

同一 job 固定 Mihomo `v1.19.33`。AES-128-GCM 的客户端 YAML 来自 `ping-rust export clash-meta`，经代理取得本地 HTTP marker，结果 **PASS**。另外两个 cipher 按 Mihomo schema 手写：`aes-256-gcm=FAIL`、`chacha20-ietf-poly1305=FAIL`。两者的 Mihomo 请求均返回 HTTP 502，shoes 均报 `failed to setup server stream: open failed for length`。Mihomo Snell 客户端 schema 没有 cipher 字段；失败是实际兼容性发现，原始日志保存在 artifact 中。

### 其他 CI

bero 上的 Rust 测试 job `ping-rust-btest-5` 为 209 passed、0 failed、2 ignored；`ping-rust-bclippy-2` 通过，fmt 通过。CI 的 Release 安装协议、source matrix、schema dry-run、热重载和多发行版 jobs 通过。systemd 与外部客户端验收在 GitHub Actions 完成。

## bero 磁盘记录

清理只涉及 `/home/agent/cargo-target`；每次删除前确认没有 cargo 进程，并记录根分区精确可用字节数。没有删除其它文件。

| 事件 | 删除前 `/` 可用 | 删除前 target | 删除后 `/` 可用 |
| --- | ---: | ---: | ---: |
| 首次测试退出码 75 | 4,297,568,256 B | 1,336,283,136 B | 5,633,851,392 B |
| 后续测试退出码 75 | 4,264,329,216 B | 1,362,337,792 B | 5,626,667,008 B |
| Release 退出码 75 | 4,291,174,400 B | 1,332,899,840 B | 5,624,074,240 B |

最后一次清理后 `~/cargo-target` 不存在（按 0 B 计），根分区可用 5,624,074,240 B，约 5.24 GiB，高于 4 GiB 停止线。

## 代码变更

`update --method release/cargo` 现在把安装二进制、state 重生成 typed config、新二进制 dry-run、原子替换和服务重启作为一个可回滚事务；失败时恢复二进制、配置和服务状态。CI 已验证成功迁移路径，尚未注入故障验证回滚路径。旧 shoes 的 `--version` 探针也保持兼容显示。
