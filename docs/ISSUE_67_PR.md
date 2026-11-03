# issue #67 PR 说明

Closes #67

交互菜单改用纯文本输入，文本、密码和确认中的 `0` 取消当前操作并返回所属菜单。
数字菜单编号、选项文字和配置提交/回滚流程保持原样；CLI 提示仍受原有终端判断保护，
`bootstrap` / `install-self` 的非交互路径未增加 stdin 读取。

## 实现与依赖

- 新增 `src/menu/input.rs`：注入 `BufRead` + `Write` 的文本、确认、密码、数字读取函数；区分取消与 `MenuEof`，无效输入打印 `错误！` 后重问。
- 终端密码读取使用 `console::Term::read_secure_line`，不回显；空密码的安全随机生成语义保留。
- `console = "=0.15.11"` 来自已有锁文件，作为直接依赖用于安全输入。dialoguer 已没有使用点，删除它及不再需要的传递依赖；未引入新的 crate。
- 输入校验复用已有配置校验器，仅扩大这些函数在 crate 内的可见性；没有修改 SNI 规则或配置写入实现。
- 读取期间不持有 stdout 锁，让 Ctrl+C 的独立信号处理任务能够恢复光标并退出 130。
- 删除配置、删除链式节点、重新生成凭据/密钥、恢复覆盖、卸载及清除配置的确认均默认 N。BBR 写入会覆盖专用 sysctl 文件，因此确认也改为默认 N。

## 返回与空输入例外

1. H2MUX `Max connections`：`0` 是数值，回车保持当前 `max_connections`，提示明确标记 `0 为合法值`。
2. H2MUX `Min streams`：`0` 是数值，回车保持当前 `min_streams`。
3. H2MUX `Max streams`：`0` 是数值，回车保持当前 `max_streams`。三个参数的组合仍须满足原有校验，不合法时打印错误重新询问；随后 padding 确认可输入 `0` 取消整次编辑。

所有交互名称输入（配置、链式节点、Pool、Chain、规则、用户名）不能再输入 `0` 作为名称；它统一表示返回。
已有名称为 `0` 的磁盘状态不改写，读取旧状态的规则不变；此类名称作默认值时，回车会提示更换名称。

原先明确允许空输入的地方继续保留含义：密码/密钥和部分用户名安全生成、快速添加端口随机分配、地址自动检测、首次部署跳过、未配置的静态 fallback 保持关闭。
静态 fallback 的原终端预填内容改为文本默认值，回车保持当前路径；为保留清空能力，提示“输入 - 关闭”，在输入层将 `-` 转成原来的空值，再交给原写入处理。未配置 fallback 时回车仍表示关闭。
H2MUX 提示展示实际当前值（包括 `0`），不再将当前 `0` 替换成 4 或 8。

## 提示清单

替换 **78 个 dialoguer 构造点**：`src/menu.rs` 71 个、`src/cli.rs` 6 个、`src/menu/chain.rs` 的共享构造点 1 个。
另外将快速添加的原生端口读取与共享数字菜单读取接入输入模块。
下面按实际问询位置展开链式菜单的共享函数，共 **90 个提示位置**（menu 72、cli 6、chain 12）；动态值用字段名或中文占位说明。
共用数字菜单提示仍为 `请选择 [0-N]:`，其读取入口是 `src/menu.rs` 的 `read_menu_choice`，实现位于 `src/menu/input.rs`；各数字菜单标题/选项不变，不重复计入 90 个位置。

| 文件:行号 | 新提示文字 |
|---|---|
| `src/menu.rs:463` | 开启 Vision？ [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:472` | 输入新端口（输入 r 随机分配）（默认：当前端口，输入 0 返回）： |
| `src/menu.rs:499` | 新配置名称（默认：当前配置名称，输入 0 返回）： |
| `src/menu.rs:509` | VPS 公网域名或 IP（留空自动检测）（输入 0 返回）： |
| `src/menu.rs:523` | 确认重新生成凭据？旧分享链接将立即失效 [y/N]（输入 0 返回）： |
| `src/menu.rs:530` | 新密码（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:550` | 新 SNI（默认：当前 SNI，输入 0 返回）： |
| `src/menu.rs:592` | ShadowTLS 密码（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:607` | ShadowTLS SNI（默认：shadowtls.server_name，输入 0 返回）： |
| `src/menu.rs:623` | Handshake destination（host:port）（默认：shadowtls.handshake_address，输入 0 返回）： |
| `src/menu.rs:644` | SOCKS5 用户名（默认：current，输入 0 返回）： |
| `src/menu.rs:651` | 启用用户名 + 密码认证？ [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:668` | 启用 UDP ASSOCIATE？ / 启用 Snell UDP-over-TCP？ / 启用 NaiveProxy UDP-over-TCP？ [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:693` | 新密码（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:705` | NaiveProxy 用户名（默认：username，输入 0 返回）： |
| `src/menu.rs:710` | NaiveProxy SNI（默认：当前 SNI，输入 0 返回）： |
| `src/menu.rs:720` | 启用 NaiveProxy padding？ [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:726` | 静态 fallback 绝对路径（输入 - 关闭）（默认：当前路径（已有 fallback 时），输入 0 返回）： |
| `src/menu.rs:743` | PEM 证书路径（输入 0 返回）： |
| `src/menu.rs:744` | PEM 私钥路径（输入 0 返回）： |
| `src/menu.rs:812` | 确认删除 {}？ [y/N]（输入 0 返回）： |
| `src/menu.rs:845` | 检查端口（默认：443，输入 0 返回）： |
| `src/menu.rs:850` | 写入 sysctl 配置并启用 BBR？ [y/N]（输入 0 返回）： |
| `src/menu.rs:863` | 备份文件路径（输入 0 返回）： |
| `src/menu.rs:864` | 恢复会替换当前配置，继续？ [y/N]（输入 0 返回）： |
| `src/menu.rs:886` | 粘贴分享链接（输入 0 返回）： |
| `src/menu.rs:896` | 节点名称（默认：parsed.name，输入 0 返回）： |
| `src/menu.rs:936` | 所选出口不支持 UDP-over-TCP，UDP 请求将失败；仍要切换？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1021` | Max connections（当前：current.max_connections，直接回车保持当前值，0 为合法值）： |
| `src/menu.rs:1022` | Min streams（当前：current.min_streams，直接回车保持当前值，0 为合法值）： |
| `src/menu.rs:1026` | Max streams（当前：current.max_streams，直接回车保持当前值，0 为合法值）： |
| `src/menu.rs:1028` | 启用 H2MUX padding？ [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:1047` | 确认删除链式节点 {}？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1076` | VPS 公网域名或 IP（输入 0 返回）： |
| `src/menu.rs:1124` | 请输入端口（直接回车随机）（输入 0 返回）： |
| `src/menu.rs:1137` | 请输入域名/SNI（输入 0 返回）： |
| `src/menu.rs:1146` | PEM 证书路径（输入 0 返回）： |
| `src/menu.rs:1147` | PEM 私钥路径（输入 0 返回）： |
| `src/menu.rs:1183` | 请设置密码（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1367` | 开启 Vision？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1394` | 重新生成密钥？（会使刚才的分享链接失效） [y/N]（输入 0 返回）： |
| `src/menu.rs:1452` | 请输入 VPS 公网域名或 IP（输入 0 返回）： |
| `src/menu.rs:1469` | 配置名称（默认：协议名，输入 0 返回）： |
| `src/menu.rs:1472` | 监听端口（默认：443，输入 0 返回）： |
| `src/menu.rs:1524` | SS2022 密钥（留空则安全生成）（输入 0 返回）： |
| `src/menu.rs:1526` | ShadowTLS 密码（留空则安全生成）（输入 0 返回）： |
| `src/menu.rs:1528` | ShadowTLS SNI（默认：当前协议默认 SNI，输入 0 返回）： |
| `src/menu.rs:1535` | Handshake destination（host:port）（默认：{sni}:443，输入 0 返回）： |
| `src/menu.rs:1550` | Snell v3 密码（留空则安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1552` | 启用 Snell UDP-over-TCP？ [Y/n]（输入 0 返回）： |
| `src/menu.rs:1561` | SOCKS5 用户名（留空则安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1563` | SOCKS5 密码（留空则安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1569` | 启用 UDP ASSOCIATE？ [Y/n]（输入 0 返回）： |
| `src/menu.rs:1587` | AnyTLS 用户名（默认：default_name，输入 0 返回）： |
| `src/menu.rs:1588` | AnyTLS 密码（留空则安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1597` | 继续添加 AnyTLS 用户？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1601` | 使用推荐 padding_scheme？ [Y/n]（输入 0 返回）： |
| `src/menu.rs:1608` | 配置认证失败 fallback？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1609` | AnyTLS fallback（host:port）（默认：127.0.0.1:80，输入 0 返回）： |
| `src/menu.rs:1618` | NaiveProxy 用户名（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1620` | NaiveProxy 密码（留空安全随机生成）（输入 0 返回）： |
| `src/menu.rs:1622` | 启用 NaiveProxy padding？ [Y/n]（输入 0 返回）： |
| `src/menu.rs:1623` | 配置静态 fallback 目录？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1624` | fallback 绝对路径（输入 0 返回）： |
| `src/menu.rs:1644` | Reality SNI / 证书域名/服务器名称（默认：default_server_name，输入 0 返回）： |
| `src/menu.rs:1656` | Reality fallback（默认：{server_name}:443，输入 0 返回）： |
| `src/menu.rs:1667` | 使用已有受信任 PEM 证书和私钥？（推荐） / 使用已有 PEM 证书和私钥？（否则自动生成自签名证书） [Y/n 或 y/N，按当前值]（输入 0 返回）： |
| `src/menu.rs:1675` | PEM 证书路径（输入 0 返回）： |
| `src/menu.rs:1676` | PEM 私钥路径（输入 0 返回）： |
| `src/menu.rs:1751` | 安装 shoes GitHub Release {target}（高级选项）？ / 明确允许降级？ / 确认来源未知的旧安装后允许安装？ [y/N]（输入 0 返回）： |
| `src/menu.rs:1780` | 确认卸载 shoes？默认保留 /etc/shoes 配置 [y/N]（输入 0 返回）： |
| `src/menu.rs:1783` | 同时永久删除 /etc/shoes 配置与凭据？ [y/N]（输入 0 返回）： |
| `src/cli.rs:776` | NaiveProxy 域名 / SNI（输入 0 返回）： |
| `src/cli.rs:794` | PEM 证书路径（输入 0 返回）： |
| `src/cli.rs:795` | PEM 私钥路径（输入 0 返回）： |
| `src/cli.rs:896` | 请输入 VPS 公网域名或 IP（直接回车跳过默认部署）（输入 0 返回）： |
| `src/cli.rs:1405` | shoes 尚未安装，是否从 GitHub Release 自动安装并继续？ [Y/n]（输入 0 返回）： |
| `src/cli.rs:784` | TLS 证书模式；1) 使用已有受信任证书（推荐），2) 自签名证书（仅测试，不推荐），0) 返回；请选择 [0-2]: |
| `src/menu/chain.rs:190` | 新名称（默认：node.name，输入 0 返回）： |
| `src/menu/chain.rs:257` | 成员编号（逗号分隔）（输入 0 返回）： |
| `src/menu/chain.rs:297` | Pool 名称（输入 0 返回）： |
| `src/menu/chain.rs:324` | 新名称（默认：pool.name，输入 0 返回）： |
| `src/menu/chain.rs:363` | 按顺序输入 hop 编号（逗号分隔）（输入 0 返回）： |
| `src/menu/chain.rs:443` | Chain 名称（输入 0 返回）： |
| `src/menu/chain.rs:470` | 新名称（默认：chain.name，输入 0 返回）： |
| `src/menu/chain.rs:539` | Chain 编号（至少两个，逗号分隔）（输入 0 返回）： |
| `src/menu/chain.rs:611` | 规则名称（输入 0 返回）： |
| `src/menu/chain.rs:612` | Masks（逗号分隔）（输入 0 返回）： |
| `src/menu/chain.rs:637` | 新名称（默认：rule.name，输入 0 返回）： |
| `src/menu/chain.rs:641` | Masks（逗号分隔）（默认：当前 masks（逗号分隔），输入 0 返回）： |

## 现有 expect 匹配逐条修改

`tests/chain_menu.exp` 的五处修改均收紧到新提示，未匹配任意内容：

1. `share URI prompt`：`粘贴分享链接` → `粘贴分享链接（输入 0 返回）：`，验证统一返回提示。
2. `node name prompt`：`节点名称` → `节点名称（默认：[^\r\n]+，输入 0 返回）：`，验证动态默认名称及返回提示，动态部分限制在一行内。
3. `pool name prompt`：`Pool 名称` → `Pool 名称（输入 0 返回）：`，验证无默认值格式。
4. `pool member prompt`：`成员编号` → `成员编号（逗号分隔）（输入 0 返回）：`，保留字段语义并验证返回提示。
5. `delete confirmation`：`确认删除链式节点` → `确认删除链式节点 [^\r\n]+？ \[y/N\]（输入 0 返回）：`，验证动态节点名称、默认 N 与返回提示。

`scripts/ci/legacy-chain-menu.exp`、`tests/fixtures/`、`.github/` 均未修改。
已有 Rust 断言没有删除或放宽；`input_errors_and_cancellation_are_classified` 将
`dialoguer::Error` 包装的 `UnexpectedEof` 改成同一种 `io::Error`，继续断言 EOF 导致退出，原因是删除了 dialoguer 依赖。

## 验证

- `cargo fmt --all -- --check`：通过。
- `cargo build --offline --locked`：通过。
- `cargo clippy --offline --locked --all-targets -- -D warnings`：通过。
- `cargo test --offline --locked menu:: --bin ping-rust -- --nocapture`：20 通过，其中新输入模块 6 项。
- `cargo test --offline --locked`：已尝试，226 通过、8 失败、3 忽略；失败来自缺少 shoes 密钥生成器（2 项）和沙箱禁止绑定本地端口（6 项）。该次运行在补充最后 2 项输入模块测试前。
- 显式排除上述 8 项后运行 bin 单元测试：228 通过、3 忽略、8 过滤。没有更改或放宽这些测试。
- `cargo test --offline --locked --test menu_input_e2e -- --nocapture`：Rust 调用入口已运行，因未设置开关而跳过 expect；另外已用 `PING_RUST_MENU_E2E=1` 实跑调用入口，输出“系统未安装 expect”并跳过。**真实终端、shoes、systemd 验收：沙箱未运行，待 CI。**
- `tclsh` 检查两个当前版本 expect 脚本的 `info complete`：通过，仅证明 Tcl 语句结构完整，不表示终端测试通过。
- CI 9 个必需检查：未验证，待推送后的 CI。本 PR 没有修改 workflow 或接入新任务。

全量单元测试受环境限制的八项：

```text
config::tests::every_registered_protocol_supports_base_changes_and_credential_regeneration
config::vless_encryption_tests::vless_enc_mode_auth_and_regeneration_use_shoes_and_keep_state_public
fast_add::tests::socks5_random_port_is_valid
github_api::tests::github_api_exhaustion_and_nonretry_errors_do_not_leak_secrets
github_api::tests::github_api_optional_auth_and_status_recovery
github_api::tests::github_api_transient_disconnect_retries
github_api::tests::github_api_truncated_json_body_retries
operations::tests::port_check_reports_requested_protocols
```

### 终端回归条件

```sh
sudo env PING_RUST_MENU_E2E=1 cargo test --offline --locked --test menu_input_e2e -- --nocapture
```

仅 Linux + `expect` 已安装 + `PING_RUST_MENU_E2E=1` 才运行脚本，其他情况打印跳过原因。
运行时还需要 root、专用测试机和 `/etc/shoes` 中至少一个已初始化、节点文件齐全的当前版本配置。
脚本只操作取消/无效输入，不负责创建节点；无需 shoes 运行或 systemd 可用，也不联网。
如果预置配置需要迁移，先在测试机用 shoes 完成迁移再运行。
脚本记录完整菜单交互，覆盖端口 `0` 返回、更名 `0` 返回、删除确认回车取消、无效端口重问、主菜单与文本框 EOF、Ctrl+C 恢复光标及退出 130。
Rust 调用方比较测试前后的 `/etc/shoes` 文件内容，防止取消路径意外改动配置。

### 三段实际输入模块运行记录

以下来自 `plain_text_input_transcripts` 的实际输出，使用注入 I/O，**不是完整 `sudo prs` 的 PTY 记录**。
方括号标出测试注入的按键和返回结果，模块本身不回显输入。完整菜单的三段 PTY 验收记录仍待 CI 按上述脚本采集。

```text
请选择 [0-10]: [注入输入：2]
新配置名称（默认：example-node，输入 0 返回）：[注入输入：0；返回上一级]
```

```text
确认删除 example-node？ [y/N]（输入 0 返回）：[注入输入：回车；确认结果：否]
```

```text
新端口（默认：443，输入 0 返回）：错误！请输入 1 到 65535 的端口: number too large to fit in target type
新端口（默认：443，输入 0 返回）：[依次注入：65536、443；读取结果：443]
```
