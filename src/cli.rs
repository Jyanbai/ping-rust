use std::{
    io::Write,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm};
use uuid::Uuid;

use crate::{
    client::{self, ClientFormat},
    config::{
        self, AnyTlsMode, AnyTlsUser, GenerationOptions, GenerationRequest, Protocol,
        ShadowsocksCipher,
    },
    deployment, fast_add,
    installer::{self, InstallMethod},
    menu, operations, self_update,
    service::{self, ServiceAction},
};

#[derive(Debug, Parser)]
#[command(name = "ping-rust")]
#[command(version, about = "shoes 代理的一键安装与管理工具")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 打开数字菜单（不带子命令时的默认行为）
    Menu,
    /// 首次安装时零输入部署默认 VLESS-REALITY
    #[command(hide = true)]
    Bootstrap,
    /// 安装 shoes
    Install {
        #[arg(long, value_enum, default_value_t = InstallMethod::Release)]
        method: InstallMethod,
    },
    /// 生成服务端配置
    Generate(Box<GenerateArgs>),
    /// 像 233boy 一样快速添加配置并直接输出分享链接
    #[command(alias = "a")]
    Add(AddArgs),
    /// 管理 shoes systemd 服务
    Service {
        #[arg(value_enum)]
        action: ServiceAction,
    },
    /// 查看安装、配置和服务信息
    #[command(alias = "i")]
    Info {
        /// 配置 UUID 或名称；省略时显示全部配置
        profile: Option<String>,
    },
    /// 重新输出配置的分享链接
    Url {
        /// 配置 UUID 或名称；只有一个配置时可省略
        profile: Option<String>,
        /// 覆盖保存的服务器公网 IP 或域名
        #[arg(long)]
        server_address: Option<String>,
    },
    /// 显示配置分享链接的终端二维码
    Qr {
        /// 配置 UUID 或名称；只有一个配置时可省略
        profile: Option<String>,
        /// 覆盖保存的服务器公网 IP 或域名
        #[arg(long)]
        server_address: Option<String>,
    },
    /// 删除一个由 ping-rust 管理的配置
    Delete {
        profile: Uuid,
        /// 跳过确认保护（脚本调用时必需）
        #[arg(long)]
        yes: bool,
    },
    /// 导出客户端配置
    Export {
        #[arg(value_enum)]
        format: ClientFormat,
        /// 配置 UUID；只有一个配置时可省略
        #[arg(long)]
        profile: Option<Uuid>,
        /// VPS 公网域名或 IP
        #[arg(long)]
        server: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 查看服务日志
    Logs {
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
    },
    /// 检查 TCP/UDP 端口是否可用
    CheckPort {
        port: u16,
        #[arg(long, value_enum, default_value_t = PortKind::Both)]
        kind: PortKind,
    },
    /// 备份配置
    Backup { output: Option<PathBuf> },
    /// 恢复配置
    Restore { archive: PathBuf },
    /// 开启 BBR
    EnableBbr,
    /// 更新 shoes
    Update {
        #[arg(long, value_enum, default_value_t = InstallMethod::Release)]
        method: InstallMethod,
    },
    /// 更新 ping-rust 自身（不会修改 shoes）
    SelfUpdate {
        /// 安装指定版本，例如 v0.1.2；默认使用最新 Release
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// 即使版本相同也重新安装
        #[arg(long)]
        force: bool,
    },
    /// 卸载 shoes（默认保留配置）
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[arg(value_enum)]
    pub protocol: Protocol,
    /// 快速添加位置参数端口，例如 `prs add reality 443`
    #[arg(value_name = "PORT", conflicts_with_all = ["port", "random_port"])]
    pub legacy_port: Option<u16>,
    /// 指定监听端口
    #[arg(long, conflicts_with_all = ["legacy_port", "random_port"])]
    pub port: Option<u16>,
    /// 显式要求随机可用端口（未指定端口时本来就是默认行为）
    #[arg(long)]
    pub random_port: bool,
    /// 配置名称；默认自动生成
    #[arg(long)]
    pub name: Option<String>,
    /// 客户端连接使用的服务器公网 IP 或域名
    #[arg(long)]
    pub server_address: Option<String>,
    /// Reality SNI 或 TLS 证书名称
    #[arg(long)]
    pub server_name: Option<String>,
    /// shoes 未安装时自动确认安装
    #[arg(long)]
    pub yes: bool,
    /// stdout 只输出一行分享 URI
    #[arg(long)]
    pub plain: bool,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// 配置显示名称
    #[arg(long)]
    name: Option<String>,
    #[arg(value_enum)]
    protocol: Protocol,
    #[arg(long, default_value_t = 443)]
    port: u16,
    #[arg(long)]
    output: Option<PathBuf>,
    /// Reality 系列 SNI 或 QUIC/TLS 证书域名；Reality 未指定时随机选择非 Apple 大厂域名
    #[arg(long)]
    server_name: Option<String>,
    /// Reality fallback，格式为 host:port
    #[arg(long)]
    dest: Option<String>,
    /// Reality short ID；不指定时安全随机生成
    #[arg(long)]
    short_id: Option<String>,
    /// Reality 允许的最大时间差（毫秒）
    #[arg(long, default_value_t = 60_000)]
    reality_max_time_diff: u64,
    /// 禁用协议 UDP 支持
    #[arg(long)]
    disable_udp: bool,
    /// Hysteria2/TUIC 的 QUIC endpoint 数；0 表示跟随 shoes 线程数
    #[arg(long, default_value_t = 0)]
    quic_endpoints: usize,
    /// 为 TUIC v5 启用 0-RTT
    #[arg(long)]
    zero_rtt: bool,
    /// Shadowsocks 加密方式（默认推荐 2022 AES-256-GCM）
    #[arg(long, value_enum, default_value_t = ShadowsocksCipher::default())]
    cipher: ShadowsocksCipher,
    /// Shadowsocks 密码；2022 cipher 必须为正确长度的标准 Base64
    #[arg(long)]
    password: Option<String>,
    /// AnyTLS 外层安全模式
    #[arg(long, value_enum, default_value_t = AnyTlsMode::default())]
    anytls_mode: AnyTlsMode,
    /// AnyTLS 用户，可重复；格式为 `[名称:]密码`
    #[arg(long = "user")]
    anytls_users: Vec<AnyTlsUser>,
    /// AnyTLS padding 条目，可重复，例如 --padding stop=8 --padding 0=30-30
    #[arg(long = "padding")]
    anytls_padding: Vec<String>,
    /// AnyTLS 认证失败 fallback，格式为 host:port
    #[arg(long)]
    fallback: Option<String>,
    /// VLESS-WS-TLS/VMess-WS-TLS 的 WebSocket 路径；不指定时安全随机生成
    #[arg(long)]
    websocket_path: Option<String>,
    /// 使用 TLS 的协议预设所需 PEM 证书；不指定时生成自签名证书
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// 与 --cert 配套的 PEM 私钥
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PortKind {
    Tcp,
    Udp,
    Both,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Menu) {
        Command::Menu => menu::run().await,
        Command::Bootstrap => {
            if !bootstrap_default_reality().await? {
                println!("检测到已有 shoes 配置，跳过默认 VLESS-REALITY 部署。");
            }
            Ok(())
        }
        Command::Install { method } => {
            let report = installer::install(method, false).await?;
            service::install_unit(false)?;
            println!("{} {}", "shoes 安装成功：".green(), report.version);
            println!("来源：{}", report.source);
            println!("路径：{}", report.destination.display());
            println!("systemd unit 已写入；生成配置后再启动服务。");
            Ok(())
        }
        Command::Generate(args) => {
            let GenerateArgs {
                name,
                protocol,
                port,
                output,
                server_name,
                dest,
                short_id,
                reality_max_time_diff,
                disable_udp,
                quic_endpoints,
                zero_rtt,
                cipher,
                password,
                anytls_mode,
                mut anytls_users,
                anytls_padding,
                fallback,
                websocket_path,
                cert,
                key,
            } = *args;
            if matches!(protocol, Protocol::AnyTls) && anytls_users.is_empty() {
                anytls_users.push(config::generated_anytls_user("default"));
            }
            let server_name = config::resolve_server_name(server_name, protocol, anytls_mode);
            let output = output.unwrap_or_else(|| PathBuf::from(crate::utils::CONFIG_FILE));
            let managed = output == Path::new(crate::utils::CONFIG_FILE);
            let request = GenerationRequest {
                name,
                protocol,
                port,
                output,
                server_address: None,
                server_name,
                reality_dest: dest,
                certificate: cert,
                certificate_key: key,
                options: GenerationOptions {
                    reality_short_id: short_id,
                    reality_max_time_diff,
                    udp_enabled: !disable_udp,
                    quic_endpoints,
                    tuic_zero_rtt: zero_rtt,
                    shadowsocks_cipher: cipher,
                    shadowsocks_password: password,
                    anytls_mode,
                    anytls_users,
                    anytls_padding_scheme: (!anytls_padding.is_empty()).then_some(anytls_padding),
                    anytls_fallback: fallback,
                    websocket_path,
                },
            };
            let result = if managed {
                deployment::generate_and_activate(request).await?
            } else {
                config::generate(request).await?
            };
            print_credentials(&result);
            if managed {
                println!("{}", "配置验证通过，shoes 已启用并启动。".green());
            }
            Ok(())
        }
        Command::Add(args) => run_add(args).await,
        Command::Service { action } => service::execute(action),
        Command::Logs { lines } => service::logs(lines),
        Command::Info { profile } => show_info(profile.as_deref()).await,
        Command::Url {
            profile,
            server_address,
        } => print_saved_url(profile.as_deref(), server_address.as_deref()),
        Command::Qr {
            profile,
            server_address,
        } => print_saved_qr(profile.as_deref(), server_address.as_deref()),
        Command::Delete { profile, yes } => {
            if !yes {
                anyhow::bail!("删除配置需要显式添加 --yes；也可使用交互菜单确认");
            }
            let deleted = deployment::delete_and_activate(profile).await?;
            println!("已删除配置 {} ({})", deleted.name, deleted.id);
            Ok(())
        }
        Command::Export {
            format,
            profile,
            server,
            output,
        } => {
            let content = client::export(profile, format, &server, output.as_deref())?;
            if let Some(path) = output {
                println!("客户端配置已写入：{}", path.display());
            } else {
                println!("{content}");
            }
            Ok(())
        }
        Command::CheckPort { port, kind } => {
            let (tcp, udp) = match kind {
                PortKind::Tcp => (true, false),
                PortKind::Udp => (false, true),
                PortKind::Both => (true, true),
            };
            print_port_status(port, operations::check_port(port, tcp, udp));
            Ok(())
        }
        Command::Backup { output } => {
            let path = operations::backup(output)?;
            println!("备份已创建：{}", path.display());
            println!("备份包含私钥和密码，请按敏感文件保管。");
            Ok(())
        }
        Command::Restore { archive } => {
            let rollback = operations::restore(&archive).await?;
            println!("配置恢复成功。");
            if let Some(path) = rollback {
                println!("恢复前配置保留于：{}", path.display());
            }
            Ok(())
        }
        Command::EnableBbr => {
            operations::enable_bbr()?;
            println!("{}", "BBR 已启用并验证生效。".green());
            Ok(())
        }
        Command::Update { method } => {
            let report = update_shoes(method).await?;
            println!("{} {}", "shoes 更新完成：".green(), report.version);
            Ok(())
        }
        Command::SelfUpdate { version, force } => run_self_update(version.as_deref(), force).await,
        Command::Uninstall { purge } => {
            crate::utils::require_linux_root()?;
            let _lock =
                crate::utils::exclusive_lock(std::path::Path::new(crate::utils::LOCK_FILE))?;
            let unit_removed = service::uninstall_unit()?;
            let binary_removed = installer::uninstall_binary()?;
            let aliases_removed = crate::utils::remove_command_aliases()?;
            if purge {
                let config_dir = std::path::Path::new(crate::utils::CONFIG_DIR);
                if config_dir.exists() {
                    std::fs::remove_dir_all(config_dir)?;
                }
            }
            println!(
                "卸载完成：二进制={}，systemd={}，快捷命令清理={}，配置清理={}",
                binary_removed, unit_removed, aliases_removed, purge
            );
            Ok(())
        }
    }
}

pub(crate) async fn update_shoes(method: InstallMethod) -> Result<installer::InstallReport> {
    crate::utils::require_linux_root()?;
    let lock = crate::utils::exclusive_lock(std::path::Path::new(crate::utils::LOCK_FILE))?;
    let unit_exists = std::path::Path::new(crate::utils::SERVICE_FILE).exists();
    let was_active = unit_exists && service::is_active()?;
    let mut report = installer::install_locked(method, true, lock).await?;
    if !was_active {
        return Ok(report);
    }
    if let Err(restart) = service::restart_and_verify() {
        let binary_rollback = report.rollback_binary();
        let service_rollback = if binary_rollback.is_ok() {
            service::restart_and_verify()
        } else {
            Ok(())
        };
        return match (binary_rollback, service_rollback) {
            (Ok(()), Ok(())) => {
                Err(restart.context("新版 shoes 启动失败，旧二进制和服务已恢复"))
            }
            (Err(binary), _) => anyhow::bail!(
                "新版 shoes 启动失败且旧二进制恢复失败：启动={restart:#}；二进制={binary:#}"
            ),
            (Ok(()), Err(service)) => anyhow::bail!(
                "新版 shoes 启动失败，旧二进制已恢复但服务恢复失败：启动={restart:#}；服务={service:#}"
            ),
        };
    }
    Ok(report)
}

async fn run_add(args: AddArgs) -> Result<()> {
    ensure_shoes_for_add(args.yes).await?;
    let result = fast_add::execute(fast_add::AddRequest {
        name: args.name,
        protocol: args.protocol,
        port: args.port.or(args.legacy_port),
        server_address: args.server_address,
        server_name: args.server_name,
        shadowsocks_cipher: None,
        shadowsocks_password: None,
    })
    .await?;
    if args.plain {
        println!("{}", result.share_uri);
        return Ok(());
    }
    print_add_result(&result);
    Ok(())
}

pub(crate) async fn bootstrap_default_reality() -> Result<bool> {
    if !bootstrap_required(
        Path::new(crate::utils::CONFIG_FILE),
        Path::new(crate::utils::STATE_FILE),
    ) {
        return Ok(false);
    }
    println!();
    println!(
        "{}",
        "首次安装：自动部署 VLESS-REALITY".bright_cyan().bold()
    );
    println!("正在自动安装 shoes、选择随机端口并生成安全凭据……");
    ensure_shoes_for_add(true).await?;
    let server_address = fast_add::resolve_server_address(None).await?;
    let result = fast_add::execute(fast_add::AddRequest {
        name: Some("reality-default".to_owned()),
        protocol: Protocol::Reality,
        port: None,
        server_address: Some(server_address),
        server_name: None,
        shadowsocks_cipher: None,
        shadowsocks_password: None,
    })
    .await?;
    print_add_result(&result);
    Ok(true)
}

fn bootstrap_required(config: &Path, state: &Path) -> bool {
    !config.exists() && !state.exists()
}

pub(crate) fn print_add_result(result: &fast_add::AddResult) {
    let profile = &result.generation.profile;
    println!("{}", "部署成功，shoes 服务已启动。".green().bold());
    print_profile_details(profile, Some(&result.share_uri));
    println!("\n复制上方链接即可导入客户端。");
    println!("{}", "安全提示：分享链接包含访问凭据，请勿公开。".yellow());
}

pub(crate) fn print_profile_details(profile: &config::ManagedProfile, share_uri: Option<&str>) {
    println!("{}", profile_details_text(profile, share_uri));
}

fn profile_details_text(profile: &config::ManagedProfile, share_uri: Option<&str>) -> String {
    let mut lines = vec![format!(
        "\n-------------- {} -------------",
        profile.config_file_name()
    )];
    let address = profile.server_address.as_deref().unwrap_or("未保存");
    match &profile.credentials {
        config::Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => {
            lines.push("协议 (protocol)         = vless".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("用户ID (id)             = {user_id}"));
            lines.push("流控 (flow)             = xtls-rprx-vision".to_owned());
            lines.push("传输协议 (network)      = tcp".to_owned());
            lines.push("传输层安全 (TLS)        = reality".to_owned());
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "指纹 (Fingerprint)      = {}",
                config::REALITY_FINGERPRINT
            ));
            lines.push(format!("公钥 (Public key)       = {public_key}"));
            lines.push(format!("短 ID (shortId)         = {short_id}"));
        }
        config::Credentials::Hysteria2 {
            password,
            server_name,
            alpn_protocols,
        } => {
            lines.push("协议 (protocol)         = hysteria2".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("密码 (password)         = {password}"));
            lines.push("传输层安全 (TLS)        = tls".to_owned());
            lines.push(format!(
                "应用层协议协商 (Alpn)   = {}",
                alpn_protocols.join(",")
            ));
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "跳过证书验证 (allowInsecure) = {}",
                profile.self_signed_certificate
            ));
        }
        config::Credentials::Tuic {
            user_id,
            password,
            server_name,
            alpn_protocols,
            zero_rtt_handshake,
        } => {
            lines.push("协议 (protocol)         = tuic".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("用户ID (id)             = {user_id}"));
            lines.push(format!("密码 (password)         = {password}"));
            lines.push("传输层安全 (TLS)        = tls".to_owned());
            lines.push(format!(
                "应用层协议协商 (Alpn)   = {}",
                alpn_protocols.join(",")
            ));
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "跳过证书验证 (allowInsecure) = {}",
                profile.self_signed_certificate
            ));
            lines.push("拥塞控制算法 (congestion_control) = bbr".to_owned());
            lines.push(format!("0-RTT                   = {zero_rtt_handshake}"));
        }
        config::Credentials::Shadowsocks {
            cipher, password, ..
        } => {
            lines.push("协议 (protocol)         = shadowsocks".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("密码 (password)         = {password}"));
            lines.push(format!("加密方式 (encryption)   = {}", cipher.as_str()));
        }
        config::Credentials::AnyTls {
            users,
            server_name,
            alpn_protocols,
            security,
            ..
        } => {
            lines.push("协议 (protocol)         = anytls".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            for user in users {
                if !user.name.is_empty() {
                    lines.push(format!("用户名 (Username)      = {}", user.name));
                }
                lines.push(format!("密码 (password)         = {}", user.password));
            }
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "应用层协议协商 (Alpn)   = {}",
                alpn_protocols.join(",")
            ));
            match security {
                config::AnyTlsSecurity::Tls => {
                    lines.push("传输层安全 (TLS)        = tls".to_owned());
                    lines.push(format!(
                        "跳过证书验证 (allowInsecure) = {}",
                        profile.self_signed_certificate
                    ));
                }
                config::AnyTlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => {
                    lines.push("传输层安全 (TLS)        = reality".to_owned());
                    lines.push(format!(
                        "指纹 (Fingerprint)      = {}",
                        config::REALITY_FINGERPRINT
                    ));
                    lines.push(format!("公钥 (Public key)       = {public_key}"));
                    lines.push(format!("短 ID (shortId)         = {short_id}"));
                }
            }
        }
        config::Credentials::VlessTls {
            user_id,
            server_name,
            alpn_protocols,
            vision,
            websocket_path,
        } => {
            lines.push("协议 (protocol)         = vless".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("用户ID (id)             = {user_id}"));
            lines.push(format!(
                "流控 (flow)             = {}",
                if *vision { "xtls-rprx-vision" } else { "none" }
            ));
            lines.push(format!(
                "传输协议 (network)      = {}",
                if websocket_path.is_some() {
                    "ws"
                } else {
                    "tcp"
                }
            ));
            if let Some(path) = websocket_path {
                lines.push(format!("WebSocket 路径 (path)  = {path}"));
            }
            lines.push("传输层安全 (TLS)        = tls".to_owned());
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "应用层协议协商 (Alpn)   = {}",
                alpn_protocols.join(",")
            ));
        }
        config::Credentials::Trojan {
            password,
            server_name,
            alpn_protocols,
            security,
        } => {
            lines.push("协议 (protocol)         = trojan".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("密码 (password)         = {password}"));
            lines.push(format!("SNI (serverName)        = {server_name}"));
            match security {
                config::TlsSecurity::Tls => {
                    lines.push("传输层安全 (TLS)        = tls".to_owned());
                    lines.push(format!(
                        "应用层协议协商 (Alpn)   = {}",
                        alpn_protocols.join(",")
                    ));
                }
                config::TlsSecurity::Reality {
                    public_key,
                    short_id,
                    ..
                } => {
                    lines.push("传输层安全 (TLS)        = reality".to_owned());
                    lines.push(format!("公钥 (Public key)       = {public_key}"));
                    lines.push(format!("短 ID (shortId)         = {short_id}"));
                }
            }
        }
        config::Credentials::VmessTls {
            user_id,
            server_name,
            alpn_protocols,
            websocket_path,
        } => {
            lines.push("协议 (protocol)         = vmess".to_owned());
            lines.push(format!("地址 (address)          = {address}"));
            lines.push(format!("端口 (port)             = {}", profile.port));
            lines.push(format!("用户ID (id)             = {user_id}"));
            lines.push("加密方式 (security)     = auto".to_owned());
            lines.push("传输协议 (network)      = ws".to_owned());
            lines.push(format!("WebSocket 路径 (path)  = {websocket_path}"));
            lines.push("传输层安全 (TLS)        = tls".to_owned());
            lines.push(format!("SNI (serverName)        = {server_name}"));
            lines.push(format!(
                "应用层协议协商 (Alpn)   = {}",
                alpn_protocols.join(",")
            ));
        }
    }
    if let Some(uri) = share_uri {
        lines.push("------------- 链接 (URL) -------------".to_owned());
        lines.push(uri.to_owned());
    }
    if profile.self_signed_certificate {
        lines.push("警告! 客户端需启用跳过证书验证 (allowInsecure)，或换用受信任证书。".to_owned());
    }
    lines.push("------------- END -------------".to_owned());
    lines.join("\n")
}

pub(crate) async fn ensure_shoes_for_add(yes: bool) -> Result<()> {
    if Path::new(crate::utils::SHOES_BIN).is_file() {
        return Ok(());
    }
    let approved = yes
        || (io::stdin().is_terminal()
            && Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("shoes 尚未安装，是否从 GitHub Release 自动安装并继续？")
                .default(true)
                .interact()?);
    if !approved {
        bail!("shoes 尚未安装；请先运行 ping-rust install，或添加 --yes 自动安装");
    }
    let report = installer::install(InstallMethod::Release, false).await?;
    service::install_unit(false)?;
    eprintln!("shoes 安装成功：{}（{}）", report.version, report.source);
    Ok(())
}

pub async fn run_self_update(version: Option<&str>, force: bool) -> Result<()> {
    match self_update::update(version, force).await? {
        self_update::UpdateReport::Current { current, available } => {
            if current == available {
                println!("ping-rust 已是当前版本：{current}");
            } else {
                println!("当前版本 {current} 不低于最新 Release {available}，无需更新。");
            }
        }
        self_update::UpdateReport::Updated {
            from,
            to,
            destination,
        } => {
            println!("{} {from} → {to}", "ping-rust 自更新完成：".green());
            println!("路径：{}", destination.display());
            println!("请重新运行 ping-rust 使用新版本。");
        }
    }
    Ok(())
}

pub async fn show_info(selector: Option<&str>) -> Result<()> {
    let version = installer::installed_version()
        .await
        .unwrap_or_else(|_| "未安装".to_owned());
    let active = service::is_active().unwrap_or(false);
    println!("shoes：{version}");
    println!("二进制：{}", crate::utils::SHOES_BIN);
    println!("配置：{}", crate::utils::CONFIG_FILE);
    println!("服务：{}", if active { "运行中" } else { "未运行" });
    if !std::path::Path::new(crate::utils::STATE_FILE).exists() {
        println!("管理状态：未创建");
    } else {
        let state = config::load_state()?;
        if state.profiles.is_empty() {
            println!("配置：无");
        } else {
            let profiles = if let Some(selector) = selector {
                vec![client::select_profile(&state.profiles, Some(selector))?]
            } else {
                state.profiles.iter().collect::<Vec<_>>()
            };
            println!("配置数量：{}", profiles.len());
            for profile in profiles {
                println!(
                    "- {} | {} | 0.0.0.0:{} | {} | {}",
                    profile.id,
                    profile.name,
                    profile.port,
                    profile.protocol_name(),
                    profile.server_name()
                );
                if let Some(server) = profile.server_address.as_deref() {
                    println!("  客户端地址：{server}");
                    match client::share_uri(profile, server) {
                        Ok(uri) => println!("  URL：{uri}"),
                        Err(error) => println!("  URL：无法生成（{error}）"),
                    }
                } else {
                    println!("  URL：未保存公网地址，可用 url --server-address 指定");
                }
            }
        }
    }
    Ok(())
}

fn print_saved_url(selector: Option<&str>, server_address: Option<&str>) -> Result<()> {
    let state = config::load_state()?;
    let profile = client::select_profile(&state.profiles, selector)?;
    println!("{}", client::stored_share_uri(profile, server_address)?);
    Ok(())
}

fn print_saved_qr(selector: Option<&str>, server_address: Option<&str>) -> Result<()> {
    let state = config::load_state()?;
    let profile = client::select_profile(&state.profiles, selector)?;
    let uri = client::stored_share_uri(profile, server_address)?;
    if !crate::utils::command_exists("qrencode") {
        println!("{uri}");
        eprintln!("未安装 qrencode；请安装后重新运行 qr，URL 已输出供复制。");
        return Ok(());
    }
    let mut child = ProcessCommand::new("qrencode")
        .args(["-t", "ANSIUTF8"])
        .stdin(Stdio::piped())
        .spawn()
        .context("无法启动 qrencode")?;
    child
        .stdin
        .take()
        .context("无法打开 qrencode 标准输入")?
        .write_all(uri.as_bytes())
        .context("写入二维码内容失败")?;
    let status = child.wait().context("等待 qrencode 失败")?;
    if !status.success() {
        bail!("qrencode 执行失败（退出码：{status}）");
    }
    Ok(())
}

pub fn print_port_status(port: u16, status: operations::PortStatus) {
    if let Some(result) = status.tcp_available {
        match result {
            Ok(()) => println!("TCP {port}: {}", "可用".green()),
            Err(error) => println!("TCP {port}: {} ({error})", "被占用/不可绑定".red()),
        }
    }
    if let Some(result) = status.udp_available {
        match result {
            Ok(()) => println!("UDP {port}: {}", "可用".green()),
            Err(error) => println!("UDP {port}: {} ({error})", "被占用/不可绑定".red()),
        }
    }
}

pub fn print_credentials(result: &config::GenerationResult) {
    println!(
        "{} {}",
        "配置已写入：".green(),
        result.config_path.display()
    );
    println!("配置 ID：{}", result.profile_id);
    match &result.credentials {
        config::Credentials::Reality {
            user_id,
            private_key,
            public_key,
            short_id,
            server_name,
        } => {
            println!("协议：VLESS-Reality-Vision");
            println!("UUID：{user_id}");
            println!("SNI：{server_name}");
            println!("Short ID：{short_id}");
            println!("Reality 私钥：{private_key}");
            println!("Reality 公钥：{public_key}");
            println!(
                "{}",
                "安全提示：私钥仅保存在服务器配置中，请勿分享。".yellow()
            );
        }
        config::Credentials::Hysteria2 {
            password,
            server_name,
            alpn_protocols,
        } => {
            println!("协议：Hysteria2");
            println!("服务器名称：{server_name}");
            println!("密码：{password}");
            println!("ALPN：{}", alpn_protocols.join(", "));
            print_certificate_notice(result);
        }
        config::Credentials::Tuic {
            user_id,
            password,
            server_name,
            alpn_protocols,
            zero_rtt_handshake,
        } => {
            println!("协议：TUIC v5");
            println!("服务器名称：{server_name}");
            println!("UUID：{user_id}");
            println!("密码：{password}");
            println!("ALPN：{}", alpn_protocols.join(", "));
            println!(
                "0-RTT：{}",
                if *zero_rtt_handshake {
                    "启用"
                } else {
                    "关闭"
                }
            );
            print_certificate_notice(result);
        }
        config::Credentials::Shadowsocks {
            cipher,
            password,
            udp_enabled,
        } => {
            println!("协议：Shadowsocks");
            println!("加密：{}", cipher.as_str());
            println!("密码：{password}");
            println!("UDP：{}", if *udp_enabled { "启用" } else { "关闭" });
        }
        config::Credentials::AnyTls {
            users,
            server_name,
            alpn_protocols,
            udp_enabled,
            security,
        } => {
            println!("协议：AnyTLS");
            println!("服务器名称：{server_name}");
            println!("ALPN：{}", alpn_protocols.join(", "));
            println!("UDP：{}", if *udp_enabled { "启用" } else { "关闭" });
            for user in users {
                let label = if user.name.is_empty() {
                    "default"
                } else {
                    &user.name
                };
                println!("用户 {label}：{}", user.password);
            }
            match security {
                config::AnyTlsSecurity::Tls => print_certificate_notice(result),
                config::AnyTlsSecurity::Reality {
                    private_key,
                    public_key,
                    short_id,
                } => {
                    println!("Short ID：{short_id}");
                    println!("Reality 私钥：{private_key}");
                    println!("Reality 公钥：{public_key}");
                    println!("{}", "安全提示：Reality 私钥不得导出或分享。".yellow());
                }
            }
        }
        config::Credentials::VlessTls {
            user_id,
            server_name,
            alpn_protocols,
            vision,
            websocket_path,
        } => {
            println!(
                "协议：{}",
                if websocket_path.is_some() {
                    "VLESS-WS-TLS"
                } else if *vision {
                    "VLESS-TLS-Vision"
                } else {
                    "VLESS-TLS"
                }
            );
            println!("UUID：{user_id}");
            println!("服务器名称：{server_name}");
            println!("ALPN：{}", alpn_protocols.join(", "));
            if let Some(path) = websocket_path {
                println!("WebSocket 路径：{path}");
            }
            print_certificate_notice(result);
        }
        config::Credentials::Trojan {
            password,
            server_name,
            security,
            ..
        } => {
            println!("协议：{}", result.profile.protocol_name());
            println!("密码：{password}");
            println!("服务器名称：{server_name}");
            match security {
                config::TlsSecurity::Tls => print_certificate_notice(result),
                config::TlsSecurity::Reality {
                    private_key,
                    public_key,
                    short_id,
                } => {
                    println!("Short ID：{short_id}");
                    println!("Reality 私钥：{private_key}");
                    println!("Reality 公钥：{public_key}");
                    println!("{}", "安全提示：Reality 私钥不得导出或分享。".yellow());
                }
            }
        }
        config::Credentials::VmessTls {
            user_id,
            server_name,
            alpn_protocols,
            websocket_path,
        } => {
            println!("协议：VMess-WS-TLS");
            println!("UUID：{user_id}");
            println!("服务器名称：{server_name}");
            println!("ALPN：{}", alpn_protocols.join(", "));
            println!("WebSocket 路径：{websocket_path}");
            print_certificate_notice(result);
        }
    }
}

fn print_certificate_notice(result: &config::GenerationResult) {
    if let Some(cert) = &result.certificate_path {
        println!("证书：{}", cert.display());
    }
    if let Some(key) = &result.certificate_key_path {
        println!("私钥：{}", key.display());
    }
    println!(
        "{}",
        "若使用自动生成的自签名证书，生产环境应将证书导入客户端信任库；不要长期关闭证书校验。"
            .yellow()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_self_update_options() {
        let cli =
            Cli::try_parse_from(["ping-rust", "self-update", "--version", "v0.1.2", "--force"])
                .unwrap();
        match cli.command.unwrap() {
            Command::SelfUpdate { version, force } => {
                assert_eq!(version.as_deref(), Some("v0.1.2"));
                assert!(force);
            }
            command => panic!("unexpected command: {command:?}"),
        }
    }

    #[test]
    fn keeps_shoes_update_as_distinct_command() {
        let cli = Cli::try_parse_from(["ping-rust", "update"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Update {
                method: InstallMethod::Release
            })
        ));
    }

    #[test]
    fn parses_new_protocol_options_without_changing_generate_shape() {
        let ss = Cli::try_parse_from([
            "ping-rust",
            "generate",
            "shadowsocks",
            "--cipher",
            "2022-blake3-aes-128-gcm",
        ])
        .unwrap();
        let Some(Command::Generate(args)) = ss.command else {
            panic!("expected generate command");
        };
        assert_eq!(args.protocol, Protocol::Shadowsocks);
        assert_eq!(args.cipher, ShadowsocksCipher::Aes128Gcm2022);

        let anytls = Cli::try_parse_from([
            "ping-rust",
            "generate",
            "anytls",
            "--anytls-mode",
            "reality",
            "--user",
            "alice:secret",
            "--padding",
            "stop=8",
        ])
        .unwrap();
        let Some(Command::Generate(args)) = anytls.command else {
            panic!("expected generate command");
        };
        assert_eq!(args.protocol, Protocol::AnyTls);
        assert_eq!(args.anytls_mode, AnyTlsMode::Reality);

        let websocket = Cli::try_parse_from([
            "ping-rust",
            "generate",
            "vless-ws-tls",
            "--websocket-path",
            "/vless",
        ])
        .unwrap();
        let Some(Command::Generate(args)) = websocket.command else {
            panic!("expected generate command");
        };
        assert_eq!(args.protocol, Protocol::VlessWsTls);
        assert_eq!(args.websocket_path.as_deref(), Some("/vless"));

        for protocol in ["vless-tls", "trojan-tls", "trojan-reality", "vmess-ws-tls"] {
            assert!(Cli::try_parse_from(["prs", "add", protocol]).is_ok());
        }
    }

    #[test]
    fn parses_prs_add_aliases_and_output_controls() {
        let cli = Cli::try_parse_from([
            "prs",
            "a",
            "r",
            "443",
            "--server-address",
            "203.0.113.9",
            "--yes",
            "--plain",
        ])
        .unwrap();
        let Some(Command::Add(args)) = cli.command else {
            panic!("expected add command");
        };
        assert_eq!(args.protocol, Protocol::Reality);
        assert_eq!(args.legacy_port, Some(443));
        assert!(args.yes);
        assert!(args.plain);

        let cli = Cli::try_parse_from(["prs", "add", "ss", "--random-port"]).unwrap();
        let Some(Command::Add(args)) = cli.command else {
            panic!("expected add command");
        };
        assert_eq!(args.protocol, Protocol::Shadowsocks);
        assert!(args.random_port);
    }

    #[test]
    fn rejects_conflicting_fast_add_port_options() {
        assert!(Cli::try_parse_from(["prs", "add", "reality", "443", "--random-port"]).is_err());
    }

    #[test]
    fn parses_info_url_and_qr_commands() {
        assert!(matches!(
            Cli::try_parse_from(["prs", "i", "main"]).unwrap().command,
            Some(Command::Info { profile: Some(profile) }) if profile == "main"
        ));
        assert!(matches!(
            Cli::try_parse_from(["prs", "url", "main"]).unwrap().command,
            Some(Command::Url { profile: Some(profile), .. }) if profile == "main"
        ));
        assert!(matches!(
            Cli::try_parse_from(["prs", "qr", "main"]).unwrap().command,
            Some(Command::Qr { profile: Some(profile), .. }) if profile == "main"
        ));
    }

    #[test]
    fn bootstrap_only_runs_when_both_managed_files_are_absent() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        assert!(bootstrap_required(&config, &state));
        std::fs::write(&config, b"servers: []").unwrap();
        assert!(!bootstrap_required(&config, &state));
        std::fs::remove_file(&config).unwrap();
        std::fs::write(&state, b"{}").unwrap();
        assert!(!bootstrap_required(&config, &state));
        assert!(matches!(
            Cli::try_parse_from(["ping-rust", "bootstrap"])
                .unwrap()
                .command,
            Some(Command::Bootstrap)
        ));
    }

    #[test]
    fn shadowsocks_details_include_import_fields() {
        let profile = config::ManagedProfile {
            id: Uuid::nil(),
            name: "ss-main".to_owned(),
            port: 34333,
            server_address: Some("203.0.113.8".to_owned()),
            credentials: config::Credentials::Shadowsocks {
                cipher: ShadowsocksCipher::Aes256Gcm2022,
                password: "generated-password".to_owned(),
                udp_enabled: true,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let output = profile_details_text(&profile, Some("ss://import-link"));
        for expected in [
            "SHADOWSOCKS-34333.yaml",
            "协议 (protocol)         = shadowsocks",
            "地址 (address)          = 203.0.113.8",
            "端口 (port)             = 34333",
            "密码 (password)         = generated-password",
            "加密方式 (encryption)   = 2022-blake3-aes-256-gcm",
            "ss://import-link",
            "------------- END -------------",
        ] {
            assert!(
                output.contains(expected),
                "missing {expected:?} in {output}"
            );
        }
    }

    #[test]
    fn all_protocol_details_include_client_fields() {
        let reality = config::ManagedProfile {
            id: Uuid::nil(),
            name: "reality".to_owned(),
            port: 443,
            server_address: Some("203.0.113.8".to_owned()),
            credentials: config::Credentials::Reality {
                user_id: Uuid::nil(),
                private_key: "never-print-private".to_owned(),
                public_key: "reality-public".to_owned(),
                short_id: "0123456789abcdef".to_owned(),
                server_name: "www.cloudflare.com".to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let reality_uri = client::share_uri(&reality, "203.0.113.8").unwrap();
        let reality_output = profile_details_text(&reality, Some(&reality_uri));
        for expected in [
            "协议 (protocol)         = vless",
            "用户ID (id)",
            "xtls-rprx-vision",
            "reality-public",
            "0123456789abcdef",
            "vless://",
        ] {
            assert!(reality_output.contains(expected));
        }
        assert!(!reality_output.contains("never-print-private"));

        let hysteria2 = config::ManagedProfile {
            id: Uuid::nil(),
            name: "hysteria2".to_owned(),
            port: 2443,
            server_address: Some("203.0.113.8".to_owned()),
            credentials: config::Credentials::Hysteria2 {
                password: "hy2-password".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let hysteria2_uri = client::share_uri(&hysteria2, "203.0.113.8").unwrap();
        let hysteria2_output = profile_details_text(&hysteria2, Some(&hysteria2_uri));
        for expected in [
            "协议 (protocol)         = hysteria2",
            "密码 (password)         = hy2-password",
            "应用层协议协商 (Alpn)   = h3",
            "allowInsecure) = true",
            "hysteria2://",
        ] {
            assert!(hysteria2_output.contains(expected));
        }

        let tuic = config::ManagedProfile {
            id: Uuid::nil(),
            name: "tuic".to_owned(),
            port: 3443,
            server_address: Some("203.0.113.8".to_owned()),
            credentials: config::Credentials::Tuic {
                user_id: Uuid::nil(),
                password: "tuic-password".to_owned(),
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h3".to_owned()],
                zero_rtt_handshake: false,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let tuic_uri = client::share_uri(&tuic, "203.0.113.8").unwrap();
        let tuic_output = profile_details_text(&tuic, Some(&tuic_uri));
        for expected in [
            "协议 (protocol)         = tuic",
            "用户ID (id)",
            "密码 (password)         = tuic-password",
            "congestion_control) = bbr",
            "tuic://",
        ] {
            assert!(tuic_output.contains(expected));
        }

        let anytls = config::ManagedProfile {
            id: Uuid::nil(),
            name: "anytls".to_owned(),
            port: 4443,
            server_address: Some("203.0.113.8".to_owned()),
            credentials: config::Credentials::AnyTls {
                users: vec![config::AnyTlsUser {
                    name: "default".to_owned(),
                    password: "anytls-password".to_owned(),
                }],
                server_name: "proxy.example.com".to_owned(),
                alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                udp_enabled: true,
                security: config::AnyTlsSecurity::Tls,
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let anytls_uri = client::share_uri(&anytls, "203.0.113.8").unwrap();
        let anytls_output = profile_details_text(&anytls, Some(&anytls_uri));
        for expected in [
            "协议 (protocol)         = anytls",
            "用户名 (Username)      = default",
            "密码 (password)         = anytls-password",
            "传输层安全 (TLS)        = tls",
            "anytls://",
        ] {
            assert!(anytls_output.contains(expected));
        }
    }
}
