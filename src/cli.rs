use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use uuid::Uuid;

use crate::{
    client::{self, ClientFormat},
    config::{self, GenerationRequest, Protocol},
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
    /// 安装 shoes
    Install {
        #[arg(long, value_enum, default_value_t = InstallMethod::Release)]
        method: InstallMethod,
    },
    /// 生成服务端配置
    Generate {
        /// 配置显示名称
        #[arg(long)]
        name: Option<String>,
        #[arg(value_enum)]
        protocol: Protocol,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Reality SNI 或 QUIC 证书域名
        #[arg(long, default_value = config::DEFAULT_SNI)]
        server_name: String,
        /// Reality fallback，格式为 host:port
        #[arg(long)]
        dest: Option<String>,
        /// Hysteria2/TUIC PEM 证书；不指定时生成自签名证书
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// Hysteria2/TUIC PEM 私钥
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
    },
    /// 管理 shoes systemd 服务
    Service {
        #[arg(value_enum)]
        action: ServiceAction,
    },
    /// 查看安装、配置和服务信息
    Info,
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
        /// 安装指定版本，例如 v0.1.1；默认使用最新 Release
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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PortKind {
    Tcp,
    Udp,
    Both,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Menu) {
        Command::Menu => menu::run().await,
        Command::Install { method } => {
            let report = installer::install(method, false).await?;
            service::install_unit(false)?;
            println!("{} {}", "shoes 安装成功：".green(), report.version);
            println!("来源：{}", report.source);
            println!("路径：{}", report.destination.display());
            println!("systemd unit 已写入；生成配置后再启动服务。");
            Ok(())
        }
        Command::Generate {
            name,
            protocol,
            port,
            output,
            server_name,
            dest,
            cert,
            key,
        } => {
            let output = output.unwrap_or_else(|| PathBuf::from(crate::utils::CONFIG_FILE));
            let result = config::generate(GenerationRequest {
                name,
                protocol,
                port,
                output,
                server_name,
                reality_dest: dest,
                certificate: cert,
                certificate_key: key,
            })
            .await?;
            print_credentials(&result);
            if result.config_path == std::path::Path::new(crate::utils::CONFIG_FILE) {
                service::install_unit(true)?;
                println!("{}", "配置验证通过，shoes 已启用并启动。".green());
            }
            Ok(())
        }
        Command::Service { action } => service::execute(action),
        Command::Logs { lines } => service::logs(lines),
        Command::Info => show_info().await,
        Command::Delete { profile, yes } => {
            if !yes {
                anyhow::bail!("删除配置需要显式添加 --yes；也可使用交互菜单确认");
            }
            let unit_exists = std::path::Path::new(crate::utils::SERVICE_FILE).exists();
            let was_active = unit_exists && service::is_active()?;
            let deleted = config::delete_profile(profile).await?;
            let state = config::load_state()?;
            if was_active {
                if state.profiles.is_empty() {
                    service::execute(ServiceAction::Stop)?;
                } else {
                    service::execute(ServiceAction::Restart)?;
                }
            }
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
            let unit_exists = std::path::Path::new(crate::utils::SERVICE_FILE).exists();
            let was_active = unit_exists && service::is_active()?;
            let report = installer::install(method, true).await?;
            if was_active {
                service::execute(ServiceAction::Restart)?;
            }
            println!("{} {}", "shoes 更新完成：".green(), report.version);
            Ok(())
        }
        Command::SelfUpdate { version, force } => run_self_update(version.as_deref(), force).await,
        Command::Uninstall { purge } => {
            let unit_removed = service::uninstall_unit()?;
            let binary_removed = installer::uninstall_binary()?;
            if purge {
                let config_dir = std::path::Path::new(crate::utils::CONFIG_DIR);
                if config_dir.exists() {
                    std::fs::remove_dir_all(config_dir)?;
                }
            }
            println!(
                "卸载完成：二进制={}，systemd={}，配置清理={}",
                binary_removed, unit_removed, purge
            );
            Ok(())
        }
    }
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

pub async fn show_info() -> Result<()> {
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
            println!("配置数量：{}", state.profiles.len());
            for profile in state.profiles {
                println!(
                    "- {} | {} | 0.0.0.0:{} | {} | {}",
                    profile.id,
                    profile.name,
                    profile.port,
                    profile.protocol_name(),
                    profile.server_name()
                );
            }
        }
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
        } => {
            println!("协议：Hysteria2");
            println!("服务器名称：{server_name}");
            println!("密码：{password}");
            print_certificate_notice(result);
        }
        config::Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => {
            println!("协议：TUIC v5");
            println!("服务器名称：{server_name}");
            println!("UUID：{user_id}");
            println!("密码：{password}");
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
            Cli::try_parse_from(["ping-rust", "self-update", "--version", "v0.1.1", "--force"])
                .unwrap();
        match cli.command.unwrap() {
            Command::SelfUpdate { version, force } => {
                assert_eq!(version.as_deref(), Some("v0.1.1"));
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
}
