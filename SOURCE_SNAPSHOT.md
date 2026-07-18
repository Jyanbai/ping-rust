# ping-rust 完整源码快照

> 由真实仓库文件逐个合并并校验；实际构建仍使用原始文件。

## `Cargo.toml`

````toml
[package]
name = "ping-rust"
version = "0.1.1"
edition = "2021"
description = "Menu-driven installer and manager for the shoes proxy server"
license = "MIT"
readme = "README.md"
documentation = "https://docs.rs/ping-rust"
repository = "https://github.com/Jyanbai/ping-rust"
exclude = ["task_plan.md", "findings.md", "progress.md", "SOURCE_SNAPSHOT.md", "COMPLETION_AUDIT.md"]
keywords = ["proxy", "shoes", "reality", "vless", "cli"]
categories = ["command-line-utilities", "network-programming"]

[[bin]]
name = "ping-rust"
path = "src/main.rs"

[dependencies]
anyhow = "1.0"
base64 = "0.22"
clap = { version = "4.5", features = ["derive"] }
colored = "3.0"
dialoguer = "0.11"
flate2 = "1.1"
fs2 = "0.4"
futures-util = "0.3"
hex = "0.4"
indicatif = "0.18"
rand = "0.9"
rcgen = "0.13"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "stream"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
semver = "1.0"
sha2 = "0.10"
tar = "0.4"
tempfile = "3.20"
tokio = { version = "1.47", features = ["macros", "process", "rt-multi-thread"] }
uuid = { version = "1.17", features = ["serde", "v4"] }
url = "2.5"
x25519-dalek = { version = "2.0", features = ["getrandom", "static_secrets"] }

[profile.release]
lto = "thin"
codegen-units = 1
strip = true
````

## `src/main.rs`

````rust
mod cli;
mod client;
mod config;
mod installer;
mod menu;
mod operations;
mod self_update;
mod service;
mod utils;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    cli::run(cli::Cli::parse()).await
}
````

## `src/cli.rs`

````rust
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
````

## `src/menu.rs`

````rust
use anyhow::Result;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};

use crate::{
    cli,
    client::{self, ClientFormat},
    config::{self, GenerationRequest, Protocol},
    installer::{self, InstallMethod},
    operations,
    service::{self, ServiceAction},
};

const MENU_ITEMS: &[&str] = &[
    "安装 shoes",
    "添加代理配置",
    "查看配置信息",
    "删除配置",
    "服务管理",
    "更新 shoes",
    "运维工具",
    "卸载",
    "退出",
];

fn select_numbered<T: AsRef<str>>(prompt: &str, items: &[T]) -> Result<usize> {
    if items.is_empty() {
        anyhow::bail!("菜单没有可选项");
    }
    println!("{prompt}");
    for (index, item) in items.iter().enumerate() {
        println!("  {}. {}", index + 1, item.as_ref());
    }
    let count = items.len();
    let selected = Input::<usize>::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("请输入序号 [1-{count}]"))
        .default(1)
        .validate_with(move |value: &usize| {
            if (1..=count).contains(value) {
                Ok(())
            } else {
                Err(format!("请输入 1 到 {count} 之间的数字"))
            }
        })
        .interact_text()?;
    Ok(selected - 1)
}

pub async fn run() -> Result<()> {
    loop {
        println!();
        println!("{}", "ping-rust · shoes 管理工具".bright_cyan().bold());
        println!("{}", "────────────────────────────".bright_black());

        let selected = select_numbered("请选择操作", MENU_ITEMS)?;

        match selected {
            0 => install_menu().await?,
            1 => add_config_menu().await?,
            2 => cli::show_info().await?,
            3 => delete_config_menu().await?,
            4 => service_menu()?,
            5 => update_menu().await?,
            6 => operations_menu().await?,
            7 => uninstall_menu()?,
            8 => {
                println!("{}", "已退出。".green());
                return Ok(());
            }
            _ => anyhow::bail!("菜单返回了无效选项"),
        }
    }
}

async fn delete_config_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有可删除的配置。");
        return Ok(());
    }
    let labels = state
        .profiles
        .iter()
        .map(|profile| {
            format!(
                "{} · {} · :{} · {}",
                profile.name,
                profile.protocol_name(),
                profile.port,
                profile.id
            )
        })
        .collect::<Vec<_>>();
    let selected = select_numbered("选择要删除的配置", &labels)?;
    let profile = &state.profiles[selected];
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("确认删除 {}？", profile.name))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    let unit_exists = std::path::Path::new(crate::utils::SERVICE_FILE).exists();
    let was_active = unit_exists && service::is_active()?;
    let deleted = config::delete_profile(profile.id).await?;
    let remaining = config::load_state()?;
    if was_active {
        if remaining.profiles.is_empty() {
            service::execute(ServiceAction::Stop)?;
        } else {
            service::execute(ServiceAction::Restart)?;
        }
    }
    println!("{} {}", "已删除：".green(), deleted.name);
    Ok(())
}

async fn operations_menu() -> Result<()> {
    let choices = [
        "查看日志",
        "端口检查",
        "开启 BBR",
        "备份配置",
        "恢复配置",
        "导出客户端配置",
        "更新 ping-rust",
        "返回",
    ];
    let selected = select_numbered("运维工具", &choices)?;
    match selected {
        0 => service::logs(100),
        1 => {
            let port = Input::<u16>::with_theme(&ColorfulTheme::default())
                .with_prompt("检查端口")
                .default(443)
                .interact_text()?;
            cli::print_port_status(port, operations::check_port(port, true, true));
            Ok(())
        }
        2 => {
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("写入 sysctl 配置并启用 BBR？")
                .default(true)
                .interact()?
            {
                operations::enable_bbr()?;
                println!("{}", "BBR 已启用。".green());
            }
            Ok(())
        }
        3 => {
            let path = operations::backup(None)?;
            println!("备份已创建：{}", path.display());
            println!("备份含私钥和密码，请安全保管。");
            Ok(())
        }
        4 => {
            let archive = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("备份文件路径")
                .interact_text()?;
            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("恢复会替换当前配置，继续？")
                .default(false)
                .interact()?
            {
                let rollback = operations::restore(std::path::Path::new(&archive)).await?;
                println!("{}", "恢复成功。".green());
                if let Some(path) = rollback {
                    println!("原配置保留于：{}", path.display());
                }
            }
            Ok(())
        }
        5 => export_menu(),
        6 => cli::run_self_update(None, false).await,
        _ => Ok(()),
    }
}

fn export_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有可导出的配置。");
        return Ok(());
    }
    let labels = state
        .profiles
        .iter()
        .map(|profile| format!("{} · {}", profile.name, profile.protocol_name()))
        .collect::<Vec<_>>();
    let selected = select_numbered("选择配置", &labels)?;
    let formats = ["Clash Meta", "sing-box", "Nekobox 分享链接"];
    let format = match select_numbered("客户端格式", &formats)? {
        0 => ClientFormat::ClashMeta,
        1 => ClientFormat::SingBox,
        _ => ClientFormat::Nekobox,
    };
    let server = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("VPS 公网域名或 IP")
        .interact_text()?;
    let content = client::render(&state.profiles[selected], format, &server)?;
    println!("\n{content}\n");
    if state.profiles[selected].self_signed_certificate {
        println!(
            "{}",
            "注意：导出内容为自签名证书启用了 insecure；生产环境建议换用受信任证书。".yellow()
        );
    }
    Ok(())
}

async fn add_config_menu() -> Result<()> {
    let choices = [
        "VLESS-Reality-Vision（推荐）",
        "Hysteria2",
        "TUIC v5",
        "返回",
    ];
    let selected = select_numbered("选择协议", &choices)?;
    let protocol = match selected {
        0 => Protocol::Reality,
        1 => Protocol::Hysteria2,
        2 => Protocol::Tuic,
        _ => return Ok(()),
    };
    let name = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("配置名称")
        .default(match protocol {
            Protocol::Reality => "reality".to_owned(),
            Protocol::Hysteria2 => "hysteria2".to_owned(),
            Protocol::Tuic => "tuic".to_owned(),
        })
        .interact_text()?;
    let port = Input::<u16>::with_theme(&ColorfulTheme::default())
        .with_prompt("监听端口")
        .default(443)
        .validate_with(|value: &u16| {
            if *value > 0 {
                Ok(())
            } else {
                Err("端口必须大于 0")
            }
        })
        .interact_text()?;
    let server_name = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(if matches!(protocol, Protocol::Reality) {
            "Reality SNI"
        } else {
            "证书域名/服务器名称"
        })
        .default(config::DEFAULT_SNI.to_owned())
        .interact_text()?;
    let reality_dest = if matches!(protocol, Protocol::Reality) {
        Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Reality fallback")
                .default(format!("{server_name}:443"))
                .interact_text()?,
        )
    } else {
        None
    };

    let result = config::generate(GenerationRequest {
        name: Some(name),
        protocol,
        port,
        output: crate::utils::CONFIG_FILE.into(),
        server_name,
        reality_dest,
        certificate: None,
        certificate_key: None,
    })
    .await?;
    cli::print_credentials(&result);
    service::install_unit(true)?;
    println!("{}", "配置验证通过，服务已启动。".green());
    Ok(())
}

async fn install_menu() -> Result<()> {
    let choices = ["GitHub Release（推荐）", "cargo install shoes", "返回"];
    let selected = select_numbered("选择安装方式", &choices)?;
    let method = match selected {
        0 => InstallMethod::Release,
        1 => InstallMethod::Cargo,
        _ => return Ok(()),
    };
    let report = installer::install(method, false).await?;
    service::install_unit(false)?;
    println!("{} {}", "安装成功：".green(), report.version);
    println!("下一步请选择“添加代理配置”。");
    Ok(())
}

async fn update_menu() -> Result<()> {
    let choices = ["GitHub Release（推荐）", "cargo install shoes", "返回"];
    let selected = select_numbered("选择更新方式", &choices)?;
    let method = match selected {
        0 => InstallMethod::Release,
        1 => InstallMethod::Cargo,
        _ => return Ok(()),
    };
    let unit_exists = std::path::Path::new(crate::utils::SERVICE_FILE).exists();
    let was_active = unit_exists && service::is_active()?;
    let report = installer::install(method, true).await?;
    if was_active {
        service::execute(ServiceAction::Restart)?;
    }
    println!("{} {}", "更新成功：".green(), report.version);
    Ok(())
}

fn service_menu() -> Result<()> {
    let choices = ["启动", "停止", "重启", "状态", "启用并启动", "禁用", "返回"];
    let selected = select_numbered("服务管理", &choices)?;
    let action = match selected {
        0 => ServiceAction::Start,
        1 => ServiceAction::Stop,
        2 => ServiceAction::Restart,
        3 => ServiceAction::Status,
        4 => ServiceAction::Enable,
        5 => ServiceAction::Disable,
        _ => return Ok(()),
    };
    service::execute(action)
}

fn uninstall_menu() -> Result<()> {
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("确认卸载 shoes？默认保留 /etc/shoes 配置")
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    let purge = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("同时永久删除 /etc/shoes 配置与凭据？")
        .default(false)
        .interact()?;
    let unit_removed = service::uninstall_unit()?;
    let binary_removed = installer::uninstall_binary()?;
    if purge && std::path::Path::new(crate::utils::CONFIG_DIR).exists() {
        std::fs::remove_dir_all(crate::utils::CONFIG_DIR)?;
    }
    println!(
        "卸载完成：二进制={}，systemd={}，配置清理={}",
        binary_removed, unit_removed, purge
    );
    Ok(())
}
````

## `src/installer.rs`

````rust
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::process::Command;

use crate::utils;

const LATEST_RELEASE_API: &str = "https://api.github.com/repos/cfal/shoes/releases/latest";
const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;
const LOW_MEMORY_THRESHOLD_KIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InstallMethod {
    /// 下载 GitHub Release 预编译文件
    Release,
    /// 执行 cargo install shoes
    Cargo,
}

#[derive(Debug)]
pub struct InstallReport {
    pub version: String,
    pub source: String,
    pub destination: PathBuf,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

pub async fn install(method: InstallMethod, force: bool) -> Result<InstallReport> {
    utils::require_linux_root()?;
    match method {
        InstallMethod::Release => install_release(Path::new(utils::SHOES_BIN)).await,
        InstallMethod::Cargo => install_cargo(force).await,
    }
}

async fn install_release(destination: &Path) -> Result<InstallReport> {
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("创建 HTTP 客户端失败")?;

    let release = client
        .get(LATEST_RELEASE_API)
        .send()
        .await
        .context("请求 shoes 最新 Release 失败")?
        .error_for_status()
        .context("GitHub Release API 返回错误")?
        .json::<GithubRelease>()
        .await
        .context("解析 GitHub Release 信息失败")?;

    let mut failures = Vec::new();
    for target in release_targets()? {
        let expected_name = format!("shoes-{target}.tar.gz");
        let Some(asset) = release
            .assets
            .iter()
            .find(|asset| asset.name == expected_name)
        else {
            failures.push(format!("{target}: Release 中缺少 {expected_name}"));
            continue;
        };
        match install_release_asset(&client, asset, destination).await {
            Ok(()) => {
                return Ok(InstallReport {
                    version: release.tag_name,
                    source: format!("GitHub Release ({})", asset.name),
                    destination: destination.to_path_buf(),
                });
            }
            Err(error) => failures.push(format!("{target}: {error:#}")),
        }
    }

    bail!(
        "Release {} 的候选资产均无法安全安装：\n- {}",
        release.tag_name,
        failures.join("\n- ")
    )
}

async fn install_release_asset(
    client: &Client,
    asset: &ReleaseAsset,
    destination: &Path,
) -> Result<()> {
    let expected_digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .context("Release 资产未提供 SHA-256 digest，已拒绝未经校验的安装")?;
    let work = tempfile::tempdir().context("创建临时目录失败")?;
    let archive_path = work.path().join(&asset.name);
    let actual_digest = download(client, asset, &archive_path).await?;
    if !actual_digest.eq_ignore_ascii_case(expected_digest) {
        bail!("SHA-256 校验失败：期望 {expected_digest}，实际 {actual_digest}；文件未安装");
    }
    let extracted = extract_shoes(&archive_path, work.path())?;
    set_executable(&extracted)?;
    binary_health(&extracted).await?;
    utils::atomic_copy(&extracted, destination, 0o755)
}

async fn install_cargo(force: bool) -> Result<InstallReport> {
    let cargo = utils::command_path("cargo").context(
        "无法找到 cargo；请安装 Rust toolchain，或确认 cargo 与 ping-rust 位于同一目录/已加入 PATH",
    )?;
    let mut command = Command::new(cargo);
    command.args(["install", "shoes", "--locked", "--root", "/usr/local"]);
    if is_low_memory_linux() {
        eprintln!("检测到系统内存低于 1 GiB：cargo 源码安装将使用单任务并关闭 LTO，避免严重换页。");
        command
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_PROFILE_RELEASE_LTO", "false");
    }
    if force || Path::new(utils::SHOES_BIN).exists() {
        command.arg("--force");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = command
        .status()
        .await
        .context("无法执行 cargo；请检查 Rust toolchain 安装")?;
    if !status.success() {
        bail!("cargo install shoes 执行失败（退出码：{status}）");
    }

    let version = installed_version()
        .await
        .unwrap_or_else(|_| "unknown".to_owned());
    Ok(InstallReport {
        version,
        source: "crates.io (cargo install)".to_owned(),
        destination: PathBuf::from(utils::SHOES_BIN),
    })
}

fn is_low_memory_linux() -> bool {
    cfg!(target_os = "linux")
        && fs::read_to_string("/proc/meminfo")
            .ok()
            .is_some_and(|meminfo| mem_total_below_threshold(&meminfo))
}

fn mem_total_below_threshold(meminfo: &str) -> bool {
    meminfo
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemTotal:")?;
            value.split_whitespace().next()?.parse::<u64>().ok()
        })
        .is_some_and(|kib| kib < LOW_MEMORY_THRESHOLD_KIB)
}

async fn download(client: &Client, asset: &ReleaseAsset, destination: &Path) -> Result<String> {
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("下载 {} 失败", asset.name))?
        .error_for_status()
        .with_context(|| format!("下载 {} 时服务器返回错误", asset.name))?;

    let total = response.content_length().unwrap_or(asset.size);
    let progress = ProgressBar::new(total);
    progress.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:36.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )?
        .progress_chars("=>-"),
    );
    progress.set_message(format!("下载 {}", asset.name));

    let mut output = File::create(destination)
        .with_context(|| format!("无法创建临时文件 {}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("下载流中断")?;
        output.write_all(&chunk).context("写入下载文件失败")?;
        hasher.update(&chunk);
        progress.inc(chunk.len() as u64);
    }
    output.sync_all().context("同步下载文件失败")?;
    progress.finish_with_message("下载完成并已校验");

    Ok(hex::encode(hasher.finalize()))
}

fn extract_shoes(archive_path: &Path, work_dir: &Path) -> Result<PathBuf> {
    let archive_file = File::open(archive_path).context("打开下载归档失败")?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = Archive::new(decoder);
    let output = work_dir.join("shoes.extracted");

    for entry in archive.entries().context("读取 tar.gz 归档失败")? {
        let mut entry = entry.context("读取归档条目失败")?;
        let path = entry.path().context("归档包含无效路径")?;
        if path.file_name() == Some(OsStr::new("shoes")) && entry.header().entry_type().is_file() {
            if entry.size() > MAX_BINARY_SIZE {
                bail!("Release 中的 shoes 文件异常大（{} bytes）", entry.size());
            }
            let mut file = File::create(&output).context("创建解压文件失败")?;
            std::io::copy(&mut entry, &mut file).context("解压 shoes 失败")?;
            file.sync_all().context("同步解压文件失败")?;
            return Ok(output);
        }
    }

    bail!("Release 归档中未找到 shoes 二进制文件")
}

fn release_targets() -> Result<Vec<&'static str>> {
    release_targets_for(std::env::consts::OS, std::env::consts::ARCH, is_musl())
}

fn release_targets_for(os: &str, arch: &str, musl: bool) -> Result<Vec<&'static str>> {
    if os != "linux" {
        bail!("预编译安装仅支持 Linux；当前系统为 {}", os);
    }

    match (arch, musl) {
        ("x86_64", true) => Ok(vec!["x86_64-unknown-linux-musl"]),
        ("x86_64", false) => Ok(vec![
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
        ]),
        ("aarch64", true) => Ok(vec!["aarch64-unknown-linux-musl"]),
        ("aarch64", false) => Ok(vec![
            "aarch64-unknown-linux-gnu",
            "aarch64-unknown-linux-musl",
        ]),
        (arch, _) => bail!("暂不支持架构 {arch}；可尝试 --method cargo"),
    }
}

fn is_musl() -> bool {
    if Path::new("/etc/alpine-release").exists() {
        return true;
    }
    std::process::Command::new("ldd")
        .arg("--version")
        .output()
        .map(|output| {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.to_ascii_lowercase().contains("musl")
        })
        .unwrap_or(false)
}

pub async fn installed_version() -> Result<String> {
    binary_health(Path::new(utils::SHOES_BIN)).await?;
    Ok("shoes（CLI 未提供版本参数）".to_owned())
}

async fn binary_health(binary: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg("generate-reality-keypair")
        .output()
        .await
        .with_context(|| format!("无法执行 {} 健康检查", binary.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "{} 健康检查失败（{}）：{}{}",
            binary.display(),
            output.status,
            stderr.trim(),
            stdout.trim()
        );
    }
    if output.stdout.is_empty() {
        bail!("{} 健康检查未返回 Reality 密钥", binary.display());
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("设置 {} 可执行权限失败", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn uninstall_binary() -> Result<bool> {
    utils::require_linux_root()?;
    let path = Path::new(utils::SHOES_BIN);
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).context("删除 shoes 二进制失败")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn extracts_binary_from_nested_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("test.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut tar = tar::Builder::new(encoder);
            let bytes = b"shoes-binary";
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, "release/shoes", &bytes[..])
                .unwrap();
            tar.finish().unwrap();
        }
        let extracted = extract_shoes(&archive_path, dir.path()).unwrap();
        let mut bytes = Vec::new();
        File::open(extracted)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"shoes-binary");
    }

    #[test]
    fn glibc_targets_fall_back_to_musl() {
        assert_eq!(
            release_targets_for("linux", "x86_64", false).unwrap(),
            vec!["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]
        );
        assert_eq!(
            release_targets_for("linux", "aarch64", false).unwrap(),
            vec!["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"]
        );
    }

    #[test]
    fn musl_hosts_only_try_musl_asset() {
        assert_eq!(
            release_targets_for("linux", "x86_64", true).unwrap(),
            vec!["x86_64-unknown-linux-musl"]
        );
    }

    #[test]
    fn detects_low_memory_from_linux_meminfo() {
        assert!(mem_total_below_threshold("MemTotal:         413696 kB\n"));
        assert!(!mem_total_below_threshold("MemTotal:        2097152 kB\n"));
        assert!(!mem_total_below_threshold("SwapTotal:       2097152 kB\n"));
    }
}
````

## `src/config.rs`

````rust
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::ValueEnum;
use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils;

pub const DEFAULT_SNI: &str = "www.cloudflare.com";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Protocol {
    Reality,
    Hysteria2,
    Tuic,
}

pub struct GenerationRequest {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub output: PathBuf,
    pub server_name: String,
    pub reality_dest: Option<String>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
}

pub struct GenerationResult {
    pub profile_id: Uuid,
    pub config_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub credentials: Credentials,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Credentials {
    Reality {
        user_id: Uuid,
        private_key: String,
        public_key: String,
        short_id: String,
        server_name: String,
    },
    Hysteria2 {
        password: String,
        server_name: String,
    },
    Tuic {
        user_id: Uuid,
        password: String,
        server_name: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedState {
    pub schema_version: u8,
    pub profiles: Vec<ManagedProfile>,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profiles: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ManagedProfile {
    pub id: Uuid,
    pub name: String,
    pub port: u16,
    pub credentials: Credentials,
    pub certificate_path: Option<PathBuf>,
    pub certificate_key_path: Option<PathBuf>,
    pub self_signed_certificate: bool,
}

impl ManagedProfile {
    pub fn protocol_name(&self) -> &'static str {
        match &self.credentials {
            Credentials::Reality { .. } => "VLESS-Reality-Vision",
            Credentials::Hysteria2 { .. } => "Hysteria2",
            Credentials::Tuic { .. } => "TUIC v5",
        }
    }

    pub fn server_name(&self) -> &str {
        match &self.credentials {
            Credentials::Reality { server_name, .. }
            | Credentials::Hysteria2 { server_name, .. }
            | Credentials::Tuic { server_name, .. } => server_name,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerConfig {
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quic_settings: Option<QuicSettings>,
    protocol: ServerProtocol,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct QuicSettings {
    cert: String,
    key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    alpn_protocols: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ServerProtocol {
    Tls {
        reality_targets: BTreeMap<String, RealityTarget>,
    },
    Hysteria2 {
        password: String,
        udp_enabled: bool,
    },
    Tuic {
        uuid: Uuid,
        password: String,
        zero_rtt_handshake: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct RealityTarget {
    private_key: String,
    short_ids: Vec<String>,
    dest: String,
    max_time_diff: u64,
    vision: bool,
    protocol: InnerProtocol,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum InnerProtocol {
    Vless { user_id: Uuid, udp_enabled: bool },
}

pub async fn generate(request: GenerationRequest) -> Result<GenerationResult> {
    validate_request(&request)?;
    let parent = request.output.parent().context("配置输出路径没有父目录")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let managed = request.output == Path::new(utils::CONFIG_FILE);
    if managed {
        utils::require_linux_root()?;
    }
    let _lock = managed
        .then(|| utils::exclusive_lock(Path::new(utils::LOCK_FILE)))
        .transpose()?;
    let mut state = if managed {
        load_state_for_update()?
    } else {
        ManagedState::default()
    };
    if state
        .profiles
        .iter()
        .any(|profile| profile.port == request.port)
    {
        bail!("端口 {} 已由现有配置使用", request.port);
    }
    let profile_id = Uuid::new_v4();
    let self_signed = request.certificate.is_none()
        && matches!(request.protocol, Protocol::Hysteria2 | Protocol::Tuic);

    let (server, credentials, certificate_path, certificate_key_path) = match request.protocol {
        Protocol::Reality => generate_reality(&request),
        Protocol::Hysteria2 | Protocol::Tuic => {
            let (cert, key) = resolve_certificate(&request, parent, profile_id)?;
            let cert_string = cert.to_string_lossy().into_owned();
            let key_string = key.to_string_lossy().into_owned();
            let password = random_secret(24);
            if matches!(request.protocol, Protocol::Hysteria2) {
                (
                    quic_server(
                        request.port,
                        &cert_string,
                        &key_string,
                        ServerProtocol::Hysteria2 {
                            password: password.clone(),
                            udp_enabled: true,
                        },
                    ),
                    Credentials::Hysteria2 {
                        password,
                        server_name: request.server_name.clone(),
                    },
                    Some(cert),
                    Some(key),
                )
            } else {
                let user_id = Uuid::new_v4();
                (
                    quic_server(
                        request.port,
                        &cert_string,
                        &key_string,
                        ServerProtocol::Tuic {
                            uuid: user_id,
                            password: password.clone(),
                            zero_rtt_handshake: false,
                        },
                    ),
                    Credentials::Tuic {
                        user_id,
                        password,
                        server_name: request.server_name.clone(),
                    },
                    Some(cert),
                    Some(key),
                )
            }
        }
    };

    let profile = ManagedProfile {
        id: profile_id,
        name: request
            .name
            .clone()
            .unwrap_or_else(|| default_profile_name(request.protocol, profile_id)),
        port: request.port,
        credentials: credentials.clone(),
        certificate_path: certificate_path.clone(),
        certificate_key_path: certificate_key_path.clone(),
        self_signed_certificate: self_signed,
    };
    let mut credential_cleanup = CredentialCleanup::new(
        self_signed,
        certificate_path.as_deref(),
        certificate_key_path.as_deref(),
    );

    let mut servers = if managed && !state.profiles.is_empty() {
        load_servers(Path::new(utils::CONFIG_FILE))?
    } else {
        Vec::new()
    };
    if servers.len() != state.profiles.len() {
        bail!("配置文件与管理状态不一致；请先备份并修复，ping-rust 不会覆盖现有配置");
    }
    servers.push(server);
    state.profiles.push(profile);

    let yaml = serde_yaml::to_string(&servers).context("序列化 shoes YAML 失败")?;
    validate_yaml(&yaml)?;
    if managed {
        validate_candidate_with_shoes(&yaml, parent).await?;
        commit_managed(&request.output, Path::new(utils::STATE_FILE), &yaml, &state)?;
    } else {
        utils::atomic_write(&request.output, yaml.as_bytes(), 0o600)?;
    }
    credential_cleanup.disarm();

    Ok(GenerationResult {
        profile_id,
        config_path: request.output,
        certificate_path,
        certificate_key_path,
        credentials,
    })
}

fn default_profile_name(protocol: Protocol, id: Uuid) -> String {
    let protocol = match protocol {
        Protocol::Reality => "reality",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
    };
    format!("{protocol}-{}", &id.simple().to_string()[..8])
}

fn load_servers(path: &Path) -> Result<Vec<ServerConfig>> {
    let yaml =
        fs::read_to_string(path).with_context(|| format!("读取配置 {} 失败", path.display()))?;
    serde_yaml::from_str(&yaml).context("现有 shoes 配置不是 ping-rust 可管理的格式")
}

fn load_state_for_update() -> Result<ManagedState> {
    let config_exists = Path::new(utils::CONFIG_FILE).exists();
    let state_exists = Path::new(utils::STATE_FILE).exists();
    if config_exists && !state_exists {
        bail!(
            "检测到非 ping-rust 管理的 {}；为避免覆盖，请先备份或改用 --output",
            utils::CONFIG_FILE
        );
    }
    if state_exists {
        load_state()
    } else {
        Ok(ManagedState::default())
    }
}

pub fn load_state() -> Result<ManagedState> {
    load_state_from(Path::new(utils::STATE_FILE))
}

fn load_state_from(path: &Path) -> Result<ManagedState> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("读取管理状态 {} 失败", path.display()))?;
    let state: ManagedState = serde_json::from_str(&json).context("管理状态 JSON 已损坏")?;
    if state.schema_version != 1 {
        bail!("不支持的管理状态版本 {}", state.schema_version);
    }
    Ok(state)
}

fn save_state_to(path: &Path, state: &ManagedState) -> Result<()> {
    let json = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
    utils::atomic_write(path, &json, 0o600)
}

pub async fn delete_profile(id: Uuid) -> Result<ManagedProfile> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let mut state = load_state()?;
    let index = state
        .profiles
        .iter()
        .position(|profile| profile.id == id)
        .with_context(|| format!("未找到配置 {id}"))?;
    let config_path = Path::new(utils::CONFIG_FILE);
    let mut servers = load_servers(config_path)?;
    if servers.len() != state.profiles.len() {
        bail!("配置文件与管理状态不一致，已拒绝删除");
    }
    servers.remove(index);
    let profile = state.profiles.remove(index);
    let yaml = serde_yaml::to_string(&servers).context("序列化更新后配置失败")?;
    if !servers.is_empty() {
        validate_yaml(&yaml)?;
        validate_candidate_with_shoes(&yaml, Path::new(utils::CONFIG_DIR)).await?;
    }
    commit_managed(config_path, Path::new(utils::STATE_FILE), &yaml, &state)?;

    if profile.self_signed_certificate {
        for path in [
            profile.certificate_path.as_deref(),
            profile.certificate_key_path.as_deref(),
        ] {
            if let Err(error) = remove_managed_credential(path) {
                eprintln!("警告：配置已删除，但清理凭据失败：{error:#}");
            }
        }
    }
    Ok(profile)
}

fn commit_managed(
    config_path: &Path,
    state_path: &Path,
    yaml: &str,
    state: &ManagedState,
) -> Result<()> {
    commit_managed_with_state_writer(config_path, state_path, yaml, state, save_state_to)
}

fn commit_managed_with_state_writer<F>(
    config_path: &Path,
    state_path: &Path,
    yaml: &str,
    state: &ManagedState,
    write_state: F,
) -> Result<()>
where
    F: FnOnce(&Path, &ManagedState) -> Result<()>,
{
    let old_config = read_optional(config_path)?;
    let old_state = read_optional(state_path)?;
    utils::atomic_write(config_path, yaml.as_bytes(), 0o600)?;
    if let Err(error) = write_state(state_path, state) {
        let state_rollback = restore_snapshot(state_path, old_state.as_deref(), 0o600);
        let config_rollback = restore_snapshot(config_path, old_config.as_deref(), 0o600);
        if let Err(rollback_error) = state_rollback.and(config_rollback) {
            return Err(error.context(format!(
                "写入管理状态失败，且回滚也失败：{rollback_error:#}"
            )));
        }
        return Err(error.context("写入管理状态失败，配置和状态已回滚"));
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn restore_snapshot(path: &Path, contents: Option<&[u8]>, mode: u32) -> Result<()> {
    if let Some(contents) = contents {
        utils::atomic_write(path, contents, mode)
    } else if path.exists() {
        fs::remove_file(path).with_context(|| format!("删除回滚目标 {} 失败", path.display()))
    } else {
        Ok(())
    }
}

struct CredentialCleanup {
    paths: Vec<PathBuf>,
    armed: bool,
}

impl CredentialCleanup {
    fn new(self_signed: bool, cert: Option<&Path>, key: Option<&Path>) -> Self {
        let paths = if self_signed {
            [cert, key]
                .into_iter()
                .flatten()
                .map(Path::to_path_buf)
                .collect()
        } else {
            Vec::new()
        };
        Self { paths, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        if self.armed {
            for path in &self.paths {
                let _ = fs::remove_file(path);
            }
        }
    }
}

fn remove_managed_credential(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else { return Ok(()) };
    if !path.starts_with(Path::new(utils::CONFIG_DIR)) {
        bail!("拒绝删除配置目录之外的凭据文件 {}", path.display());
    }
    if path.is_file() {
        std::fs::remove_file(path)
            .with_context(|| format!("删除凭据文件 {} 失败", path.display()))?;
    }
    Ok(())
}

fn generate_reality(
    request: &GenerationRequest,
) -> (ServerConfig, Credentials, Option<PathBuf>, Option<PathBuf>) {
    let keypair = generate_reality_keypair();
    let short_id = random_hex(8);
    let user_id = Uuid::new_v4();
    let destination = request
        .reality_dest
        .clone()
        .unwrap_or_else(|| format!("{}:443", request.server_name));
    let target = RealityTarget {
        private_key: keypair.private_key.clone(),
        short_ids: vec![short_id.clone()],
        dest: destination,
        max_time_diff: 60_000,
        vision: true,
        protocol: InnerProtocol::Vless {
            user_id,
            udp_enabled: true,
        },
    };
    let mut targets = BTreeMap::new();
    targets.insert(request.server_name.clone(), target);

    (
        ServerConfig {
            address: format!("0.0.0.0:{}", request.port),
            transport: None,
            quic_settings: None,
            protocol: ServerProtocol::Tls {
                reality_targets: targets,
            },
            rules: Vec::new(),
        },
        Credentials::Reality {
            user_id,
            private_key: keypair.private_key,
            public_key: keypair.public_key,
            short_id,
            server_name: request.server_name.clone(),
        },
        None,
        None,
    )
}

fn quic_server(port: u16, cert: &str, key: &str, protocol: ServerProtocol) -> ServerConfig {
    ServerConfig {
        address: format!("0.0.0.0:{port}"),
        transport: Some("quic".to_owned()),
        quic_settings: Some(QuicSettings {
            cert: cert.to_owned(),
            key: key.to_owned(),
            alpn_protocols: vec!["h3".to_owned()],
        }),
        protocol,
        rules: vec!["allow-all-direct".to_owned()],
    }
}

fn resolve_certificate(
    request: &GenerationRequest,
    parent: &Path,
    profile_id: Uuid,
) -> Result<(PathBuf, PathBuf)> {
    match (&request.certificate, &request.certificate_key) {
        (Some(cert), Some(key)) => {
            if !cert.is_file() || !key.is_file() {
                bail!("指定的证书或私钥文件不存在");
            }
            Ok((cert.clone(), key.clone()))
        }
        (None, None) => {
            let suffix = &profile_id.simple().to_string()[..8];
            let cert = parent.join(format!("cert-{suffix}.pem"));
            let key = parent.join(format!("key-{suffix}.pem"));
            write_self_signed_certificate(&request.server_name, &cert, &key)?;
            Ok((cert, key))
        }
        _ => bail!("--cert 和 --key 必须同时提供"),
    }
}

fn write_self_signed_certificate(server_name: &str, cert: &Path, key: &Path) -> Result<()> {
    let CertifiedKey {
        cert: generated,
        key_pair,
    } = generate_simple_self_signed(vec![server_name.to_owned()]).context("生成自签名证书失败")?;
    utils::atomic_write(cert, generated.pem().as_bytes(), 0o644)?;
    if let Err(error) = utils::atomic_write(key, key_pair.serialize_pem().as_bytes(), 0o600) {
        let _ = fs::remove_file(cert);
        return Err(error.context("写入证书私钥失败，已清理证书"));
    }
    Ok(())
}

pub struct RealityKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_reality_keypair() -> RealityKeyPair {
    let private = StaticSecret::random();
    let public = PublicKey::from(&private);
    RealityKeyPair {
        private_key: URL_SAFE_NO_PAD.encode(private.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    hex::encode(value)
}

fn random_secret(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn validate_request(request: &GenerationRequest) -> Result<()> {
    if request.port == 0 {
        bail!("端口必须在 1..=65535 范围内");
    }
    if let Some(name) = &request.name {
        if name.trim().is_empty() || name.chars().any(char::is_control) || name.len() > 64 {
            bail!("配置名称必须为 1..=64 个非控制字符");
        }
    }
    if request.server_name.trim().is_empty()
        || request.server_name.len() > 253
        || request.server_name.contains(char::is_whitespace)
        || request.server_name.contains('/')
        || request.server_name.contains([':', '\\'])
    {
        bail!("SNI/服务器名称无效");
    }
    if let Some(destination) = &request.reality_dest {
        validate_host_port(destination)?;
    }
    if matches!(request.protocol, Protocol::Reality)
        && (request.certificate.is_some() || request.certificate_key.is_some())
    {
        bail!("Reality 不使用 --cert/--key；请改用 --server-name 和 --dest");
    }
    if !matches!(request.protocol, Protocol::Reality) && request.reality_dest.is_some() {
        bail!("--dest 仅适用于 Reality");
    }
    Ok(())
}

fn validate_host_port(value: &str) -> Result<()> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .context("IPv6 Reality fallback 必须采用 [address]:port 格式")?;
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .context("Reality fallback 必须采用 host:port 格式")?;
        if host.contains(':') {
            bail!("IPv6 Reality fallback 必须使用方括号，例如 [2001:db8::1]:443");
        }
        (host, port)
    };
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains(['/', '\\', '[', ']'])
    {
        bail!("Reality fallback 主机名或地址无效");
    }
    let port = port
        .parse::<u16>()
        .context("Reality fallback 端口必须是 1..=65535 的整数")?;
    if port == 0 {
        bail!("Reality fallback 端口必须在 1..=65535 范围内");
    }
    Ok(())
}

fn validate_yaml(yaml: &str) -> Result<()> {
    let configs =
        serde_yaml::from_str::<Vec<ServerConfig>>(yaml).context("生成的 YAML 无法反序列化")?;
    if configs.is_empty() {
        bail!("生成的配置至少应包含一个服务器");
    }
    Ok(())
}

async fn validate_candidate_with_shoes(yaml: &str, directory: &Path) -> Result<()> {
    validate_candidate_with_binary(yaml, directory, Path::new(utils::SHOES_BIN)).await
}

async fn validate_candidate_with_binary(yaml: &str, directory: &Path, binary: &Path) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("创建候选配置目录 {} 失败", directory.display()))?;
    let mut candidate = tempfile::Builder::new()
        .prefix(".ping-rust-candidate-")
        .suffix(".yaml")
        .tempfile_in(directory)
        .context("创建候选配置失败")?;
    candidate
        .write_all(yaml.as_bytes())
        .context("写入候选配置失败")?;
    candidate.as_file().sync_all().context("同步候选配置失败")?;
    validate_with_binary(binary, candidate.path()).await
}

pub(crate) fn validate_managed_snapshot(config_path: &Path, state_path: &Path) -> Result<()> {
    let servers = load_servers(config_path)?;
    let state = load_state_from(state_path)?;
    if servers.len() != state.profiles.len() {
        bail!(
            "备份中的配置条目数 {} 与管理状态条目数 {} 不一致",
            servers.len(),
            state.profiles.len()
        );
    }
    for (server, profile) in servers.iter().zip(&state.profiles) {
        let expected = format!("0.0.0.0:{}", profile.port);
        if server.address != expected {
            bail!(
                "备份配置 {} 的监听地址 {} 与管理状态端口不一致",
                profile.id,
                server.address
            );
        }
    }
    Ok(())
}

pub async fn validate_with_shoes(config_path: &Path) -> Result<()> {
    validate_with_binary(Path::new(utils::SHOES_BIN), config_path).await
}

async fn validate_with_binary(binary: &Path, config_path: &Path) -> Result<()> {
    if !binary.is_file() {
        bail!("shoes 尚未安装，无法执行 --dry-run 验证");
    }
    let output = Command::new(binary)
        .arg("--dry-run")
        .arg(config_path)
        .output()
        .await
        .context("无法启动 shoes 配置校验")?;
    if !output.status.success() {
        bail!(
            "shoes 拒绝生成的配置：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(protocol: Protocol, output: PathBuf) -> GenerationRequest {
        GenerationRequest {
            name: None,
            protocol,
            port: 443,
            output,
            server_name: "www.cloudflare.com".to_owned(),
            reality_dest: None,
            certificate: None,
            certificate_key: None,
        }
    }

    #[test]
    fn reality_keys_are_x25519_base64url() {
        let pair = generate_reality_keypair();
        let private = URL_SAFE_NO_PAD.decode(&pair.private_key).unwrap();
        let public = URL_SAFE_NO_PAD.decode(&pair.public_key).unwrap();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        let private: [u8; 32] = private.try_into().unwrap();
        let derived = PublicKey::from(&StaticSecret::from(private));
        assert_eq!(derived.as_bytes(), public.as_slice());
    }

    #[tokio::test]
    async fn reality_yaml_matches_shoes_shape() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate(request(Protocol::Reality, dir.path().join("reality.yaml")))
            .await
            .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: tls"));
        assert!(yaml.contains("reality_targets:"));
        assert!(yaml.contains("type: vless"));
        assert!(yaml.contains("vision: true"));
    }

    #[tokio::test]
    async fn hysteria2_generates_certificate_and_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate(request(Protocol::Hysteria2, dir.path().join("hy2.yaml")))
            .await
            .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: hysteria2"));
        assert!(yaml.contains("transport: quic"));
        assert!(result.certificate_path.unwrap().is_file());
        assert!(result.certificate_key_path.unwrap().is_file());
    }

    #[tokio::test]
    async fn tuic_yaml_has_required_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate(request(Protocol::Tuic, dir.path().join("tuic.yaml")))
            .await
            .unwrap();
        let yaml = std::fs::read_to_string(result.config_path).unwrap();
        assert!(yaml.contains("type: tuic"));
        assert!(yaml.contains("uuid:"));
        assert!(yaml.contains("zero_rtt_handshake: false"));
    }

    #[test]
    fn validates_multiple_server_entries() {
        let request = request(Protocol::Reality, PathBuf::from("unused.yaml"));
        let (first, _, _, _) = generate_reality(&request);
        let mut second_request = request;
        second_request.port = 8443;
        let (second, _, _, _) = generate_reality(&second_request);
        let yaml = serde_yaml::to_string(&vec![first, second]).unwrap();
        validate_yaml(&yaml).unwrap();
    }

    #[test]
    fn managed_snapshot_rejects_count_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        let request = request(Protocol::Reality, config.clone());
        let (server, _, _, _) = generate_reality(&request);
        fs::write(&config, serde_yaml::to_string(&vec![server]).unwrap()).unwrap();
        fs::write(
            &state,
            serde_json::to_vec(&ManagedState::default()).unwrap(),
        )
        .unwrap();
        assert!(validate_managed_snapshot(&config, &state).is_err());
    }

    #[test]
    fn validates_reality_destination_host_and_port() {
        validate_host_port("www.cloudflare.com:443").unwrap();
        validate_host_port("[2001:db8::1]:443").unwrap();
        assert!(validate_host_port("2001:db8::1:443").is_err());
        assert!(validate_host_port("example.com:not-a-port").is_err());
        assert!(validate_host_port("example.com:0").is_err());
    }

    #[test]
    fn managed_commit_restores_exact_config_when_state_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let state = dir.path().join("state.json");
        fs::write(&config, b"old-config").unwrap();

        let error = commit_managed_with_state_writer(
            &config,
            &state,
            "new-config",
            &ManagedState::default(),
            |_, _| Err(anyhow::anyhow!("injected state write failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("已回滚"));
        assert_eq!(fs::read(&config).unwrap(), b"old-config");
        assert!(!state.exists());
    }

    #[tokio::test]
    async fn rejected_candidate_is_removed_without_touching_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("config.yaml");
        fs::write(&live, b"known-good").unwrap();
        let current_test_binary = std::env::current_exe().unwrap();

        let result =
            validate_candidate_with_binary("candidate: invalid", dir.path(), &current_test_binary)
                .await;
        assert!(result.is_err());
        assert_eq!(fs::read(&live).unwrap(), b"known-good");
        let leftovers = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ping-rust-candidate-")
            })
            .count();
        assert_eq!(leftovers, 0);
    }
}
````

## `src/service.rs`

````rust
use std::{fs, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use crate::utils;

pub const SERVICE_NAME: &str = "shoes.service";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ServiceAction {
    Install,
    Start,
    Stop,
    Restart,
    Status,
    Enable,
    Disable,
}

pub fn unit_contents() -> String {
    format!(
        r#"[Unit]
Description=shoes proxy server managed by ping-rust
Documentation=https://github.com/cfal/shoes
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart={} {}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths={}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
"#,
        utils::SHOES_BIN,
        utils::CONFIG_FILE,
        utils::CONFIG_DIR
    )
}

pub fn install_unit(enable_now: bool) -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    utils::atomic_write(
        Path::new(utils::SERVICE_FILE),
        unit_contents().as_bytes(),
        0o644,
    )?;
    systemctl(&["daemon-reload"])?;
    if enable_now {
        systemctl(&["enable", "--now", SERVICE_NAME])?;
    }
    Ok(())
}

pub fn execute(action: ServiceAction) -> Result<()> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    match action {
        ServiceAction::Install => install_unit(false),
        ServiceAction::Start => systemctl(&["start", SERVICE_NAME]),
        ServiceAction::Stop => systemctl(&["stop", SERVICE_NAME]),
        ServiceAction::Restart => systemctl(&["restart", SERVICE_NAME]),
        ServiceAction::Status => systemctl(&["status", "--no-pager", SERVICE_NAME]),
        ServiceAction::Enable => systemctl(&["enable", "--now", SERVICE_NAME]),
        ServiceAction::Disable => systemctl(&["disable", "--now", SERVICE_NAME]),
    }
}

pub fn logs(lines: usize) -> Result<()> {
    utils::require_linux()?;
    let status = Command::new("journalctl")
        .args(["-u", SERVICE_NAME, "--no-pager", "-n", &lines.to_string()])
        .status()
        .context("无法执行 journalctl")?;
    if !status.success() {
        bail!("journalctl 执行失败（退出码：{status}）");
    }
    Ok(())
}

pub fn uninstall_unit() -> Result<bool> {
    utils::require_linux_root()?;
    ensure_systemctl()?;
    let path = Path::new(utils::SERVICE_FILE);
    if !path.exists() {
        return Ok(false);
    }

    systemctl(&["disable", "--now", SERVICE_NAME])?;
    fs::remove_file(path).context("删除 systemd unit 失败")?;
    systemctl(&["daemon-reload"])?;
    Ok(true)
}

pub fn is_active() -> Result<bool> {
    utils::require_linux()?;
    ensure_systemctl()?;
    Ok(Command::new("systemctl")
        .args(["is-active", "--quiet", SERVICE_NAME])
        .status()
        .context("无法查询 systemd 服务状态")?
        .success())
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("无法执行 systemctl {}", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} 失败（退出码：{status}）", args.join(" "));
    }
    Ok(())
}

fn ensure_systemctl() -> Result<()> {
    if !utils::command_exists("systemctl") {
        bail!("未找到 systemctl；当前系统可能未使用 systemd");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_uses_expected_paths_and_hardening() {
        let unit = unit_contents();
        assert!(unit.contains("ExecStart=/usr/local/bin/shoes /etc/shoes/config.yaml"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }
}
````

## `src/utils.rs`

````rust
use std::{
    env, fs,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use fs2::FileExt;

pub const SHOES_BIN: &str = "/usr/local/bin/shoes";
pub const CONFIG_DIR: &str = "/etc/shoes";
pub const CONFIG_FILE: &str = "/etc/shoes/config.yaml";
pub const STATE_FILE: &str = "/etc/shoes/ping-rust-state.json";
pub const LOCK_FILE: &str = "/run/lock/ping-rust.lock";
pub const SERVICE_FILE: &str = "/etc/systemd/system/shoes.service";

pub fn require_linux() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        bail!("该操作仅支持 Linux；当前系统为 {}", std::env::consts::OS)
    }
}

pub fn require_linux_root() -> Result<()> {
    require_linux()?;
    let output = Command::new("id")
        .arg("-u")
        .output()
        .context("无法检查当前用户权限")?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != "0" {
        bail!("该操作需要 root 权限，请使用 sudo ping-rust ...")
    }
    Ok(())
}

pub fn command_exists(name: &str) -> bool {
    command_path(name).is_some()
}

pub fn command_path(name: &str) -> Option<PathBuf> {
    let requested = Path::new(name);
    if requested.components().count() > 1 {
        return is_executable(requested).then(|| requested.to_path_buf());
    }

    env::var_os("PATH")
        .and_then(|path| {
            env::split_paths(&path).find_map(|directory| {
                command_candidates(&directory, name)
                    .into_iter()
                    .find(|candidate| is_executable(candidate))
            })
        })
        .or_else(|| {
            std::env::current_exe().ok().and_then(|executable| {
                executable.parent().and_then(|parent| {
                    command_candidates(parent, name)
                        .into_iter()
                        .find(|candidate| is_executable(candidate))
                })
            })
        })
}

fn command_candidates(directory: &Path, name: &str) -> Vec<PathBuf> {
    let base = directory.join(name);
    #[cfg(windows)]
    {
        if Path::new(name).extension().is_some() {
            return vec![base];
        }
        let extensions = env::var_os("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.is_empty())
                    .map(|extension| base.with_extension(extension.trim_start_matches('.')))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![base.with_extension("exe")]);
        extensions
    }
    #[cfg(not(windows))]
    vec![base]
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

pub struct ExclusiveLock(File);

pub fn exclusive_lock(path: &Path) -> Result<ExclusiveLock> {
    let parent = path.parent().context("锁文件路径没有父目录")?;
    fs::create_dir_all(parent).with_context(|| format!("创建锁目录 {} 失败", parent.display()))?;
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("打开锁文件 {} 失败", path.display()))?;
    set_mode(path, 0o600)?;
    file.lock_exclusive()
        .with_context(|| format!("锁定 {} 失败", path.display()))?;
    Ok(ExclusiveLock(file))
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub fn atomic_write(destination: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = destination.parent().context("目标路径没有父目录")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::create_dir_all(parent).with_context(|| format!("创建目录 {} 失败", parent.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("无法在 {} 创建临时文件", parent.display()))?;
    temp.write_all(contents).context("写入临时文件失败")?;
    temp.as_file().sync_all().context("同步临时文件失败")?;
    set_mode(temp.path(), mode)?;
    persist_replace(temp, destination)
}

pub fn atomic_copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let bytes = fs::read(source).with_context(|| format!("读取 {} 失败", source.display()))?;
    atomic_write(destination, &bytes, mode)
}

fn persist_replace(temp: tempfile::NamedTempFile, destination: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    if destination.exists() {
        fs::remove_file(destination)
            .with_context(|| format!("替换 {} 失败", destination.display()))?;
    }
    temp.persist(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("原子替换 {} 失败", destination.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yaml");
        atomic_write(&file, b"first", 0o600).unwrap();
        atomic_write(&file, b"second", 0o600).unwrap();
        assert_eq!(fs::read(file).unwrap(), b"second");
    }

    #[test]
    fn command_exists_does_not_require_which() {
        assert!(command_exists(
            std::env::current_exe().unwrap().to_str().unwrap()
        ));
        assert!(!command_exists("ping-rust-command-that-does-not-exist"));
    }

    #[test]
    fn exclusive_lock_can_be_reacquired_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        drop(exclusive_lock(&path).unwrap());
        drop(exclusive_lock(&path).unwrap());
    }
}
````

## `src/operations.rs`

````rust
use std::{
    fs::{self, File},
    io,
    net::{TcpListener, UdpSocket},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use tar::Archive;

use crate::{config, service, utils};

pub struct PortStatus {
    pub tcp_available: Option<Result<(), String>>,
    pub udp_available: Option<Result<(), String>>,
}

pub fn check_port(port: u16, tcp: bool, udp: bool) -> PortStatus {
    PortStatus {
        tcp_available: tcp.then(|| {
            TcpListener::bind(("0.0.0.0", port))
                .map(drop)
                .map_err(|error| error.to_string())
        }),
        udp_available: udp.then(|| {
            UdpSocket::bind(("0.0.0.0", port))
                .map(drop)
                .map_err(|error| error.to_string())
        }),
    }
}

pub fn enable_bbr() -> Result<()> {
    utils::require_linux_root()?;
    if utils::command_exists("modprobe") {
        let _ = Command::new("modprobe").arg("tcp_bbr").status();
    }
    let settings = b"net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n";
    let sysctl_file = Path::new("/etc/sysctl.d/99-ping-rust-bbr.conf");
    utils::atomic_write(sysctl_file, settings, 0o644)?;
    let status = Command::new("sysctl")
        .arg("--system")
        .status()
        .context("无法执行 sysctl --system")?;
    if !status.success() {
        bail!(
            "sysctl --system 失败；设置文件保留在 {}",
            sysctl_file.display()
        );
    }
    let algorithms = fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")
        .context("无法读取内核拥塞控制算法列表")?;
    if !algorithms.split_whitespace().any(|name| name == "bbr") {
        bail!("当前内核未提供 BBR；请升级内核后重试");
    }
    let active = fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control")
        .context("无法读取当前拥塞控制算法")?;
    if active.trim() != "bbr" {
        bail!("BBR 已写入 sysctl，但当前算法仍为 {}", active.trim());
    }
    Ok(())
}

pub fn backup(output: Option<PathBuf>) -> Result<PathBuf> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let source = Path::new(utils::CONFIG_DIR);
    if !source.is_dir() {
        bail!("配置目录 {} 不存在", source.display());
    }
    let destination =
        output.unwrap_or_else(|| PathBuf::from(format!("shoes-backup-{}.tar.gz", timestamp())));
    if destination.exists() {
        bail!("备份文件 {} 已存在，拒绝覆盖", destination.display());
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("创建备份目录失败")?;
    let temp = tempfile::NamedTempFile::new_in(parent).context("创建备份临时文件失败")?;
    {
        let encoder = GzEncoder::new(temp.as_file(), Compression::default());
        let mut tar = tar::Builder::new(encoder);
        tar.append_dir_all("shoes", source)
            .context("将配置加入备份归档失败")?;
        let encoder = tar.into_inner().context("结束 tar 归档失败")?;
        encoder.finish().context("结束 gzip 压缩失败")?;
    }
    temp.persist(&destination)
        .map_err(|error| error.error)
        .context("保存备份文件失败")?;
    set_private_permissions(&destination)?;
    Ok(destination)
}

pub async fn restore(archive_path: &Path) -> Result<Option<PathBuf>> {
    utils::require_linux_root()?;
    let _lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    if !archive_path.is_file() {
        bail!("备份文件 {} 不存在", archive_path.display());
    }
    let stage = tempfile::tempdir().context("创建恢复临时目录失败")?;
    extract_backup(archive_path, stage.path())?;
    let restored = stage.path().join("shoes");
    if !restored.join("config.yaml").is_file() {
        bail!("归档缺少 shoes/config.yaml");
    }
    let yaml = fs::read_to_string(restored.join("config.yaml"))?;
    let _: Vec<serde_yaml::Value> =
        serde_yaml::from_str(&yaml).context("备份中的 config.yaml 不是有效 YAML 数组")?;
    if restored.join("ping-rust-state.json").exists() {
        config::validate_managed_snapshot(
            &restored.join("config.yaml"),
            &restored.join("ping-rust-state.json"),
        )?;
    }

    let destination = Path::new(utils::CONFIG_DIR);
    let rollback = destination.with_extension(format!("pre-restore-{}", timestamp()));
    let had_existing = destination.exists();
    let unit_exists = Path::new(utils::SERVICE_FILE).exists();
    let was_active = unit_exists && service::is_active()?;
    if had_existing {
        fs::rename(destination, &rollback).context("暂存现有配置失败")?;
    }
    if let Err(error) = copy_tree(&restored, destination) {
        rollback_restore(destination, &rollback, had_existing)?;
        return Err(error.context("复制恢复文件失败，原配置已回滚"));
    }
    if let Err(error) = config::validate_with_shoes(Path::new(utils::CONFIG_FILE)).await {
        rollback_restore(destination, &rollback, had_existing)?;
        return Err(error.context("恢复配置未通过 shoes 校验，原配置已回滚"));
    }
    if was_active {
        if let Err(error) = service::execute(crate::service::ServiceAction::Restart) {
            rollback_restore(destination, &rollback, had_existing)?;
            if let Err(restart_error) = service::execute(crate::service::ServiceAction::Restart) {
                return Err(error.context(format!(
                    "恢复后的服务启动失败，文件已回滚，但原服务恢复也失败：{restart_error:#}"
                )));
            }
            return Err(error.context("恢复后的服务启动失败，原配置和服务已回滚"));
        }
    }
    Ok(had_existing.then_some(rollback))
}

fn extract_backup(archive_path: &Path, destination: &Path) -> Result<()> {
    let file = File::open(archive_path).context("打开备份归档失败")?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    for entry in archive.entries().context("读取备份归档失败")? {
        let mut entry = entry.context("读取备份条目失败")?;
        let path = entry.path().context("备份条目路径无效")?.into_owned();
        if !is_safe_relative_path(&path) {
            bail!("备份包含不安全路径 {}", path.display());
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!("备份包含不允许的链接或特殊文件 {}", path.display());
        }
        if !entry.unpack_in(destination).context("解压备份条目失败")? {
            bail!("备份条目越过恢复目录 {}", path.display());
        }
    }
    Ok(())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            bail!("恢复源包含链接或特殊文件 {}", entry.path().display());
        }
    }
    Ok(())
}

fn rollback_restore(destination: &Path, rollback: &Path, had_existing: bool) -> Result<()> {
    if destination != Path::new(utils::CONFIG_DIR) {
        bail!("内部安全检查失败：恢复目标不是预期配置目录");
    }
    if destination.exists() {
        fs::remove_dir_all(destination).context("清理失败的恢复目录失败")?;
    }
    if had_existing {
        fs::rename(rollback, destination).context("回滚原配置失败")?;
    }
    Ok(())
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn rejects_archive_traversal_paths() {
        assert!(!is_safe_relative_path(Path::new("../etc/passwd")));
        assert!(!is_safe_relative_path(Path::new("/etc/passwd")));
        assert!(is_safe_relative_path(Path::new("shoes/config.yaml")));
    }

    #[test]
    fn port_check_reports_requested_protocols() {
        let status = check_port(0, true, false);
        assert!(matches!(status.tcp_available, Some(Ok(()))));
        assert!(status.udp_available.is_none());
    }

    #[test]
    fn extracts_safe_backup_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("backup.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(file, Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let contents = b"- address: 0.0.0.0:443\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, "shoes/config.yaml", Cursor::new(contents))
                .unwrap();
            builder.finish().unwrap();
        }
        let output = dir.path().join("output");
        fs::create_dir(&output).unwrap();
        extract_backup(&archive_path, &output).unwrap();
        assert_eq!(
            fs::read(output.join("shoes/config.yaml")).unwrap(),
            b"- address: 0.0.0.0:443\n"
        );
    }

    #[test]
    fn rejects_symlink_backup_entry() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("link.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let encoder = GzEncoder::new(file, Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder
                .append_data(&mut header, "shoes/key.pem", io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        let output = dir.path().join("output");
        fs::create_dir(&output).unwrap();
        let error = extract_backup(&archive_path, &output).unwrap_err();
        assert!(error.to_string().contains("链接或特殊文件"));
    }
}
````

## `src/client.rs`

````rust
use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde_json::{json, Value};
use url::form_urlencoded::{byte_serialize, Serializer};
use uuid::Uuid;

use crate::{
    config::{self, Credentials, ManagedProfile},
    utils,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ClientFormat {
    ClashMeta,
    SingBox,
    Nekobox,
}

pub fn export(
    profile_id: Option<Uuid>,
    format: ClientFormat,
    server: &str,
    output: Option<&Path>,
) -> Result<String> {
    if server.trim().is_empty() || server.contains(char::is_whitespace) {
        bail!("客户端 server 地址无效");
    }
    let state = config::load_state()?;
    let profile = match profile_id {
        Some(id) => state
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .with_context(|| format!("未找到配置 {id}"))?,
        None if state.profiles.len() == 1 => &state.profiles[0],
        None => bail!("存在多个配置，请用 --profile <UUID> 指定导出对象"),
    };
    let content = render(profile, format, server)?;
    if let Some(path) = output {
        utils::atomic_write(path, content.as_bytes(), 0o600)?;
    }
    Ok(content)
}

pub fn render(profile: &ManagedProfile, format: ClientFormat, server: &str) -> Result<String> {
    match format {
        ClientFormat::ClashMeta => clash_meta(profile, server),
        ClientFormat::SingBox => sing_box(profile, server),
        ClientFormat::Nekobox => Ok(share_uri(profile, server)),
    }
}

fn clash_meta(profile: &ManagedProfile, server: &str) -> Result<String> {
    let proxy = match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => json!({
            "name": profile.name,
            "type": "vless",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "network": "tcp",
            "udp": true,
            "tls": true,
            "servername": server_name,
            "flow": "xtls-rprx-vision",
            "client-fingerprint": "chrome",
            "reality-opts": { "public-key": public_key, "short-id": short_id }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
        } => json!({
            "name": profile.name,
            "type": "hysteria2",
            "server": server,
            "port": profile.port,
            "password": password,
            "sni": server_name,
            "skip-cert-verify": profile.self_signed_certificate
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => json!({
            "name": profile.name,
            "type": "tuic",
            "server": server,
            "port": profile.port,
            "uuid": user_id,
            "password": password,
            "sni": server_name,
            "alpn": ["h3"],
            "congestion-controller": "bbr",
            "udp-relay-mode": "native",
            "skip-cert-verify": profile.self_signed_certificate
        }),
    };
    serde_yaml::to_string(&json!({ "proxies": [proxy] })).context("生成 Clash Meta YAML 失败")
}

fn sing_box(profile: &ManagedProfile, server: &str) -> Result<String> {
    let tls = |server_name: &str, insecure: bool| {
        json!({
            "enabled": true,
            "server_name": server_name,
            "insecure": insecure
        })
    };
    let outbound: Value = match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => json!({
            "type": "vless",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": server_name,
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": { "enabled": true, "public_key": public_key, "short_id": short_id }
            }
        }),
        Credentials::Hysteria2 {
            password,
            server_name,
        } => json!({
            "type": "hysteria2",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "password": password,
            "tls": tls(server_name, profile.self_signed_certificate)
        }),
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => json!({
            "type": "tuic",
            "tag": profile.name,
            "server": server,
            "server_port": profile.port,
            "uuid": user_id,
            "password": password,
            "congestion_control": "bbr",
            "tls": tls(server_name, profile.self_signed_certificate)
        }),
    };
    serde_json::to_string_pretty(&json!({ "outbounds": [outbound] }))
        .context("生成 sing-box JSON 失败")
}

fn share_uri(profile: &ManagedProfile, server: &str) -> String {
    let host = authority_host(server);
    let fragment = encode(&profile.name);
    match &profile.credentials {
        Credentials::Reality {
            user_id,
            public_key,
            short_id,
            server_name,
            ..
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("encryption", "none")
                .append_pair("flow", "xtls-rprx-vision")
                .append_pair("security", "reality")
                .append_pair("sni", server_name)
                .append_pair("fp", "chrome")
                .append_pair("pbk", public_key)
                .append_pair("sid", short_id)
                .append_pair("type", "tcp");
            format!(
                "vless://{user_id}@{host}:{}?{}#{fragment}",
                profile.port,
                query.finish()
            )
        }
        Credentials::Hysteria2 {
            password,
            server_name,
        } => {
            let mut query = Serializer::new(String::new());
            query.append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query.append_pair("insecure", "1");
            }
            format!(
                "hysteria2://{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            )
        }
        Credentials::Tuic {
            user_id,
            password,
            server_name,
        } => {
            let mut query = Serializer::new(String::new());
            query
                .append_pair("congestion_control", "bbr")
                .append_pair("alpn", "h3")
                .append_pair("sni", server_name);
            if profile.self_signed_certificate {
                query.append_pair("allow_insecure", "1");
            }
            format!(
                "tuic://{user_id}:{}@{host}:{}?{}#{fragment}",
                encode(password),
                profile.port,
                query.finish()
            )
        }
    }
}

fn authority_host(server: &str) -> String {
    if server.contains(':') && !(server.starts_with('[') && server.ends_with(']')) {
        format!("[{server}]")
    } else {
        server.to_owned()
    }
}

fn encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Credentials;

    fn reality_profile() -> ManagedProfile {
        ManagedProfile {
            id: Uuid::nil(),
            name: "reality-test".to_owned(),
            port: 443,
            credentials: Credentials::Reality {
                user_id: Uuid::nil(),
                private_key: "private".to_owned(),
                public_key: "public".to_owned(),
                short_id: "0123456789abcdef".to_owned(),
                server_name: "www.cloudflare.com".to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        }
    }

    #[test]
    fn exports_reality_to_all_formats_without_private_key() {
        let profile = reality_profile();
        for format in [
            ClientFormat::ClashMeta,
            ClientFormat::SingBox,
            ClientFormat::Nekobox,
        ] {
            let output = render(&profile, format, "203.0.113.1").unwrap();
            assert!(output.contains("public"));
            assert!(!output.contains("private"));
        }
    }

    #[test]
    fn wraps_ipv6_authority() {
        let output = render(&reality_profile(), ClientFormat::Nekobox, "2001:db8::1").unwrap();
        assert!(output.contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn exports_hysteria2_self_signed_warning_flag() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "hy2".to_owned(),
            port: 8443,
            credentials: Credentials::Hysteria2 {
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: true,
        };
        let clash = render(&profile, ClientFormat::ClashMeta, "203.0.113.2").unwrap();
        let sing_box = render(&profile, ClientFormat::SingBox, "203.0.113.2").unwrap();
        assert!(clash.contains("skip-cert-verify: true"));
        assert!(sing_box.contains("\"insecure\": true"));
    }

    #[test]
    fn exports_tuic_required_fields() {
        let profile = ManagedProfile {
            id: Uuid::nil(),
            name: "tuic".to_owned(),
            port: 443,
            credentials: Credentials::Tuic {
                user_id: Uuid::nil(),
                password: "secret".to_owned(),
                server_name: "proxy.example.com".to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        let clash = render(&profile, ClientFormat::ClashMeta, "203.0.113.3").unwrap();
        let sing_box = render(&profile, ClientFormat::SingBox, "203.0.113.3").unwrap();
        assert!(clash.contains("congestion-controller: bbr"));
        assert!(sing_box.contains("\"congestion_control\": \"bbr\""));
    }
}
````

## `src/self_update.rs`

````rust
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::process::Command;

use crate::utils;

const RELEASES_API: &str = "https://api.github.com/repos/Jyanbai/ping-rust/releases";
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
const MAX_CHECKSUM_SIZE: u64 = 64 * 1024;
const MAX_BINARY_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum UpdateReport {
    Current {
        current: Version,
        available: Version,
    },
    Updated {
        from: Version,
        to: Version,
        destination: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}

pub async fn update(requested: Option<&str>, force: bool) -> Result<UpdateReport> {
    utils::require_linux()?;

    let target = target_for(std::env::consts::OS, std::env::consts::ARCH)?;
    let requested = requested.map(normalize_tag).transpose()?;
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .build()
        .context("创建自更新 HTTP 客户端失败")?;
    let release = fetch_release(&client, requested.as_ref().map(|(tag, _)| tag)).await?;
    let available = release_version(&release.tag_name)?;
    if let Some((tag, expected)) = &requested {
        if &available != expected {
            bail!("GitHub 为 {tag} 返回了不一致的版本 {}", release.tag_name);
        }
    }

    let current =
        Version::parse(env!("CARGO_PKG_VERSION")).context("当前 ping-rust 包含无效版本号")?;
    if !force
        && if requested.is_some() {
            available == current
        } else {
            available <= current
        }
    {
        return Ok(UpdateReport::Current { current, available });
    }

    let archive_name = format!("ping-rust-{target}.tar.gz");
    let archive_asset = unique_asset(&release.assets, &archive_name)?;
    let checksum_asset = unique_asset(&release.assets, "SHA256SUMS")?;
    let work = tempfile::tempdir().context("创建自更新临时目录失败")?;

    let checksum_path = work.path().join("SHA256SUMS");
    let checksum_digest = download_asset(
        &client,
        checksum_asset,
        &checksum_path,
        MAX_CHECKSUM_SIZE,
        false,
    )
    .await?;
    verify_api_digest(checksum_asset, &checksum_digest)?;
    let checksums = fs::read_to_string(&checksum_path).context("SHA256SUMS 不是有效 UTF-8 文本")?;
    let expected_digest = checksum_for(&checksums, &archive_name)?;

    let archive_path = work.path().join(&archive_name);
    let actual_digest = download_asset(
        &client,
        archive_asset,
        &archive_path,
        MAX_ARCHIVE_SIZE,
        true,
    )
    .await?;
    verify_api_digest(archive_asset, &actual_digest)?;
    if !actual_digest.eq_ignore_ascii_case(&expected_digest) {
        bail!(
            "{} SHA-256 校验失败：期望 {}，实际 {}；当前程序未修改",
            archive_name,
            expected_digest,
            actual_digest
        );
    }

    let extracted = extract_binary(&archive_path, work.path())?;
    set_executable(&extracted)?;
    verify_binary_version(&extracted, &available).await?;

    let destination = std::env::current_exe().context("无法确定当前 ping-rust 路径")?;
    if !destination.is_file() {
        bail!("当前 ping-rust 路径不是普通文件：{}", destination.display());
    }
    replace_binary(&extracted, &destination, &available).await?;

    Ok(UpdateReport::Updated {
        from: current,
        to: available,
        destination,
    })
}

async fn fetch_release(client: &Client, tag: Option<&String>) -> Result<GithubRelease> {
    let url = match tag {
        Some(tag) => format!("{RELEASES_API}/tags/{tag}"),
        None => format!("{RELEASES_API}/latest"),
    };
    client
        .get(url)
        .send()
        .await
        .context("请求 ping-rust GitHub Release 失败")?
        .error_for_status()
        .context("GitHub Release API 返回错误")?
        .json::<GithubRelease>()
        .await
        .context("解析 ping-rust GitHub Release 失败")
}

fn normalize_tag(value: &str) -> Result<(String, Version)> {
    let value = value.trim();
    let version = Version::parse(value.strip_prefix('v').unwrap_or(value))
        .with_context(|| format!("版本格式无效：{value}；示例：v0.1.1"))?;
    Ok((format!("v{version}"), version))
}

fn release_version(tag: &str) -> Result<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .with_context(|| format!("Release tag 不是有效语义版本：{tag}"))
}

fn target_for(os: &str, arch: &str) -> Result<&'static str> {
    if os != "linux" {
        bail!("ping-rust 自更新仅支持 Linux；当前系统为 {os}");
    }
    match arch {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        _ => bail!("ping-rust 自更新暂不支持架构 {arch}"),
    }
}

fn unique_asset<'a>(assets: &'a [ReleaseAsset], name: &str) -> Result<&'a ReleaseAsset> {
    let mut matches = assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .with_context(|| format!("Release 中缺少资产 {name}"))?;
    if matches.next().is_some() {
        bail!("Release 中存在重复资产 {name}");
    }
    Ok(asset)
}

async fn download_asset(
    client: &Client,
    asset: &ReleaseAsset,
    destination: &Path,
    max_size: u64,
    show_progress: bool,
) -> Result<String> {
    if asset.size > max_size {
        bail!("{} 尺寸异常：{} bytes", asset.name, asset.size);
    }
    let url = reqwest::Url::parse(&asset.browser_download_url)
        .with_context(|| format!("{} 下载 URL 无效", asset.name))?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        bail!("{} 下载 URL 不是受信任的 GitHub HTTPS 地址", asset.name);
    }

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("下载 {} 失败", asset.name))?
        .error_for_status()
        .with_context(|| format!("下载 {} 时服务器返回错误", asset.name))?;
    if response
        .content_length()
        .is_some_and(|size| size > max_size)
    {
        bail!("{} HTTP 内容长度超过安全上限", asset.name);
    }

    let progress = show_progress.then(|| {
        let progress = ProgressBar::new(response.content_length().unwrap_or(asset.size));
        if let Ok(style) = ProgressStyle::with_template(
            "{spinner:.green} [{bar:36.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        ) {
            progress.set_style(style.progress_chars("=>-"));
        }
        progress.set_message(format!("下载 {}", asset.name));
        progress
    });
    let mut output = File::create(destination)
        .with_context(|| format!("创建临时文件 {} 失败", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut received = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("GitHub Release 下载流中断")?;
        received = received
            .checked_add(chunk.len() as u64)
            .context("下载大小溢出")?;
        if received > max_size {
            bail!("{} 下载内容超过安全上限", asset.name);
        }
        output.write_all(&chunk).context("写入下载文件失败")?;
        hasher.update(&chunk);
        if let Some(progress) = &progress {
            progress.inc(chunk.len() as u64);
        }
    }
    output.sync_all().context("同步下载文件失败")?;
    if received != asset.size {
        bail!(
            "{} 下载大小不一致：Release 声明 {} bytes，实际 {} bytes",
            asset.name,
            asset.size,
            received
        );
    }
    if let Some(progress) = progress {
        progress.finish_with_message("下载完成");
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_api_digest(asset: &ReleaseAsset, actual: &str) -> Result<()> {
    if let Some(expected) = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
    {
        if !actual.eq_ignore_ascii_case(expected) {
            bail!(
                "{} 与 GitHub API digest 不一致：期望 {}，实际 {}",
                asset.name,
                expected,
                actual
            );
        }
    }
    Ok(())
}

fn checksum_for(contents: &str, filename: &str) -> Result<String> {
    let mut found = None;
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || fields[1] != filename {
            continue;
        }
        if found.is_some() {
            bail!("SHA256SUMS 中存在重复条目 {filename}");
        }
        let digest = fields[0];
        let decoded = hex::decode(digest)
            .with_context(|| format!("SHA256SUMS 中 {filename} 的摘要不是十六进制"))?;
        if decoded.len() != 32 {
            bail!("SHA256SUMS 中 {filename} 的摘要长度无效");
        }
        found = Some(digest.to_ascii_lowercase());
    }
    found.with_context(|| format!("SHA256SUMS 中缺少 {filename}"))
}

fn extract_binary(archive_path: &Path, work_dir: &Path) -> Result<PathBuf> {
    let file = File::open(archive_path).context("打开 ping-rust 归档失败")?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let destination = work_dir.join("ping-rust.extracted");
    let mut found = false;

    for entry in archive.entries().context("读取 ping-rust tar.gz 失败")? {
        let mut entry = entry.context("读取 ping-rust 归档条目失败")?;
        let path = entry.path().context("ping-rust 归档包含无效路径")?;
        if path.as_ref() != Path::new("ping-rust")
            || path.file_name() != Some(OsStr::new("ping-rust"))
            || !entry.header().entry_type().is_file()
        {
            bail!("ping-rust 归档只能包含根目录普通文件 ping-rust");
        }
        if found {
            bail!("ping-rust 归档包含重复二进制");
        }
        if entry.size() > MAX_BINARY_SIZE {
            bail!("ping-rust 二进制异常大（{} bytes）", entry.size());
        }
        let mut output = File::create(&destination).context("创建解压二进制失败")?;
        std::io::copy(&mut entry, &mut output).context("解压 ping-rust 失败")?;
        output.sync_all().context("同步解压二进制失败")?;
        found = true;
    }

    if !found {
        bail!("ping-rust 归档中没有二进制");
    }
    Ok(destination)
}

async fn replace_binary(source: &Path, destination: &Path, version: &Version) -> Result<()> {
    let original = fs::read(destination)
        .with_context(|| format!("备份当前程序 {} 失败", destination.display()))?;
    let original_mode = executable_mode(destination)?;
    utils::atomic_copy(source, destination, 0o755).with_context(|| {
        format!(
            "替换 {} 失败；若它位于系统目录，请使用 sudo ping-rust self-update",
            destination.display()
        )
    })?;

    if let Err(error) = verify_binary_version(destination, version).await {
        match utils::atomic_write(destination, &original, original_mode) {
            Ok(()) => bail!("新版本安装后验证失败，已恢复原程序：{error:#}"),
            Err(rollback) => {
                bail!("新版本安装后验证失败，且恢复原程序失败：验证={error:#}；恢复={rollback:#}")
            }
        }
    }
    Ok(())
}

async fn verify_binary_version(binary: &Path, version: &Version) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("无法执行 {} 版本检查", binary.display()))?;
    if !output.status.success() {
        bail!(
            "{} 版本检查失败（{}）：{}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("版本输出不是有效 UTF-8")?;
    let expected = format!("ping-rust {version}");
    if stdout.trim() != expected {
        bail!(
            "{} 版本不匹配：期望 {expected:?}，实际 {:?}",
            binary.display(),
            stdout.trim()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("设置 {} 可执行权限失败", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn executable_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)
        .with_context(|| format!("读取 {} 权限失败", path.display()))?
        .permissions()
        .mode()
        & 0o777)
}

#[cfg(not(unix))]
fn executable_mode(_path: &Path) -> Result<u32> {
    Ok(0o755)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive
                .append_data(&mut header, name, &contents[..])
                .unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn normalizes_requested_versions() {
        assert_eq!(
            normalize_tag("0.1.1").unwrap(),
            ("v0.1.1".to_owned(), Version::new(0, 1, 1))
        );
        assert_eq!(
            normalize_tag("v1.2.3-beta.1").unwrap(),
            (
                "v1.2.3-beta.1".to_owned(),
                Version::parse("1.2.3-beta.1").unwrap()
            )
        );
        assert!(normalize_tag("latest").is_err());
    }

    #[test]
    fn maps_supported_release_targets() {
        assert_eq!(
            target_for("linux", "x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            target_for("linux", "aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert!(target_for("windows", "x86_64").is_err());
        assert!(target_for("linux", "arm").is_err());
    }

    #[test]
    fn parses_exact_checksum_entry() {
        let checksum = "a".repeat(64);
        let contents = format!(
            "{}  other.tar.gz\n{}  ping-rust-x86_64-unknown-linux-musl.tar.gz\n",
            "b".repeat(64),
            checksum
        );
        assert_eq!(
            checksum_for(&contents, "ping-rust-x86_64-unknown-linux-musl.tar.gz").unwrap(),
            checksum
        );
        assert!(checksum_for(&contents, "missing.tar.gz").is_err());
    }

    #[test]
    fn rejects_duplicate_checksum_entries() {
        let digest = "a".repeat(64);
        let contents = format!("{digest}  package.tar.gz\n{digest}  package.tar.gz\n");
        assert!(checksum_for(&contents, "package.tar.gz").is_err());
    }

    #[test]
    fn extracts_strict_single_binary_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ping-rust.tar.gz");
        write_archive(&archive, &[("ping-rust", b"binary")]);
        let extracted = extract_binary(&archive, dir.path()).unwrap();
        assert_eq!(fs::read(extracted).unwrap(), b"binary");
    }

    #[test]
    fn rejects_archive_with_extra_entry() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("ping-rust.tar.gz");
        write_archive(
            &archive,
            &[("ping-rust", b"binary"), ("unexpected", b"payload")],
        );
        assert!(extract_binary(&archive, dir.path()).is_err());
    }
}
````

## `README.md`

````markdown
# ping-rust

`ping-rust` 是一个纯 Rust 编写的 [cfal/shoes](https://github.com/cfal/shoes) 安装与管理工具。它提供类似 233boy 脚本的数字菜单，在 Linux VPS 上完成 shoes 安装、VLESS-Reality/Hysteria2/TUIC 配置、systemd 管理和日常运维。

核心逻辑全部位于 Rust 源码中；`scripts/install.sh` 只负责下载、校验并安装官方预编译二进制。

## 一键安装（推荐）

无需预装 Rust。在 Ubuntu 22.04/24.04、Debian 12、Rocky Linux 9、AlmaLinux 9 等 systemd Linux 上执行：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh)
sudo ping-rust
```

安装指定版本或目录：

```bash
bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --version v0.1.1

bash <(curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Jyanbai/ping-rust/main/scripts/install.sh) \
  --install-dir /usr/local/bin --quiet
```

安装器自动识别 x86_64/aarch64，从 GitHub Releases 下载对应 musl 静态包，强制验证 `SHA256SUMS` 和二进制版本后原子安装到 `/usr/local/bin/ping-rust`。写入系统目录时会调用 `sudo`；令牌、密码和代理配置都不会被上传。

## 功能

- 从 GitHub Release 下载 shoes，自动匹配 x86_64/aarch64 与 GNU/musl，强制校验官方 SHA-256 digest；GNU 资产不兼容时安全回退 static musl
- 使用 `cargo install shoes` 从 crates.io 编译安装；低于 1 GiB 内存时自动单任务并关闭 LTO，避免换页风暴
- 生成 VLESS-Reality-Vision、Hysteria2、TUIC v5 服务端配置
- 在 Rust 内生成 X25519 Reality 密钥、UUID、short ID、随机密码和自签名证书
- 在同目录候选文件上调用 `shoes --dry-run`，通过后才原子提交并启用 systemd 服务
- 多配置添加、列表、删除、端口冲突保护
- 跨进程配置锁、配置/sidecar 精确回滚，更新与恢复保留服务原运行状态
- 服务启停、重启、状态、journalctl 日志、更新与卸载
- BBR、TCP/UDP 端口检查、敏感配置备份与安全恢复
- 导出 Clash Meta、sing-box 和 Nekobox 分享链接
- Rust 原生更新 ping-rust 自身：GitHub Release + `SHA256SUMS` 双重校验、版本探针、原子替换与失败回滚

## 支持环境

| 系统 | 架构 | Release 安装 | cargo 安装 |
|---|---|---:|---:|
| Ubuntu 22.04 / 24.04 | x86_64 / aarch64 | 是 | 是 |
| Debian 12 | x86_64 / aarch64 | 是 | 是 |
| Rocky Linux 9 / AlmaLinux 9 | x86_64 / aarch64 | 是 | 是 |

要求系统使用 systemd。一键安装 ping-rust 与 shoes Release 安装都不要求服务器预装 Rust；只有 cargo 安装方式需要稳定版 Rust 工具链。

## 其他安装方式

crate 发布到 crates.io 后：

```bash
cargo install ping-rust --locked
sudo ping-rust
```

直接从已公开的 GitHub `main` 安装：

```bash
cargo install --git https://github.com/Jyanbai/ping-rust.git --locked
sudo ping-rust
```

从当前源码安装：

```bash
git clone https://github.com/Jyanbai/ping-rust.git
cd ping-rust
cargo install --path . --locked
sudo ping-rust
```

首次启动、生成系统配置、管理 systemd、BBR、备份恢复和卸载都需要 root。生成到自定义路径、查看帮助和本地端口检查不要求 root。

## 三分钟 Reality 部署

```text
$ sudo ping-rust

ping-rust · shoes 管理工具
────────────────────────────
请选择操作
  1. 安装 shoes
  2. 添加代理配置
  3. 查看配置信息
  4. 删除配置
  5. 服务管理
  6. 更新 shoes
  7. 运维工具
  8. 卸载
  9. 退出
请输入序号 [1-9]:
```

1. 选择“安装 shoes” → “GitHub Release（推荐）”。
2. 选择“添加代理配置” → “VLESS-Reality-Vision（推荐）”。
3. 输入配置名、端口、SNI 和 fallback；通常可接受 `443`、`www.cloudflare.com` 和 `www.cloudflare.com:443`。
4. 工具写入配置，运行 `shoes --dry-run`，创建/启用 `shoes.service`。
5. 记录输出的 UUID、公钥和 short ID。Reality 私钥只应留在服务器。
6. 在“运维工具”中导出客户端配置，并填写 VPS 公网 IP 或域名。

非交互方式：

```bash
sudo ping-rust install --method release
sudo ping-rust generate reality \
  --name reality-main \
  --port 443 \
  --server-name www.cloudflare.com \
  --dest www.cloudflare.com:443
```

## Hysteria2 与 TUIC

快速生成：

```bash
sudo ping-rust generate hysteria2 --name hy2 --port 8443 --server-name proxy.example.com
sudo ping-rust generate tuic --name tuic --port 10443 --server-name proxy.example.com
```

未指定证书时会创建自签名证书。工具导出客户端配置时会设置相应的跳过校验字段，并显示风险提示；生产环境推荐使用受信任证书：

```bash
sudo ping-rust generate hysteria2 \
  --name hy2 \
  --port 8443 \
  --server-name proxy.example.com \
  --cert /etc/letsencrypt/live/proxy.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/proxy.example.com/privkey.pem
```

`--cert` 与 `--key` 必须同时提供。

## 常用命令

```bash
ping-rust --help
sudo ping-rust info
sudo ping-rust service status
sudo ping-rust service restart
sudo ping-rust logs -n 200
ping-rust check-port 443 --kind both
sudo ping-rust enable-bbr
sudo ping-rust update --method release
sudo ping-rust self-update
```

`update` 只更新 shoes 内核；`self-update` 更新 ping-rust 本身。默认安装最新 Release，也可以指定版本；显式指定旧版本表示受控降级：

```bash
sudo ping-rust self-update --version v0.1.1
sudo ping-rust self-update --version v0.1.1 --force
```

自更新支持 Linux x86_64/aarch64，下载对应 musl 静态包，校验 GitHub API digest 与 `SHA256SUMS`，确认新二进制版本后才替换当前程序。程序位于 `/usr/local/bin` 时通常需要 `sudo`；用户目录内可写的 cargo 安装则不需要。

多个配置使用不同端口。查看 ID 后删除：

```bash
sudo ping-rust info
sudo ping-rust delete <配置-UUID> --yes
```

## 客户端导出

```bash
sudo ping-rust export clash-meta --profile <配置-UUID> --server 203.0.113.10 --output clash.yaml
sudo ping-rust export sing-box --profile <配置-UUID> --server proxy.example.com --output sing-box.json
sudo ping-rust export nekobox --profile <配置-UUID> --server 203.0.113.10
```

只有一个配置时可以省略 `--profile`。导出内容包含客户端连接所需凭据，但 Reality 导出永远不包含服务器私钥。

## 备份与恢复

```bash
sudo ping-rust backup ./shoes-backup.tar.gz
sudo ping-rust restore ./shoes-backup.tar.gz
```

备份包含私钥、UUID 和密码，文件权限为 `0600`，请加密保存。恢复过程拒绝绝对路径、`..`、符号链接和特殊文件；新配置未通过 shoes 校验时会自动恢复旧目录。成功恢复后，旧目录仍保留为 `/etc/shoes.pre-restore-<时间戳>`，确认无误后再手动清理。

## 文件位置与权限

| 路径 | 用途 | 权限 |
|---|---|---:|
| `/usr/local/bin/shoes` | shoes 内核 | `0755` |
| `/etc/shoes/config.yaml` | shoes 配置 | `0600` |
| `/etc/shoes/ping-rust-state.json` | 多配置元数据与客户端导出凭据 | `0600` |
| `/etc/shoes/cert-*.pem` | 自动生成证书 | `0644` |
| `/etc/shoes/key-*.pem` | 自动生成证书私钥 | `0600` |
| `/run/lock/ping-rust.lock` | 配置操作进程间互斥 | `0600` |
| `/etc/systemd/system/shoes.service` | systemd unit | `0644` |

卸载默认保留 `/etc/shoes`。只有 `uninstall --purge` 或菜单二次确认才会删除配置。

## 故障排查

查看服务和日志：

```bash
sudo systemctl status shoes --no-pager
sudo journalctl -u shoes -n 200 --no-pager
sudo /usr/local/bin/shoes --dry-run /etc/shoes/config.yaml
```

- `Address already in use`：运行 `ping-rust check-port <端口>`，换用未占用端口。
- Reality 连接失败：检查 VPS 防火墙、安全组、UUID、公钥、short ID、SNI 和 fallback 是否一致，并用 `timedatectl status` 确认客户端与服务端时钟已同步。
- Hysteria2/TUIC 失败：确认 UDP 端口已放行，并检查证书域名。
- `systemctl` 不存在：当前系统不是 systemd 环境，服务管理功能无法使用。
- GitHub API 限流：稍后重试，或使用 `install --method cargo`。
- 自更新提示权限不足：若当前程序位于 `/usr/local/bin`，改用 `sudo ping-rust self-update`；不要手工覆盖正在更新的文件。
- cargo 安装版本较旧：GitHub Release 与 crates.io 的发布时间可能不同，优先选择 Release。
- cargo 编译很慢：低内存 VPS 上源码模式可能需要数十分钟；这是回退通道，默认部署应优先使用 Release。

## 开发与验证

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo doc --no-deps
```

本仓库开发阶段已完成：

- Rust 单元测试覆盖密钥/YAML、归档解包、原子写入、systemd unit、端口检查、客户端三格式和恢复路径安全。
- 自更新单元测试覆盖版本、架构、checksum 重复/缺失和严格单文件归档；Release job 还会真实执行一次强制自更新并复核版本。
- 使用 shoes 0.2.8 对 ping-rust 实际生成的 Reality、Hysteria2、TUIC 三份配置执行联合 `--dry-run`，解析成功并加载证书。
- 通过 cargo-zigbuild + Zig 生成 x86_64/aarch64 Linux GNU release ELF，最高 GLIBC 需求为 2.34，覆盖 Rocky/Alma 9 及更新的目标发行版基线。
- CI 定义覆盖 Ubuntu 22.04/24.04，并在 Debian 12、Rocky Linux 9、AlmaLinux 9 容器中执行锁定依赖测试和 release 构建；工作流实际结果需在推送 GitHub 后确认。
- 使用 RustSec `cargo audit` 扫描锁定依赖，当前未报告安全公告。
- 在一台干净代理环境的 Debian 12 x86_64 VPS 上完成原生安装与运行验收：Release 路径约 2 秒完成 shoes v0.2.7 musl 安装，三协议同时通过 dry-run 并由 systemd 启动，外部 Reality 客户端的代理出口与 VPS 公网 IP 一致。
- 实机完成 9 份客户端导出解析、BBR、端口检查、日志、备份恢复、inactive 状态保持和 Release 更新；详细证据见完成度审计。

逐项需求、修复记录、ELF 哈希和外部验收边界见 [COMPLETION_AUDIT.md](COMPLETION_AUDIT.md)。

发布前应在全新 Ubuntu 24.04 x86_64 VPS 执行以下实机验收：

1. `cargo install --path . --locked`。
2. Release 与 cargo 两种 shoes 安装方式各测试一次。
3. 三种协议分别生成、启动，并从外部客户端连接。
4. 重启 VPS，确认 `shoes.service` 自动启动。
5. 验证更新、日志、BBR、备份恢复、删除和卸载。

当前 Debian 12 VPS 证据可以证明 Linux/systemd 与公网 Reality 路径可用，但不能替代成功标准指定的 Ubuntu 24.04 实机；完成上述 Ubuntu 清单前，不宣称“Ubuntu 24.04 实机全部通过”。

## 截图建议

发布 README 时建议补充三张终端截图：

1. 主数字菜单全景。
2. Reality 生成完成画面（必须遮盖私钥、UUID 和 short ID）。
3. `systemctl status shoes` 与客户端连通性测试。

## 仓库结构

```text
ping-rust/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── .gitignore
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── menu.rs
│   ├── installer.rs
│   ├── config.rs
│   ├── service.rs
│   ├── client.rs
│   ├── operations.rs
│   ├── self_update.rs
│   └── utils.rs
├── examples/
│   ├── reality.yaml
│   ├── hysteria2.yaml
│   └── tuic.yaml
├── systemd/
│   └── ping-rust.service
└── scripts/
    └── install.sh
```

## 项目仓库

源码仓库：[Jyanbai/ping-rust](https://github.com/Jyanbai/ping-rust)

## 许可证

[MIT License](LICENSE)
````
