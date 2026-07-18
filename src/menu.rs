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
