use anyhow::Result;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};

use crate::{
    cli,
    client::{self, ClientFormat},
    config::{
        self, AnyTlsMode, AnyTlsUser, GenerationOptions, GenerationRequest, Protocol,
        ShadowsocksCipher,
    },
    deployment, fast_add,
    installer::{self, InstallMethod},
    operations,
    service::{self, ServiceAction},
};

const MAIN_MENU_ITEMS: &[(usize, &str)] = &[
    (1, "添加配置"),
    (2, "更改配置"),
    (3, "查看配置"),
    (4, "删除配置"),
    (5, "运行管理"),
    (6, "更新"),
    (7, "卸载"),
    (8, "帮助"),
    (9, "其他"),
    (10, "关于"),
];

const PROTOCOL_MENU_ITEMS: &[(usize, &str)] = &[
    (1, "TUIC"),
    (3, "Hysteria2"),
    (8, "Shadowsocks"),
    (18, "VLESS-REALITY（推荐）"),
    (20, "AnyTLS"),
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

fn select_keyed(prompt: &str, items: &[(usize, &str)], empty_exits: bool) -> Result<Option<usize>> {
    println!("{prompt}");
    for (key, label) in items {
        println!("  {key}. {label}");
    }
    loop {
        let value = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt(if empty_exits {
                "请输入序号（直接回车退出）"
            } else {
                "请输入序号"
            })
            .allow_empty(empty_exits)
            .interact_text()?;
        if value.trim().is_empty() && empty_exits {
            return Ok(None);
        }
        let Ok(key) = value.trim().parse::<usize>() else {
            println!("请输入有效数字。");
            continue;
        };
        if items.iter().any(|(candidate, _)| *candidate == key) {
            return Ok(Some(key));
        }
        println!(
            "无效序号；可选 {}。",
            items
                .iter()
                .map(|(key, _)| key.to_string())
                .collect::<Vec<_>>()
                .join("、")
        );
    }
}

pub async fn run() -> Result<()> {
    println!();
    println!("{}", "ping-rust · shoes 管理工具".bright_cyan().bold());
    println!("{}", "────────────────────────────".bright_black());
    let Some(selected) = select_keyed("请选择操作", MAIN_MENU_ITEMS, true)? else {
        println!("{}", "已退出。".green());
        return Ok(());
    };
    match selected {
        1 => fast_add_config_menu().await,
        2 => {
            println!("更改配置请使用完整 generate 参数，或删除后通过快速添加安全重建。");
            Ok(())
        }
        3 => cli::show_info(None).await,
        4 => delete_config_menu().await,
        5 => service_menu(),
        6 => update_menu().await,
        7 => uninstall_menu(),
        8 => {
            println!("常用命令：sb add reality、sb add ss、sb info、sb url、sb qr");
            println!("高级帮助：ping-rust --help");
            Ok(())
        }
        9 => operations_menu().await,
        10 => {
            println!("ping-rust {}", env!("CARGO_PKG_VERSION"));
            println!("Rust 实现的 shoes 菜单式安装与管理工具");
            println!("https://github.com/Jyanbai/ping-rust");
            Ok(())
        }
        _ => anyhow::bail!("菜单返回了无效选项"),
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
        "高级添加配置",
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
        0 => advanced_add_config_menu().await,
        1 => service::logs(100),
        2 => {
            let port = Input::<u16>::with_theme(&ColorfulTheme::default())
                .with_prompt("检查端口")
                .default(443)
                .interact_text()?;
            cli::print_port_status(port, operations::check_port(port, true, true));
            Ok(())
        }
        3 => {
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
        4 => {
            let path = operations::backup(None)?;
            println!("备份已创建：{}", path.display());
            println!("备份含私钥和密码，请安全保管。");
            Ok(())
        }
        5 => {
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
        6 => export_menu(),
        7 => cli::run_self_update(None, false).await,
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

async fn fast_add_config_menu() -> Result<()> {
    cli::ensure_shoes_for_add(false).await?;
    let protocol_number = select_keyed("选择协议", PROTOCOL_MENU_ITEMS, false)?
        .ok_or_else(|| anyhow::anyhow!("未选择协议"))?;
    let protocol = fast_add::protocol_from_reference_number(protocol_number)?;
    let port_text = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("输入端口（直接回车自动选择随机端口）")
        .allow_empty(true)
        .validate_with(|value: &String| {
            if value.trim().is_empty() {
                return Ok(());
            }
            match value.trim().parse::<u16>() {
                Ok(port) if port > 0 => Ok(()),
                _ => Err("端口必须在 1..=65535 范围内，或直接回车"),
            }
        })
        .interact_text()?;
    let port = if port_text.trim().is_empty() {
        None
    } else {
        Some(port_text.trim().parse::<u16>()?)
    };
    let server_address = match fast_add::resolve_server_address(None).await {
        Ok(address) => address,
        Err(error) => {
            eprintln!("自动检测公网地址失败：{error:#}");
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("请输入 VPS 公网域名或 IP")
                .interact_text()?
        }
    };
    let result = fast_add::execute(fast_add::AddRequest {
        name: None,
        protocol,
        port,
        server_address: Some(server_address),
        server_name: None,
    })
    .await?;
    cli::print_add_result(&result);
    Ok(())
}

async fn advanced_add_config_menu() -> Result<()> {
    let choices = [
        "VLESS-Reality-Vision（推荐）",
        "Hysteria2",
        "TUIC v5",
        "Shadowsocks 2022",
        "AnyTLS",
        "返回",
    ];
    let selected = select_numbered("选择协议", &choices)?;
    let protocol = match selected {
        0 => Protocol::Reality,
        1 => Protocol::Hysteria2,
        2 => Protocol::Tuic,
        3 => Protocol::Shadowsocks,
        4 => Protocol::AnyTls,
        _ => return Ok(()),
    };
    let name = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("配置名称")
        .default(match protocol {
            Protocol::Reality => "reality".to_owned(),
            Protocol::Hysteria2 => "hysteria2".to_owned(),
            Protocol::Tuic => "tuic".to_owned(),
            Protocol::Shadowsocks => "shadowsocks".to_owned(),
            Protocol::AnyTls => "anytls".to_owned(),
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
    let mut options = GenerationOptions::default();
    if matches!(protocol, Protocol::Shadowsocks) {
        let ciphers = [
            "2022-blake3-aes-256-gcm（推荐）",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-chacha20-ietf-poly1305",
            "aes-256-gcm",
            "aes-128-gcm",
            "chacha20-ietf-poly1305",
        ];
        options.shadowsocks_cipher = match select_numbered("选择加密方式", &ciphers)? {
            0 => ShadowsocksCipher::Aes256Gcm2022,
            1 => ShadowsocksCipher::Aes128Gcm2022,
            2 => ShadowsocksCipher::Chacha20IetfPoly13052022,
            3 => ShadowsocksCipher::Aes256Gcm,
            4 => ShadowsocksCipher::Aes128Gcm,
            _ => ShadowsocksCipher::Chacha20IetfPoly1305,
        };
    }
    if matches!(protocol, Protocol::AnyTls) {
        options.anytls_mode =
            match select_numbered("AnyTLS 外层安全模式", &["TLS（推荐）", "Reality（高级）"])?
            {
                0 => AnyTlsMode::Tls,
                _ => AnyTlsMode::Reality,
            };
        loop {
            let default_name = if options.anytls_users.is_empty() {
                "default".to_owned()
            } else {
                format!("user{}", options.anytls_users.len() + 1)
            };
            let user_name = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("AnyTLS 用户名")
                .default(default_name)
                .interact_text()?;
            let password = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("AnyTLS 密码（留空则安全随机生成）")
                .allow_empty(true)
                .interact_text()?;
            options.anytls_users.push(if password.is_empty() {
                config::generated_anytls_user(user_name)
            } else {
                AnyTlsUser {
                    name: user_name,
                    password,
                }
            });
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("继续添加 AnyTLS 用户？")
                .default(false)
                .interact()?
            {
                break;
            }
        }
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("使用推荐 padding_scheme？")
            .default(true)
            .interact()?
        {
            options.anytls_padding_scheme = Some(vec![
                "stop=8".to_owned(),
                "0=30-30".to_owned(),
                "1=50-100".to_owned(),
            ]);
        }
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("配置认证失败 fallback？")
            .default(false)
            .interact()?
        {
            options.anytls_fallback = Some(
                Input::<String>::with_theme(&ColorfulTheme::default())
                    .with_prompt("AnyTLS fallback（host:port）")
                    .default("127.0.0.1:80".to_owned())
                    .interact_text()?,
            );
        }
    }
    let server_name = if matches!(protocol, Protocol::Shadowsocks) {
        config::DEFAULT_SNI.to_owned()
    } else {
        Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt(
                if matches!(protocol, Protocol::Reality)
                    || options.anytls_mode == AnyTlsMode::Reality
                {
                    "Reality SNI"
                } else {
                    "证书域名/服务器名称"
                },
            )
            .default(config::DEFAULT_SNI.to_owned())
            .interact_text()?
    };
    let reality_dest = if matches!(protocol, Protocol::Reality)
        || (matches!(protocol, Protocol::AnyTls) && options.anytls_mode == AnyTlsMode::Reality)
    {
        Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Reality fallback")
                .default(format!("{server_name}:443"))
                .interact_text()?,
        )
    } else {
        None
    };
    let needs_certificate = matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic)
        || (matches!(protocol, Protocol::AnyTls) && options.anytls_mode == AnyTlsMode::Tls);
    let (certificate, certificate_key) = if needs_certificate
        && Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("使用已有 PEM 证书和私钥？（否则自动生成自签名证书）")
            .default(false)
            .interact()?
    {
        let cert = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("PEM 证书路径")
            .interact_text()?;
        let key = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("PEM 私钥路径")
            .interact_text()?;
        (Some(cert.into()), Some(key.into()))
    } else {
        (None, None)
    };

    let result = deployment::generate_and_activate(GenerationRequest {
        name: Some(name),
        protocol,
        port,
        output: crate::utils::CONFIG_FILE.into(),
        server_address: None,
        server_name,
        reality_dest,
        certificate,
        certificate_key,
        options,
    })
    .await?;
    cli::print_credentials(&result);
    println!("{}", "配置验证通过，服务已启动。".green());
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
    let alias_removed = crate::utils::remove_sb_alias()?;
    if purge && std::path::Path::new(crate::utils::CONFIG_DIR).exists() {
        std::fs::remove_dir_all(crate::utils::CONFIG_DIR)?;
    }
    println!(
        "卸载完成：二进制={}，systemd={}，sb 别名={}，配置清理={}",
        binary_removed, unit_removed, alias_removed, purge
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_reference_main_and_protocol_numbers() {
        assert_eq!(MAIN_MENU_ITEMS.first().unwrap().0, 1);
        assert_eq!(MAIN_MENU_ITEMS.last().unwrap().0, 10);
        for (number, protocol) in [
            (1, Protocol::Tuic),
            (3, Protocol::Hysteria2),
            (8, Protocol::Shadowsocks),
            (18, Protocol::Reality),
            (20, Protocol::AnyTls),
        ] {
            assert!(PROTOCOL_MENU_ITEMS.iter().any(|item| item.0 == number));
            assert_eq!(
                fast_add::protocol_from_reference_number(number).unwrap(),
                protocol
            );
        }
    }
}
