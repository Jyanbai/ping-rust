use std::io::{self, Write};

use anyhow::{Context, Result};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};

use crate::{
    cli,
    client::{self, ClientFormat},
    config::{
        self, AnyTlsMode, AnyTlsUser, Credentials, GenerationOptions, GenerationRequest,
        ProfileChange, Protocol, ShadowsocksCipher,
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
    (0, "退出"),
];

const PROTOCOL_MENU_ITEMS: &[(usize, &str)] = &[
    (1, "TUIC"),
    (2, "Hysteria2"),
    (3, "Shadowsocks"),
    (4, "VLESS-REALITY（推荐）"),
    (5, "AnyTLS"),
    (0, "返回"),
];

#[derive(Clone, Copy)]
enum ChangeAction {
    Port,
    Name,
    ServerAddress,
    RegenerateCredentials,
    Password,
    RealityServerName,
    ShadowsocksCipher,
    AnyTlsUserPassword,
}

fn parse_numbered_choice(value: &str, count: usize) -> Option<Option<usize>> {
    match value.trim().parse::<usize>().ok()? {
        0 => Some(None),
        selected if (1..=count).contains(&selected) => Some(Some(selected - 1)),
        _ => None,
    }
}

fn parse_keyed_choice(value: &str, items: &[(usize, &str)]) -> Option<usize> {
    let key = value.trim().parse::<usize>().ok()?;
    items
        .iter()
        .any(|(candidate, _)| *candidate == key)
        .then_some(key)
}

fn read_menu_choice(max: usize) -> Result<String> {
    print!("请选择 [0-{max}]: ");
    io::stdout().flush().context("输出菜单提示失败")?;
    let mut value = String::new();
    if io::stdin()
        .read_line(&mut value)
        .context("读取菜单输入失败")?
        == 0
    {
        anyhow::bail!("输入已结束");
    }
    Ok(value)
}

fn select_numbered<T: AsRef<str>>(prompt: &str, items: &[T]) -> Result<Option<usize>> {
    if items.is_empty() {
        anyhow::bail!("菜单没有可选项");
    }
    println!("\n{prompt}:\n");
    for (index, item) in items.iter().enumerate() {
        println!("{}) {}", index + 1, item.as_ref());
    }
    println!("0) 返回\n");
    let count = items.len();
    loop {
        let value = read_menu_choice(count)?;
        if let Some(selected) = parse_numbered_choice(&value, count) {
            return Ok(selected);
        }
        println!("无效序号；请输入 0 到 {count} 之间的数字。");
    }
}

fn select_keyed(prompt: &str, items: &[(usize, &str)]) -> Result<usize> {
    if !prompt.is_empty() {
        println!("\n{prompt}:\n");
    }
    for (key, label) in items {
        println!("{key}) {label}");
    }
    println!();
    let max = items.iter().map(|(key, _)| *key).max().unwrap_or(0);
    loop {
        let value = read_menu_choice(max)?;
        if let Some(key) = parse_keyed_choice(&value, items) {
            return Ok(key);
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

fn select_profile(profiles: &[config::ManagedProfile]) -> Result<Option<usize>> {
    if profiles.len() == 1 {
        return Ok(Some(0));
    }
    let labels = profiles
        .iter()
        .map(config::ManagedProfile::display_name)
        .collect::<Vec<_>>();
    select_numbered("请选择配置", &labels)
}

pub async fn run() -> Result<()> {
    cli::bootstrap_default_reality().await?;
    loop {
        println!(
            "\n------------- ping-rust v{} -------------",
            env!("CARGO_PKG_VERSION")
        );
        let shoes_status = if service::is_active().unwrap_or(false) {
            "running"
        } else if std::path::Path::new(crate::utils::SHOES_BIN).is_file() {
            "stopped"
        } else {
            "not installed"
        };
        println!("shoes: {shoes_status}");
        println!("项目: https://github.com/Jyanbai/ping-rust\n");
        let selected = select_keyed("", MAIN_MENU_ITEMS)?;
        let result = match selected {
            0 => break,
            1 => fast_add_config_menu().await,
            2 => change_config_menu().await,
            3 => view_config_menu(),
            4 => delete_config_menu().await,
            5 => service_menu(),
            6 => update_menu().await,
            7 => uninstall_menu(),
            8 => {
                println!("常用命令：prs add reality、prs add ss、prs info、prs url、prs qr");
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
        };
        result?;
    }
    println!("{}", "已退出。".green());
    Ok(())
}

async fn change_config_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有可更改的配置。");
        return Ok(());
    }
    let Some(selected) = select_profile(&state.profiles)? else {
        return Ok(());
    };
    let profile = state.profiles[selected].clone();
    let mut actions = vec![
        (ChangeAction::Port, "更改端口"),
        (ChangeAction::Name, "更改配置名称"),
        (ChangeAction::ServerAddress, "更改客户端公网地址"),
        (ChangeAction::RegenerateCredentials, "重新生成全部协议凭据"),
    ];
    match profile.protocol() {
        Protocol::Reality => actions.push((ChangeAction::RealityServerName, "更改 SNI")),
        Protocol::Hysteria2 | Protocol::Tuic => {
            actions.push((ChangeAction::Password, "更改密码"));
        }
        Protocol::Shadowsocks => {
            actions.push((ChangeAction::Password, "更改密码"));
            actions.push((ChangeAction::ShadowsocksCipher, "更改加密方式"));
        }
        Protocol::AnyTls => {
            actions.push((ChangeAction::AnyTlsUserPassword, "更改用户密码"));
        }
    }
    let action_labels = actions.iter().map(|(_, label)| *label).collect::<Vec<_>>();
    let Some(action_index) = select_numbered("选择更改项目", &action_labels)? else {
        return Ok(());
    };
    let action = actions[action_index].0;
    let change = match action {
        ChangeAction::Port => {
            let value = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("输入新端口（直接回车自动选择随机端口）")
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
            let requested = if value.trim().is_empty() {
                None
            } else {
                Some(value.trim().parse::<u16>()?)
            };
            let port = fast_add::select_port_for_update(
                profile.protocol(),
                requested,
                profile.id,
                profile.port,
            )?;
            ProfileChange::Port(port)
        }
        ChangeAction::Name => {
            let name = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("新配置名称")
                .default(profile.name.clone())
                .interact_text()?;
            ProfileChange::Name(name)
        }
        ChangeAction::ServerAddress => {
            let value = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("VPS 公网域名或 IP（留空自动检测）")
                .allow_empty(true)
                .interact_text()?;
            let address = if value.trim().is_empty() {
                fast_add::resolve_server_address(None).await?
            } else {
                client::normalize_server_address(&value)?
            };
            ProfileChange::ServerAddress(Some(address))
        }
        ChangeAction::RegenerateCredentials => {
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("确认重新生成凭据？旧分享链接将立即失效")
                .default(false)
                .interact()?
            {
                return Ok(());
            }
            ProfileChange::RegenerateCredentials
        }
        ChangeAction::Password => {
            let password = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("新密码（留空安全随机生成）")
                .allow_empty_password(true)
                .interact()?;
            if password.is_empty() {
                if matches!(profile.protocol(), Protocol::Shadowsocks) {
                    ProfileChange::RegenerateCredentials
                } else {
                    ProfileChange::Password(config::generated_password())
                }
            } else {
                ProfileChange::Password(password)
            }
        }
        ChangeAction::RealityServerName => {
            let server_name = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("新 SNI")
                .default(profile.server_name().to_owned())
                .interact_text()?;
            ProfileChange::RealityServerName(server_name)
        }
        ChangeAction::ShadowsocksCipher => {
            let ciphers = [
                ShadowsocksCipher::Aes256Gcm2022,
                ShadowsocksCipher::Aes128Gcm2022,
                ShadowsocksCipher::Chacha20IetfPoly13052022,
                ShadowsocksCipher::Aes256Gcm,
                ShadowsocksCipher::Aes128Gcm,
                ShadowsocksCipher::Chacha20IetfPoly1305,
            ];
            let labels = ciphers
                .iter()
                .map(|cipher| cipher.as_str())
                .collect::<Vec<_>>();
            let Some(selected) = select_numbered("选择新加密方式", &labels)? else {
                return Ok(());
            };
            ProfileChange::ShadowsocksCipher(ciphers[selected])
        }
        ChangeAction::AnyTlsUserPassword => {
            let Credentials::AnyTls { users, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let user_labels = users
                .iter()
                .enumerate()
                .map(|(index, user)| {
                    if user.name.is_empty() {
                        format!("用户 {}", index + 1)
                    } else {
                        user.name.clone()
                    }
                })
                .collect::<Vec<_>>();
            let Some(index) = select_numbered("选择 AnyTLS 用户", &user_labels)? else {
                return Ok(());
            };
            let password = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("新密码（留空安全随机生成）")
                .allow_empty_password(true)
                .interact()?;
            let password = if password.is_empty() {
                config::generated_password()
            } else {
                password
            };
            ProfileChange::AnyTlsUserPassword { index, password }
        }
    };

    let result = deployment::update_and_activate(profile.id, change).await?;
    println!(
        "{} {}",
        "配置更改成功：".green(),
        result.profile.display_name()
    );
    if let Some(server) = result.profile.server_address.as_deref() {
        match client::share_uri(&result.profile, server) {
            Ok(uri) => println!("\n{uri}\n"),
            Err(error) => eprintln!("分享链接生成失败：{error:#}"),
        }
    }
    Ok(())
}

fn view_config_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有配置。");
        return Ok(());
    }
    let Some(selected) = select_profile(&state.profiles)? else {
        return Ok(());
    };
    let profile = &state.profiles[selected];
    println!("\n------------- 配置信息 -------------\n");
    println!("名称: {}", profile.display_name());
    println!("协议: {}", profile.protocol_name());
    println!("端口: {}", profile.port);
    if profile.server_name() != "-" {
        println!("SNI: {}", profile.server_name());
    }
    if let Some(server) = profile.server_address.as_deref() {
        println!("地址: {server}");
        match client::share_uri(profile, server) {
            Ok(uri) => println!("\n{uri}\n"),
            Err(error) => println!("\n分享链接生成失败: {error}\n"),
        }
    }
    Ok(())
}

async fn delete_config_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有可删除的配置。");
        return Ok(());
    }
    let Some(selected) = select_profile(&state.profiles)? else {
        return Ok(());
    };
    let profile = &state.profiles[selected];
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("确认删除 {}？", profile.display_name()))
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
    println!("{} {}", "已删除：".green(), deleted.display_name());
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
    ];
    let Some(selected) = select_numbered("运维工具", &choices)? else {
        return Ok(());
    };
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
        _ => unreachable!("运维菜单编号已验证"),
    }
}

fn export_menu() -> Result<()> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有可导出的配置。");
        return Ok(());
    }
    let Some(selected) = select_profile(&state.profiles)? else {
        return Ok(());
    };
    let formats = ["Clash Meta", "sing-box", "Nekobox 分享链接"];
    let Some(format_index) = select_numbered("客户端格式", &formats)? else {
        return Ok(());
    };
    let format = match format_index {
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
    let protocol_number = select_keyed("选择协议", PROTOCOL_MENU_ITEMS)?;
    if protocol_number == 0 {
        return Ok(());
    }
    cli::ensure_shoes_for_add(false).await?;
    let protocol = fast_add::protocol_from_menu_number(protocol_number)?;
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
    deploy_fast_config(protocol, port).await
}

async fn deploy_fast_config(protocol: Protocol, port: Option<u16>) -> Result<()> {
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
        "TUIC v5",
        "Hysteria2",
        "Shadowsocks 2022",
        "VLESS-Reality-Vision（推荐）",
        "AnyTLS",
    ];
    let Some(selected) = select_numbered("选择协议", &choices)? else {
        return Ok(());
    };
    let protocol = match selected {
        0 => Protocol::Tuic,
        1 => Protocol::Hysteria2,
        2 => Protocol::Shadowsocks,
        3 => Protocol::Reality,
        4 => Protocol::AnyTls,
        _ => unreachable!("协议菜单编号已验证"),
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
        let Some(cipher) = select_numbered("选择加密方式", &ciphers)? else {
            return Ok(());
        };
        options.shadowsocks_cipher = match cipher {
            0 => ShadowsocksCipher::Aes256Gcm2022,
            1 => ShadowsocksCipher::Aes128Gcm2022,
            2 => ShadowsocksCipher::Chacha20IetfPoly13052022,
            3 => ShadowsocksCipher::Aes256Gcm,
            4 => ShadowsocksCipher::Aes128Gcm,
            _ => ShadowsocksCipher::Chacha20IetfPoly1305,
        };
    }
    if matches!(protocol, Protocol::AnyTls) {
        let Some(mode) =
            select_numbered("AnyTLS 外层安全模式", &["TLS（推荐）", "Reality（高级）"])?
        else {
            return Ok(());
        };
        options.anytls_mode = match mode {
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
            let password = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("AnyTLS 密码（留空则安全随机生成）")
                .allow_empty_password(true)
                .interact()?;
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
    let choices = ["GitHub Release（推荐）", "cargo 固定源码编译 shoes"];
    let Some(selected) = select_numbered("选择更新方式", &choices)? else {
        return Ok(());
    };
    let method = match selected {
        0 => InstallMethod::Release,
        1 => InstallMethod::Cargo,
        _ => unreachable!("更新菜单编号已验证"),
    };
    let report = cli::update_shoes(method).await?;
    println!("{} {}", "更新成功：".green(), report.version);
    Ok(())
}

fn service_menu() -> Result<()> {
    let choices = ["启动", "停止", "重启", "状态", "启用并启动", "禁用"];
    let Some(selected) = select_numbered("服务管理", &choices)? else {
        return Ok(());
    };
    let action = match selected {
        0 => ServiceAction::Start,
        1 => ServiceAction::Stop,
        2 => ServiceAction::Restart,
        3 => ServiceAction::Status,
        4 => ServiceAction::Enable,
        5 => ServiceAction::Disable,
        _ => unreachable!("服务菜单编号已验证"),
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
    crate::utils::require_linux_root()?;
    let _lock = crate::utils::exclusive_lock(std::path::Path::new(crate::utils::LOCK_FILE))?;
    let unit_removed = service::uninstall_unit()?;
    let binary_removed = installer::uninstall_binary()?;
    let aliases_removed = crate::utils::remove_command_aliases()?;
    if purge && std::path::Path::new(crate::utils::CONFIG_DIR).exists() {
        std::fs::remove_dir_all(crate::utils::CONFIG_DIR)?;
    }
    println!(
        "卸载完成：二进制={}，systemd={}，快捷命令清理={}，配置清理={}",
        binary_removed, unit_removed, aliases_removed, purge
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_zero_for_exit_and_sequential_protocol_numbers() {
        assert_eq!(MAIN_MENU_ITEMS.first().unwrap().0, 1);
        assert_eq!(MAIN_MENU_ITEMS.last(), Some(&(0, "退出")));
        assert_eq!(PROTOCOL_MENU_ITEMS.last(), Some(&(0, "返回")));
        for (number, protocol) in [
            (1, Protocol::Tuic),
            (2, Protocol::Hysteria2),
            (3, Protocol::Shadowsocks),
            (4, Protocol::Reality),
            (5, Protocol::AnyTls),
        ] {
            assert!(PROTOCOL_MENU_ITEMS.iter().any(|item| item.0 == number));
            assert_eq!(
                fast_add::protocol_from_menu_number(number).unwrap(),
                protocol
            );
        }
    }

    #[test]
    fn zero_is_the_only_menu_return_value() {
        assert_eq!(parse_numbered_choice("0", 5), Some(None));
        assert_eq!(parse_numbered_choice("", 5), None);
        assert_eq!(parse_numbered_choice("6", 5), None);
        assert_eq!(parse_keyed_choice("0", MAIN_MENU_ITEMS), Some(0));
        assert_eq!(parse_keyed_choice("0", PROTOCOL_MENU_ITEMS), Some(0));
        assert_eq!(parse_keyed_choice("", MAIN_MENU_ITEMS), None);
    }

    #[test]
    fn profile_lists_use_short_protocol_and_port_labels() {
        let profile = config::ManagedProfile {
            id: uuid::Uuid::new_v4(),
            name: "reality-abcd1234".to_owned(),
            port: 53453,
            server_address: None,
            credentials: Credentials::Reality {
                user_id: uuid::Uuid::new_v4(),
                private_key: "private".to_owned(),
                public_key: "public".to_owned(),
                short_id: "0123456789abcdef".to_owned(),
                server_name: config::DEFAULT_SNI.to_owned(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
        };
        assert_eq!(profile.display_name(), "VLESS-REALITY-53453");
        assert!(!profile.display_name().contains(&profile.id.to_string()));
    }
}
