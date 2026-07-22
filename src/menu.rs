use std::{
    io::{self, Write},
    time::Duration,
};

use anyhow::{Context, Result};
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};

use crate::{
    chain_proxy::{self, ChainNode, ChainProxyChange},
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
    (6, "VLESS-TLS-Vision"),
    (7, "VLESS-WS-TLS"),
    (8, "Trojan-TLS"),
    (9, "Trojan-REALITY"),
    (10, "VMess-WS-TLS"),
    (0, "返回"),
];

const OPERATIONS_MENU_ITEMS: [&str; 9] = [
    "链式代理",
    "高级添加配置",
    "查看日志",
    "端口检查",
    "开启 BBR",
    "备份配置",
    "恢复配置",
    "导出客户端配置",
    "更新 ping-rust",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MenuControl {
    Continue,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortChoice {
    Back,
    Random,
    Fixed(u16),
}

fn control_after_success(main_menu_choice: usize) -> MenuControl {
    match main_menu_choice {
        1 | 3 => MenuControl::Exit,
        _ => MenuControl::Continue,
    }
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

fn parse_port_choice(value: &str) -> Option<PortChoice> {
    let value = value.trim();
    if value.is_empty() {
        return Some(PortChoice::Random);
    }
    match value.parse::<u16>().ok()? {
        0 => Some(PortChoice::Back),
        port => Some(PortChoice::Fixed(port)),
    }
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
        .map(config::ManagedProfile::config_file_name)
        .collect::<Vec<_>>();
    select_numbered("请选择配置", &labels)
}

pub async fn run() -> Result<()> {
    cli::bootstrap_default_reality().await?;
    config::ensure_profile_files().await?;
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
        let control = match selected {
            0 => {
                println!("{}", "已退出。".green());
                return Ok(());
            }
            1 => fast_add_config_menu().await,
            2 => {
                change_config_menu().await?;
                Ok(MenuControl::Continue)
            }
            3 => view_config_menu(),
            4 => {
                delete_config_menu().await?;
                Ok(MenuControl::Continue)
            }
            5 => {
                service_menu()?;
                Ok(MenuControl::Continue)
            }
            6 => {
                update_menu().await?;
                Ok(MenuControl::Continue)
            }
            7 => {
                uninstall_menu()?;
                Ok(MenuControl::Continue)
            }
            8 => {
                println!("常用命令：prs add reality、prs add ss、prs info、prs url、prs qr");
                println!("高级帮助：ping-rust --help");
                Ok(MenuControl::Continue)
            }
            9 => {
                operations_menu().await?;
                Ok(MenuControl::Continue)
            }
            10 => {
                println!("ping-rust {}", env!("CARGO_PKG_VERSION"));
                println!("Rust 实现的 shoes 菜单式安装与管理工具");
                println!("https://github.com/Jyanbai/ping-rust");
                Ok(MenuControl::Continue)
            }
            _ => anyhow::bail!("菜单返回了无效选项"),
        }?;
        if control == MenuControl::Exit {
            return Ok(());
        }
    }
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
        Protocol::VlessTlsVision
        | Protocol::VlessWsTls
        | Protocol::TrojanTls
        | Protocol::TrojanReality
        | Protocol::VmessWsTls => {}
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
        result.profile.config_file_name()
    );
    if let Some(server) = result.profile.server_address.as_deref() {
        match client::share_uri(&result.profile, server) {
            Ok(uri) => println!("\n{uri}\n"),
            Err(error) => eprintln!("分享链接生成失败：{error:#}"),
        }
    }
    Ok(())
}

fn view_config_menu() -> Result<MenuControl> {
    let state = config::load_state()?;
    if state.profiles.is_empty() {
        println!("没有配置。");
        return Ok(MenuControl::Continue);
    }
    let Some(selected) = select_profile(&state.profiles)? else {
        return Ok(MenuControl::Continue);
    };
    let profile = &state.profiles[selected];
    let share_uri = profile
        .server_address
        .as_deref()
        .map(|server| client::share_uri(profile, server))
        .transpose()?;
    cli::print_profile_details(profile, share_uri.as_deref());
    Ok(control_after_success(3))
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
        .with_prompt(format!("确认删除 {}？", profile.config_file_name()))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    let deleted = deployment::delete_and_activate(profile.id).await?;
    println!("{} {}", "已删除：".green(), deleted.config_file_name());
    Ok(())
}

async fn operations_menu() -> Result<()> {
    let Some(selected) = select_numbered("运维工具", &OPERATIONS_MENU_ITEMS)? else {
        return Ok(());
    };
    match selected {
        0 => chain_proxy_menu().await,
        1 => advanced_add_config_menu().await,
        2 => service::logs(100),
        3 => {
            let port = Input::<u16>::with_theme(&ColorfulTheme::default())
                .with_prompt("检查端口")
                .default(443)
                .interact_text()?;
            cli::print_port_status(port, operations::check_port(port, true, true));
            Ok(())
        }
        4 => {
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
        5 => {
            let path = operations::backup(None)?;
            println!("备份已创建：{}", path.display());
            println!("备份含私钥和密码，请安全保管。");
            Ok(())
        }
        6 => {
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
        7 => export_menu(),
        8 => cli::run_self_update(None, false).await,
        _ => unreachable!("运维菜单编号已验证"),
    }
}

async fn chain_proxy_menu() -> Result<()> {
    loop {
        let state = config::load_state()?;
        println!("\n------------- 链式代理管理 -------------");
        println!(
            "状态：{}",
            if state.chain_proxy.enabled {
                "● 已启用"
            } else {
                "○ 未启用"
            }
        );
        match state.chain_proxy.active() {
            Some(node) => println!(
                "当前出口：{} | {} | {}",
                node.name,
                node.protocol_name(),
                node.address()
            ),
            None => println!("当前出口：未选择"),
        }
        println!("节点数量：{}\n", state.chain_proxy.nodes.len());
        let action = if state.chain_proxy.enabled {
            "关闭链式代理"
        } else {
            "启用链式代理"
        };
        let items = [
            (1, "添加节点（分享链接）"),
            (2, "选择出口节点"),
            (3, action),
            (4, "测试节点（TCP 连通性）"),
            (5, "查看节点"),
            (6, "删除节点"),
            (0, "返回"),
        ];
        match select_keyed("", &items)? {
            0 => return Ok(()),
            1 => add_chain_node().await?,
            2 => select_chain_exit().await?,
            3 => {
                let enabled = !state.chain_proxy.enabled;
                if enabled
                    && state
                        .chain_proxy
                        .active()
                        .is_some_and(|node| !node.supports_udp_over_tcp())
                    && !Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("当前出口不支持 UDP-over-TCP，UDP 请求将失败；仍要启用？")
                        .default(false)
                        .interact()?
                {
                    continue;
                }
                deployment::update_chain_proxy(ChainProxyChange::SetEnabled(enabled)).await?;
                println!(
                    "{}",
                    if enabled {
                        "链式代理已启用：受支持的 TCP 流量将经当前节点转发。"
                    } else {
                        "链式代理已关闭：所有受管入站已恢复直连。"
                    }
                    .green()
                );
            }
            4 => test_chain_node().await?,
            5 => print_chain_nodes(&state.chain_proxy.nodes, state.chain_proxy.active_node),
            6 => delete_chain_node().await?,
            _ => unreachable!("链式代理菜单编号已验证"),
        }
    }
}

async fn add_chain_node() -> Result<()> {
    println!("支持：SOCKS5、HTTP(S)、Shadowsocks、VLESS（TCP/TLS/Reality/WS）、Trojan（TLS/WS）");
    println!("不支持：Hysteria2、TUIC、WireGuard/WARP、未经验证的分享链接格式");
    let uri = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("粘贴分享链接（输入 0 返回）")
        .interact_text()?;
    if uri.trim() == "0" {
        return Ok(());
    }
    let parsed = chain_proxy::parse_share_uri(&uri)?;
    println!(
        "识别结果：{} | {} | {}",
        parsed.name,
        parsed.protocol_name(),
        parsed.address()
    );
    if !parsed.supports_udp_over_tcp() {
        println!("提示：该节点不支持 UDP-over-TCP；UDP 请求将失败，不会回退直连。");
    }
    let name = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("节点名称")
        .default(parsed.name.clone())
        .interact_text()?;
    let node = parsed.with_name(name)?;
    let state = deployment::update_chain_proxy(ChainProxyChange::Add(node.clone())).await?;
    println!("{} {}", "节点已添加：".green(), node.name);
    if state.chain_proxy.active_node == Some(node.id) {
        println!("该节点已设为当前出口；启用链式代理后生效。");
    }
    Ok(())
}

fn select_chain_node(nodes: &[ChainNode], prompt: &str) -> Result<Option<usize>> {
    let labels = nodes
        .iter()
        .map(|node| {
            format!(
                "{} | {} | {}",
                node.name,
                node.protocol_name(),
                node.address()
            )
        })
        .collect::<Vec<_>>();
    select_numbered(prompt, &labels)
}

async fn select_chain_exit() -> Result<()> {
    let state = config::load_state()?;
    if state.chain_proxy.nodes.is_empty() {
        println!("没有可选择的链式代理节点。");
        return Ok(());
    }
    let Some(index) = select_chain_node(&state.chain_proxy.nodes, "选择出口节点")? else {
        return Ok(());
    };
    let node = &state.chain_proxy.nodes[index];
    if state.chain_proxy.enabled
        && !node.supports_udp_over_tcp()
        && !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("所选出口不支持 UDP-over-TCP，UDP 请求将失败；仍要切换？")
            .default(false)
            .interact()?
    {
        return Ok(());
    }
    deployment::update_chain_proxy(ChainProxyChange::Select(node.id)).await?;
    println!("{} {}", "当前出口已切换为：".green(), node.name);
    Ok(())
}

async fn test_chain_node() -> Result<()> {
    let state = config::load_state()?;
    if state.chain_proxy.nodes.is_empty() {
        println!("没有可测试的链式代理节点。");
        return Ok(());
    }
    let Some(index) = select_chain_node(&state.chain_proxy.nodes, "选择测试节点")? else {
        return Ok(());
    };
    let node = state.chain_proxy.nodes[index].clone();
    let tested = node.clone();
    let elapsed = tokio::task::spawn_blocking(move || {
        chain_proxy::test_tcp_connect(&tested, Duration::from_secs(5))
    })
    .await
    .context("节点测试任务异常退出")??;
    println!(
        "{} {}（TCP 建连 {} ms）",
        "节点端口可达：".green(),
        node.name,
        elapsed.as_millis()
    );
    println!("说明：该测试只验证地址和端口；启用时仍会由 shoes --dry-run 校验完整配置。");
    Ok(())
}

fn print_chain_nodes(nodes: &[ChainNode], active: Option<uuid::Uuid>) {
    if nodes.is_empty() {
        println!("没有链式代理节点。");
        return;
    }
    println!("\n链式代理节点:\n");
    for (index, node) in nodes.iter().enumerate() {
        let marker = if active == Some(node.id) {
            "●"
        } else {
            "○"
        };
        println!(
            "{}) {} {} | {} | {}",
            index + 1,
            marker,
            node.name,
            node.protocol_name(),
            node.address()
        );
    }
}

async fn delete_chain_node() -> Result<()> {
    let state = config::load_state()?;
    if state.chain_proxy.nodes.is_empty() {
        println!("没有可删除的链式代理节点。");
        return Ok(());
    }
    let Some(index) = select_chain_node(&state.chain_proxy.nodes, "选择删除节点")? else {
        return Ok(());
    };
    let node = &state.chain_proxy.nodes[index];
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("确认删除链式节点 {}？", node.name))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    deployment::update_chain_proxy(ChainProxyChange::Delete(node.id)).await?;
    println!("{} {}", "节点已删除：".green(), node.name);
    if state.chain_proxy.active_node == Some(node.id) && state.chain_proxy.enabled {
        println!("被删除节点原为当前出口，链式代理已自动关闭并恢复直连。");
    }
    Ok(())
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

async fn fast_add_config_menu() -> Result<MenuControl> {
    let protocol_number = select_keyed("选择协议", PROTOCOL_MENU_ITEMS)?;
    if protocol_number == 0 {
        return Ok(MenuControl::Continue);
    }
    let protocol = fast_add::protocol_from_menu_number(protocol_number)?;
    let port = loop {
        print!("\n请输入端口（直接回车随机，输入 0 返回）: ");
        io::stdout().flush().context("输出端口提示失败")?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value).context("读取端口失败")? == 0 {
            anyhow::bail!("输入已结束");
        }
        match parse_port_choice(&value) {
            Some(PortChoice::Back) => return Ok(MenuControl::Continue),
            Some(PortChoice::Random) => break None,
            Some(PortChoice::Fixed(port)) => break Some(port),
            None => println!("错误! 请输入 1..=65535 的端口、直接回车随机，或输入 0 返回。"),
        }
    };
    let (shadowsocks_cipher, shadowsocks_password) = if protocol == Protocol::Shadowsocks {
        let Some(cipher) = select_shadowsocks_cipher()? else {
            return Ok(MenuControl::Continue);
        };
        let entered_password = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("请设置密码（留空安全随机生成，输入 0 返回）")
            .allow_empty_password(true)
            .interact()?;
        if entered_password == "0" {
            return Ok(MenuControl::Continue);
        }
        let (password, warning) = prepare_shadowsocks_password(cipher, entered_password);
        if let Some(warning) = warning {
            println!(
                "\n警告! Shadowsocks 协议 ({}) 不支持使用该密码。",
                cipher.as_str()
            );
            println!("原因：{warning}");
            println!("脚本将自动创建可用密码。\n");
        }
        (Some(cipher), Some(password))
    } else {
        (None, None)
    };
    cli::ensure_shoes_for_add(false).await?;
    deploy_fast_config(protocol, port, shadowsocks_cipher, shadowsocks_password).await
}

fn select_shadowsocks_cipher() -> Result<Option<ShadowsocksCipher>> {
    let ciphers = [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20IetfPoly1305,
        ShadowsocksCipher::Aes128Gcm2022,
        ShadowsocksCipher::Aes256Gcm2022,
        ShadowsocksCipher::Chacha20IetfPoly13052022,
    ];
    println!("\n请选择加密方式:\n");
    for (index, cipher) in ciphers.iter().enumerate() {
        println!("{}) {}", index + 1, cipher.as_str());
    }
    println!("0) 返回");
    println!("\n(默认 {}):\n", ShadowsocksCipher::default().as_str());
    loop {
        let value = read_menu_choice(ciphers.len())?;
        let value = value.trim();
        if value.is_empty() {
            return Ok(Some(ShadowsocksCipher::default()));
        }
        if value == "0" {
            return Ok(None);
        }
        if let Ok(selected) = value.parse::<usize>() {
            if let Some(cipher) = ciphers.get(selected.saturating_sub(1)) {
                return Ok(Some(*cipher));
            }
        }
        println!(
            "无效序号；请输入 0 到 {} 之间的数字，或直接回车使用默认值。",
            ciphers.len()
        );
    }
}

fn prepare_shadowsocks_password(
    cipher: ShadowsocksCipher,
    entered_password: String,
) -> (String, Option<String>) {
    if entered_password.is_empty() {
        return (config::generate_shadowsocks_password(cipher), None);
    }
    match config::validate_shadowsocks_password(cipher, &entered_password) {
        Ok(()) => (entered_password, None),
        Err(error) => (
            config::generate_shadowsocks_password(cipher),
            Some(error.to_string()),
        ),
    }
}

async fn deploy_fast_config(
    protocol: Protocol,
    port: Option<u16>,
    shadowsocks_cipher: Option<ShadowsocksCipher>,
    shadowsocks_password: Option<String>,
) -> Result<MenuControl> {
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
        shadowsocks_cipher,
        shadowsocks_password,
    })
    .await?;
    cli::print_add_result(&result);
    Ok(control_after_success(1))
}

async fn advanced_add_config_menu() -> Result<()> {
    let choices = [
        "TUIC v5",
        "Hysteria2",
        "Shadowsocks 2022",
        "VLESS-Reality-Vision（推荐）",
        "AnyTLS",
        "VLESS-TLS-Vision",
        "VLESS-WS-TLS",
        "Trojan-TLS",
        "Trojan-REALITY",
        "VMess-WS-TLS",
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
        5 => Protocol::VlessTlsVision,
        6 => Protocol::VlessWsTls,
        7 => Protocol::TrojanTls,
        8 => Protocol::TrojanReality,
        9 => Protocol::VmessWsTls,
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
            Protocol::VlessTlsVision => "vless-tls-vision".to_owned(),
            Protocol::VlessWsTls => "vless-ws-tls".to_owned(),
            Protocol::TrojanTls => "trojan-tls".to_owned(),
            Protocol::TrojanReality => "trojan-reality".to_owned(),
            Protocol::VmessWsTls => "vmess-ws-tls".to_owned(),
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
    let reality_outer = protocol.uses_reality(options.anytls_mode);
    let server_name = if matches!(protocol, Protocol::Shadowsocks) {
        config::DEFAULT_SNI.to_owned()
    } else {
        let default_server_name = config::resolve_server_name(None, protocol, options.anytls_mode);
        Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt(if reality_outer {
                "Reality SNI"
            } else {
                "证书域名/服务器名称"
            })
            .default(default_server_name)
            .interact_text()?
    };
    let reality_dest = if reality_outer {
        Some(
            Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Reality fallback")
                .default(format!("{server_name}:443"))
                .interact_text()?,
        )
    } else {
        None
    };
    let needs_certificate = protocol.requires_certificate(options.anytls_mode);
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
            (6, Protocol::VlessTlsVision),
            (7, Protocol::VlessWsTls),
            (8, Protocol::TrojanTls),
            (9, Protocol::TrojanReality),
            (10, Protocol::VmessWsTls),
        ] {
            assert!(PROTOCOL_MENU_ITEMS.iter().any(|item| item.0 == number));
            assert_eq!(
                fast_add::protocol_from_menu_number(number).unwrap(),
                protocol
            );
        }
    }

    #[test]
    fn chain_proxy_is_the_first_other_tool() {
        assert_eq!(OPERATIONS_MENU_ITEMS.first(), Some(&"链式代理"));
        assert_eq!(OPERATIONS_MENU_ITEMS.len(), 9);
    }

    #[test]
    fn zero_is_the_only_menu_return_value() {
        assert_eq!(parse_numbered_choice("0", 5), Some(None));
        assert_eq!(parse_numbered_choice("", 5), None);
        assert_eq!(parse_numbered_choice("6", 5), None);
        assert_eq!(parse_keyed_choice("0", MAIN_MENU_ITEMS), Some(0));
        assert_eq!(parse_keyed_choice("0", PROTOCOL_MENU_ITEMS), Some(0));
        assert_eq!(parse_keyed_choice("", MAIN_MENU_ITEMS), None);
        assert_eq!(parse_port_choice("0"), Some(PortChoice::Back));
        assert_eq!(parse_port_choice(""), Some(PortChoice::Random));
        assert_eq!(parse_port_choice("443"), Some(PortChoice::Fixed(443)));
        assert_eq!(parse_port_choice("65536"), None);
    }

    #[test]
    fn add_and_view_success_exit_the_menu() {
        assert_eq!(control_after_success(1), MenuControl::Exit);
        assert_eq!(control_after_success(3), MenuControl::Exit);
        assert_eq!(control_after_success(2), MenuControl::Continue);
        assert_eq!(control_after_success(4), MenuControl::Continue);
    }

    #[test]
    fn single_profile_is_selected_without_showing_a_choice_menu() {
        let profile = config::ManagedProfile {
            id: uuid::Uuid::new_v4(),
            name: "only-profile".to_owned(),
            port: 443,
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

        assert_eq!(select_profile(&[profile]).unwrap(), Some(0));
    }

    #[test]
    fn invalid_shadowsocks_2022_password_is_replaced() {
        let cipher = ShadowsocksCipher::Aes256Gcm2022;
        let invalid = "ordinary-password".to_owned();
        let (password, warning) = prepare_shadowsocks_password(cipher, invalid.clone());
        assert_ne!(password, invalid);
        assert!(warning.is_some());
        config::validate_shadowsocks_password(cipher, &password).unwrap();
    }

    #[test]
    fn valid_shadowsocks_password_is_preserved() {
        let cipher = ShadowsocksCipher::Aes128Gcm2022;
        let valid = config::generate_shadowsocks_password(cipher);
        let (password, warning) = prepare_shadowsocks_password(cipher, valid.clone());
        assert_eq!(password, valid);
        assert!(warning.is_none());

        let legacy = "user-selected-password".to_owned();
        let (password, warning) =
            prepare_shadowsocks_password(ShadowsocksCipher::Aes256Gcm, legacy.clone());
        assert_eq!(password, legacy);
        assert!(warning.is_none());

        let (password, warning) =
            prepare_shadowsocks_password(ShadowsocksCipher::Aes256Gcm2022, String::new());
        assert!(warning.is_none());
        config::validate_shadowsocks_password(ShadowsocksCipher::Aes256Gcm2022, &password).unwrap();
    }

    #[test]
    fn profile_lists_use_real_protocol_and_port_file_names() {
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
        assert_eq!(profile.config_file_name(), "VLESS-REALITY-53453.yaml");
        assert!(!profile.display_name().contains(&profile.id.to_string()));
    }
}
