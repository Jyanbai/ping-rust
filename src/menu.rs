use std::{io, time::Duration};

use anyhow::{bail, Context, Result};
use colored::Colorize;
use input::MenuEof;

use crate::{
    chain_proxy::{self, ChainNode, ChainProxyChange},
    cli,
    client::{self, ClientFormat},
    config::{
        self, AnyTlsMode, AnyTlsSecurity, AnyTlsUser, Credentials, GenerationOptions,
        GenerationRequest, ProfileChange, Protocol, ShadowsocksCipher, SnellCipher,
    },
    deployment, fast_add,
    h2mux::H2MuxOptions,
    installer::{self, InstallMethod},
    operations,
    service::{self, ServiceAction},
};

mod chain;
pub(crate) mod input;

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

const UPDATE_CENTER_ITEMS: [&str; 3] =
    ["更新 ping-rust（推荐）", "更新 shoes 内核", "检查更新状态"];

const SHOES_UPDATE_ITEMS: [&str; 2] = [
    "安装 ping-rust 已验证版本（推荐）",
    "安装 shoes 最新 GitHub Release（高级）",
];

#[derive(Clone, Copy)]
enum ChangeAction {
    VlessEncMode,
    VlessEncAuth,
    VlessEncVision,
    H2Mux,
    Port,
    Name,
    ServerAddress,
    RegenerateCredentials,
    Password,
    RealityServerName,
    RecommendSni,
    ShadowsocksCipher,
    ShadowTlsPassword,
    ShadowTlsServerName,
    ShadowTlsHandshake,
    SnellCipher,
    Socks5Username,
    Socks5Authentication,
    UdpEnabled,
    AnyTlsUserPassword,
    NaiveUsername,
    NaivePadding,
    NaiveFallback,
    NaiveCertificate,
    NaiveServerName,
    RegenerateNaiveCertificate,
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

fn control_after_error(error: &anyhow::Error) -> MenuControl {
    if error.chain().any(|cause| {
        cause.is::<MenuEof>()
            || cause
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof)
    }) {
        MenuControl::Exit
    } else {
        MenuControl::Continue
    }
}

fn parse_port_change(input: &str) -> Option<PortChoice> {
    match input.trim() {
        "" | "0" => Some(PortChoice::Back),
        "r" | "R" => Some(PortChoice::Random),
        value => parse_port_choice(value),
    }
}

fn parse_shadowsocks_mode(input: &str) -> Option<Option<config::ShadowsocksMode>> {
    match input.trim() {
        "" | "1" => Some(Some(config::ShadowsocksMode::Plain)),
        "2" => Some(Some(config::ShadowsocksMode::ShadowTlsV3)),
        "0" => Some(None),
        _ => None,
    }
}

fn control_after_success(main_menu_choice: usize) -> MenuControl {
    match main_menu_choice {
        1 | 3 => MenuControl::Exit,
        _ => MenuControl::Continue,
    }
}

fn protocol_menu_items() -> Vec<(usize, &'static str)> {
    Protocol::all()
        .map(|protocol| (protocol.menu_number(), protocol.menu_label()))
        .chain(std::iter::once((0, "返回")))
        .collect()
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
    input::read_menu_choice(&mut io::stdin().lock(), &mut io::stdout(), max)
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

pub(crate) fn select_keyed(prompt: &str, items: &[(usize, &str)]) -> Result<usize> {
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

pub(crate) async fn bootstrap_address<F, Fut>(
    detect: F,
    terminal: bool,
    prompt: impl FnOnce() -> Result<String>,
) -> Result<Option<String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    match detect().await {
        Ok(address) => Ok(Some(address)),
        Err(error) if !terminal => {
            Err(error.context("请运行 prs add reality --server-address <IP或域名>"))
        }
        Err(error) => {
            eprintln!("自动检测公网地址失败：{error:#}");
            let entered = prompt()?;
            if entered.trim().is_empty() {
                Ok(None)
            } else {
                client::normalize_server_address(&entered).map(Some)
            }
        }
    }
}

pub async fn run() -> Result<()> {
    match cli::bootstrap_default_reality_for_menu().await {
        Err(error) if input::is_back(&error) => {}
        Err(error) if control_after_error(&error) == MenuControl::Exit => return Ok(()),
        result => {
            result?;
        }
    }
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
        let selected = match select_keyed("", MAIN_MENU_ITEMS) {
            Err(error) if control_after_error(&error) == MenuControl::Exit => return Ok(()),
            result => result?,
        };
        let result = async {
            match selected {
                0 => {
                    println!("{}", "已退出。".green());
                    Ok(MenuControl::Exit)
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
                6 => update_menu().await,
                7 => {
                    uninstall_menu()?;
                    Ok(MenuControl::Continue)
                }
                8 => {
                    println!("常用命令：prs add reality、prs add ss、prs info、prs url、prs qr");
                    println!("高级帮助：ping-rust --help");
                    Ok(MenuControl::Continue)
                }
                9 => operations_menu().await,
                10 => {
                    println!("ping-rust {}", env!("CARGO_PKG_VERSION"));
                    println!("Rust 实现的 shoes 菜单式安装与管理工具");
                    println!("https://github.com/Jyanbai/ping-rust");
                    Ok(MenuControl::Continue)
                }
                _ => anyhow::bail!("菜单返回了无效选项"),
            }
        }
        .await;
        let control = match result {
            Ok(control) => control,
            Err(error) => {
                if crate::is_interrupted(&error) {
                    crate::restore_cursor_and_exit();
                }
                let control = control_after_error(&error);
                if control == MenuControl::Continue && !input::is_back(&error) {
                    eprintln!("{}", format!("错误：{error:#}").red());
                }
                control
            }
        };
        if control == MenuControl::Exit {
            return Ok(());
        }
    }
}

async fn prompt_probed_sni(label: &str, mode: crate::sni::Mode) -> Result<String> {
    loop {
        println!("\n{label}\n1) 自动选择（默认）\n2) 检测与推荐\n3) 手动输入\n0) 返回");
        let choice =
            input::validated_text("选择 SNI 方式", Some("1"), false, |value| match value {
                "1" | "2" | "3" => Ok(value.to_owned()),
                _ => bail!("请输入 1、2 或 3"),
            })?;
        match choice.as_str() {
            "1" => return crate::sni_probe::resolve(None, true).await,
            "2" => match recommend_sni(mode).await {
                Ok(Some(domain)) => return Ok(domain),
                Ok(None) => continue,
                Err(error) if input::is_back(&error) => continue,
                Err(error) => return Err(error),
            },
            _ => {
                let domain = input::checked_text(label, None, false, config::validate_server_name)?;
                return crate::sni_probe::resolve(Some(domain), true).await;
            }
        }
    }
}

async fn recommend_sni(mode: crate::sni::Mode) -> Result<Option<String>> {
    use crate::sni;
    loop {
        let Some(source) = select_numbered(
            "检测与推荐 SNI：选择候选来源",
            &[
                "默认名单",
                "现有节点的 SNI",
                "输入域名（空格分隔）",
                "在自己电脑上扫描并导入 CSV（推荐）",
                "在 VPS 上扫描（需确认风险）",
            ],
        )?
        else {
            return Ok(None);
        };
        let candidates = match source {
            0 | 1 => sni::defaults(Some(mode))?
                .into_iter()
                .filter(|c| (c.source == "默认名单") == (source == 0))
                .collect(),
            2 => input::validated_text("输入 SNI 域名，空格分隔", None, false, |value| {
                sni::manual(value, mode)
            })?,
            3 => {
                match sni::local_scanner_command().await {
                    Ok(command) => println!("在自己电脑上运行（需先安装 RealiTLScanner v0.2.3）：\n{command}"),
                    Err(error) => println!("{error:#}\n在自己电脑上运行（将占位符换成 VPS IPv4）：\nRealiTLScanner -addr <VPS 的 IPv4>/24 -port 443 -thread 5 -timeout 5 -out out.csv"),
                }
                println!("上传 out.csv 到 VPS 后输入路径。该 XTLS 项目采用 MPL-2.0 许可。导入不在 VPS 上运行扫描器。");
                let path = input::file_path("CSV 文件路径")?;
                let subnet = input::validated_text(
                    "CSV 实际扫描的 IPv4/24 网段",
                    None,
                    false,
                    str::parse::<sni::Subnet>,
                )?;
                sni::import(std::path::Path::new(&path), subnet, mode)?
            }
            _ => sni::scan(false, mode).await?,
        };
        let reports = sni::check(candidates).await;
        sni::print_reports(&reports);
        if reports.is_empty() {
            println!("没有候选，请选择其他来源。");
            continue;
        }
        println!("输入通过条目的编号选择 SNI，输入 0 返回上一步。");
        loop {
            let choice = read_menu_choice(reports.len())?;
            match parse_numbered_choice(&choice, reports.len()) {
                Some(Some(index)) => match sni::selected(&reports, index) {
                    Ok(domain) => return Ok(Some(domain)),
                    Err(error) => println!("{error}"),
                },
                Some(None) => break,
                None => println!("无效编号，请重新输入。"),
            }
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
    loop {
        match change_profile_menu(&profile).await {
            Err(error) if input::is_back(&error) => continue,
            result => return result,
        }
    }
}

async fn change_profile_menu(profile: &config::ManagedProfile) -> Result<()> {
    let mut actions = vec![
        (ChangeAction::Port, "更改端口"),
        (ChangeAction::Name, "更改配置名称"),
        (ChangeAction::ServerAddress, "更改客户端公网地址"),
        (ChangeAction::RegenerateCredentials, "重新生成全部协议凭据"),
    ];
    match profile.protocol() {
        Protocol::VlessEnc => {
            actions[3] = (
                ChangeAction::RegenerateCredentials,
                "重新生成 VLESS Encryption 密钥",
            );
            actions.push((
                ChangeAction::VlessEncMode,
                "更改 VLESS Encryption 外观（重新生成密钥）",
            ));
            actions.push((
                ChangeAction::VlessEncAuth,
                "更改 VLESS Encryption 认证（重新生成密钥）",
            ));
            actions.push((ChangeAction::VlessEncVision, "开启或关闭 Vision"));
        }
        Protocol::Reality | Protocol::TrojanReality => {
            actions.push((ChangeAction::RealityServerName, "更改 SNI"));
            actions.push((ChangeAction::RecommendSni, "检测与推荐 SNI"));
        }
        Protocol::Hysteria2 | Protocol::Tuic => {
            actions.push((ChangeAction::Password, "更改密码"));
        }
        Protocol::Shadowsocks => {
            if matches!(
                profile.credentials,
                Credentials::Shadowsocks {
                    shadowtls: Some(_),
                    ..
                }
            ) {
                actions.push((ChangeAction::Password, "更改 SS2022 密钥"));
                actions.push((ChangeAction::ShadowTlsPassword, "更改 ShadowTLS 密码"));
                actions.push((ChangeAction::ShadowTlsServerName, "更改 ShadowTLS SNI"));
                actions.push((ChangeAction::RecommendSni, "检测与推荐 SNI"));
                actions.push((ChangeAction::ShadowTlsHandshake, "更改握手目标"));
            } else {
                actions.push((ChangeAction::Password, "更改密码"));
            }
            actions.push((ChangeAction::ShadowsocksCipher, "更改加密方式"));
        }
        Protocol::Snell => {
            actions.push((ChangeAction::Password, "更改密码"));
            actions.push((ChangeAction::SnellCipher, "更改加密方式"));
            actions.push((ChangeAction::UdpEnabled, "更改 UDP-over-TCP"));
        }
        Protocol::Socks5 => {
            actions.push((ChangeAction::Socks5Username, "更改用户名"));
            actions.push((ChangeAction::Password, "更改密码"));
            actions.push((ChangeAction::UdpEnabled, "更改 UDP ASSOCIATE"));
            actions.push((ChangeAction::Socks5Authentication, "更改认证模式"));
        }
        Protocol::NaiveProxy => {
            actions.push((ChangeAction::NaiveUsername, "更改 NaiveProxy 用户名"));
            actions.push((ChangeAction::Password, "更改 NaiveProxy 密码"));
            actions.push((ChangeAction::NaiveServerName, "更改 NaiveProxy SNI"));
            actions.push((ChangeAction::NaivePadding, "更改 NaiveProxy padding"));
            actions.push((ChangeAction::UdpEnabled, "更改 NaiveProxy UDP-over-TCP"));
            actions.push((ChangeAction::NaiveFallback, "更改 fallback 路径"));
            actions.push((ChangeAction::NaiveCertificate, "更改 TLS 证书"));
            if profile.self_signed_certificate {
                actions.push((ChangeAction::RegenerateNaiveCertificate, "重新生成测试证书"));
            }
        }
        Protocol::AnyTls => {
            actions.push((ChangeAction::AnyTlsUserPassword, "更改用户密码"));
            if matches!(
                profile.credentials,
                Credentials::AnyTls {
                    security: AnyTlsSecurity::Reality { .. },
                    ..
                }
            ) {
                actions.push((ChangeAction::RealityServerName, "更改 SNI"));
                actions.push((ChangeAction::RecommendSni, "检测与推荐 SNI"));
            }
        }
        Protocol::VlessTlsVision
        | Protocol::VlessWsTls
        | Protocol::TrojanTls
        | Protocol::VmessWsTls => {}
    }
    if profile.h2mux_eligible() {
        actions.push((ChangeAction::H2Mux, "配置 H2MUX 客户端偏好"));
    }
    let action_labels = actions.iter().map(|(_, label)| *label).collect::<Vec<_>>();
    let Some(action_index) = select_numbered("选择更改项目", &action_labels)? else {
        return Ok(());
    };
    let action = actions[action_index].0;
    let change = match action {
        ChangeAction::VlessEncMode => {
            let Some(mode) = prompt_vless_enc_mode()? else {
                return Ok(());
            };
            ProfileChange::VlessEncMode(mode)
        }
        ChangeAction::VlessEncAuth => {
            let Some(auth) = prompt_vless_enc_auth()? else {
                return Ok(());
            };
            ProfileChange::VlessEncAuth(auth)
        }
        ChangeAction::VlessEncVision => {
            let Credentials::VlessEnc { vision, .. } = &profile.credentials else {
                bail!("配置协议不一致");
            };
            ProfileChange::VlessEncVision(input::confirm("开启 Vision？", *vision)?)
        }
        ChangeAction::H2Mux => {
            let Some(options) = prompt_h2mux_options(&profile.h2mux)? else {
                return Ok(());
            };
            ProfileChange::H2Mux(options)
        }
        ChangeAction::Port => {
            let value = input::validated_text(
                "输入新端口（输入 r 随机分配）",
                Some(&profile.port.to_string()),
                false,
                |value| {
                    parse_port_change(value)
                        .map(|_| value.to_owned())
                        .context("请输入 1 到 65535、r 或 0")
                },
            )?;
            let requested = match parse_port_change(&value).expect("端口输入已验证") {
                PortChoice::Back => {
                    println!("端口未更改。");
                    return Ok(());
                }
                PortChoice::Random => None,
                PortChoice::Fixed(port) => Some(port),
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
            let name = input::checked_text("新配置名称", Some(&profile.name), false, |name| {
                config::validate_profile_name(
                    name,
                    &config::load_state()?.profiles,
                    Some(profile.id),
                )
            })?;
            ProfileChange::Name(name)
        }
        ChangeAction::ServerAddress => {
            let value = input::checked_text(
                "VPS 公网域名或 IP（留空自动检测）",
                None,
                true,
                |value| client::normalize_server_address(value).map(|_| ()),
            )?;
            let address = if value.trim().is_empty() {
                fast_add::resolve_server_address(None).await?
            } else {
                client::normalize_server_address(&value)?
            };
            ProfileChange::ServerAddress(Some(address))
        }
        ChangeAction::RegenerateCredentials => {
            if !input::confirm("确认重新生成凭据？旧分享链接将立即失效", false)?
            {
                return Ok(());
            }
            ProfileChange::RegenerateCredentials
        }
        ChangeAction::Password => {
            let password = input::password("新密码（留空安全随机生成）", true)?;
            if matches!(profile.protocol(), Protocol::NaiveProxy) {
                ProfileChange::NaivePassword(if password.is_empty() {
                    config::generated_password()
                } else {
                    password
                })
            } else if password.is_empty() {
                if let Credentials::Shadowsocks { cipher, .. } = profile.credentials {
                    ProfileChange::Password(config::generate_shadowsocks_password(cipher))
                } else if matches!(profile.protocol(), Protocol::Snell) {
                    ProfileChange::RegenerateCredentials
                } else {
                    ProfileChange::Password(config::generated_password())
                }
            } else {
                ProfileChange::Password(password)
            }
        }
        ChangeAction::RecommendSni => {
            let shadowtls = matches!(
                profile.credentials,
                Credentials::Shadowsocks {
                    shadowtls: Some(_),
                    ..
                }
            );
            let mode = if shadowtls {
                crate::sni::Mode::ShadowTls
            } else {
                crate::sni::Mode::Reality
            };
            let Some(domain) = recommend_sni(mode).await? else {
                return Ok(());
            };
            if !input::confirm(
                format!("确认将 SNI 更改为 {domain}？客户端配置也需要同步更新"),
                false,
            )? {
                return Ok(());
            }
            let backup = operations::backup(Some(std::path::PathBuf::from(format!(
                "/var/backups/ping-rust-sni-{}.tar.gz",
                uuid::Uuid::new_v4()
            ))))?;
            println!("配置备份：{}", backup.display());
            if shadowtls {
                ProfileChange::ShadowTlsServerName(domain)
            } else {
                ProfileChange::RealityServerName(domain)
            }
        }
        ChangeAction::RealityServerName => {
            let server_name = input::checked_text(
                "新 SNI",
                Some(profile.server_name()),
                false,
                config::validate_server_name,
            )?;
            crate::sni_probe::check_manual(&server_name).await;
            ProfileChange::RealityServerName(server_name)
        }
        ChangeAction::ShadowsocksCipher => {
            let shadowtls = matches!(
                profile.credentials,
                Credentials::Shadowsocks {
                    shadowtls: Some(_),
                    ..
                }
            );
            let ciphers = if shadowtls {
                vec![
                    ShadowsocksCipher::Aes256Gcm2022,
                    ShadowsocksCipher::Aes128Gcm2022,
                    ShadowsocksCipher::Chacha20IetfPoly13052022,
                ]
            } else {
                vec![
                    ShadowsocksCipher::Aes256Gcm2022,
                    ShadowsocksCipher::Aes128Gcm2022,
                    ShadowsocksCipher::Chacha20IetfPoly13052022,
                    ShadowsocksCipher::Aes256Gcm,
                    ShadowsocksCipher::Aes128Gcm,
                    ShadowsocksCipher::Chacha20IetfPoly1305,
                ]
            };
            let labels = ciphers
                .iter()
                .map(|cipher| cipher.as_str())
                .collect::<Vec<_>>();
            let Some(selected) = select_numbered("选择新加密方式", &labels)? else {
                return Ok(());
            };
            ProfileChange::ShadowsocksCipher(ciphers[selected])
        }
        ChangeAction::ShadowTlsPassword => {
            let password = input::password("ShadowTLS 密码（留空安全随机生成）", true)?;
            ProfileChange::ShadowTlsPassword(if password.is_empty() {
                config::generated_password()
            } else {
                password
            })
        }
        ChangeAction::ShadowTlsServerName => {
            let Credentials::Shadowsocks {
                shadowtls: Some(shadowtls),
                ..
            } = &profile.credentials
            else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let server_name = input::checked_text(
                "ShadowTLS SNI",
                Some(&shadowtls.server_name),
                false,
                config::validate_server_name,
            )?;
            crate::sni_probe::check_manual(&server_name).await;
            ProfileChange::ShadowTlsServerName(server_name)
        }
        ChangeAction::ShadowTlsHandshake => {
            let Credentials::Shadowsocks {
                shadowtls: Some(shadowtls),
                ..
            } = &profile.credentials
            else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let handshake = input::checked_text(
                "Handshake destination（host:port）",
                Some(&shadowtls.handshake_address),
                false,
                config::validate_host_port,
            )?;
            ProfileChange::ShadowTlsHandshake(handshake)
        }
        ChangeAction::SnellCipher => {
            let Some(cipher) = select_snell_cipher("选择新加密方式")? else {
                return Ok(());
            };
            ProfileChange::SnellCipher(cipher)
        }
        ChangeAction::Socks5Username => {
            let Credentials::Socks5 { username, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let Some(current) = username else {
                anyhow::bail!("无认证 SOCKS5 请先切换为用户名密码认证");
            };
            let username = input::text("SOCKS5 用户名", Some(current), false)?;
            ProfileChange::Socks5Username(username)
        }
        ChangeAction::Socks5Authentication => {
            let Credentials::Socks5 { username, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let enabled = input::confirm("启用用户名 + 密码认证？", username.is_some())?;
            if !enabled {
                println!("警告：SOCKS5 无认证且无传输加密，公开到公网可能被第三方滥用。");
            }
            ProfileChange::Socks5Authentication(enabled)
        }
        ChangeAction::UdpEnabled => {
            let (udp_enabled, prompt) = match &profile.credentials {
                Credentials::Socks5 { udp_enabled, .. } => (udp_enabled, "启用 UDP ASSOCIATE？"),
                Credentials::Snell { udp_enabled, .. } => {
                    (udp_enabled, "启用 Snell UDP-over-TCP？")
                }
                Credentials::NaiveProxy { udp_enabled, .. } => {
                    (udp_enabled, "启用 NaiveProxy UDP-over-TCP？")
                }
                _ => anyhow::bail!("配置协议与管理状态不一致"),
            };
            let enabled = input::confirm(prompt, *udp_enabled)?;
            if profile.protocol() == Protocol::NaiveProxy {
                ProfileChange::NaiveUdpEnabled(enabled)
            } else {
                ProfileChange::UdpEnabled(enabled)
            }
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
            let password = input::password("新密码（留空安全随机生成）", true)?;
            let password = if password.is_empty() {
                config::generated_password()
            } else {
                password
            };
            ProfileChange::AnyTlsUserPassword { index, password }
        }
        ChangeAction::NaiveUsername => {
            let Credentials::NaiveProxy { username, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            ProfileChange::NaiveUsername(input::text("NaiveProxy 用户名", Some(username), false)?)
        }
        ChangeAction::RegenerateNaiveCertificate => {
            return cli::regenerate_test_certificate(profile.id).await;
        }
        ChangeAction::NaiveServerName => ProfileChange::NaiveServerName(input::checked_text(
            "NaiveProxy SNI",
            Some(profile.server_name()),
            false,
            config::validate_server_name,
        )?),
        ChangeAction::NaivePadding => {
            let Credentials::NaiveProxy { padding, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            ProfileChange::NaivePadding(input::confirm("启用 NaiveProxy padding？", *padding)?)
        }
        ChangeAction::NaiveFallback => {
            let Credentials::NaiveProxy { fallback, .. } = &profile.credentials else {
                anyhow::bail!("配置协议与管理状态不一致");
            };
            let value = input::validated_text(
                "静态 fallback 绝对路径（输入 - 关闭）",
                fallback.as_deref(),
                true,
                |value| {
                    if value == "-" {
                        return Ok(String::new());
                    }
                    if !value.is_empty() {
                        config::validate_naive_fallback(value)?;
                    }
                    Ok(value.to_owned())
                },
            )?;
            ProfileChange::NaiveFallback((!value.trim().is_empty()).then_some(value))
        }
        ChangeAction::NaiveCertificate => {
            let cert = input::file_path("PEM 证书路径")?;
            let key = input::file_path("PEM 私钥路径")?;
            ProfileChange::NaiveCertificate {
                certificate: cert.into(),
                key: key.into(),
            }
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
            Ok(uri) if result.profile.protocol() == Protocol::VlessEnc => {
                cli::print_share_uri_with_qr(&uri)
            }
            Ok(uri) => println!("\n{uri}\n"),
            Err(error) => eprintln!("分享链接生成失败：{error:#}"),
        }
    }
    if result.profile.h2mux.enabled {
        println!("提示：分享链接不包含 H2MUX 客户端偏好；请使用 sing-box 导出。shoes 服务端自动识别 H2MUX。");
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
    let (share_uri, share_warning) = share_uri_for_view(profile);
    cli::print_profile_details_with_qr(profile, share_uri.as_deref());
    if let Some(warning) = share_warning {
        println!("未生成标准分享链接：{warning}");
        println!("配置详情仍可查看；请按上方提示选择受支持的客户端导出方式。");
    }
    Ok(control_after_success(3))
}

fn share_uri_for_view(profile: &config::ManagedProfile) -> (Option<String>, Option<String>) {
    let Some(server) = profile.server_address.as_deref() else {
        return (None, None);
    };
    match client::share_uri(profile, server) {
        Ok(uri) => (Some(uri), None),
        Err(error) => (None, Some(format!("{error:#}"))),
    }
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
    if !input::confirm(format!("确认删除 {}？", profile.config_file_name()), false)? {
        return Ok(());
    }
    let deleted = deployment::delete_and_activate(profile.id).await?;
    println!("{} {}", "已删除：".green(), deleted.config_file_name());
    Ok(())
}

async fn operations_menu() -> Result<MenuControl> {
    loop {
        match operations_menu_once().await {
            Err(error) if input::is_back(&error) => continue,
            result => return result,
        }
    }
}

async fn operations_menu_once() -> Result<MenuControl> {
    let Some(selected) = select_numbered("运维工具", &OPERATIONS_MENU_ITEMS)? else {
        return Ok(MenuControl::Continue);
    };
    if selected == 8 {
        return Ok(if cli::run_self_update(None, false).await? {
            MenuControl::Exit
        } else {
            MenuControl::Continue
        });
    }
    match selected {
        0 => chain_proxy_menu().await,
        1 => advanced_add_config_menu().await,
        2 => service::logs(100),
        3 => {
            let port = input::port("检查端口", Some(443))?;
            cli::print_port_status(port, operations::check_port(port, true, true));
            Ok(())
        }
        4 => {
            if input::confirm("写入 sysctl 配置并启用 BBR？", false)? {
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
            let archive = input::file_path("备份文件路径")?;
            if input::confirm("恢复会替换当前配置，继续？", false)? {
                let rollback = operations::restore(std::path::Path::new(&archive)).await?;
                println!("{}", "恢复成功。".green());
                if let Some(path) = rollback {
                    println!("原配置保留于：{}", path.display());
                }
            }
            Ok(())
        }
        7 => export_menu(),
        _ => unreachable!("运维菜单编号已验证"),
    }?;
    Ok(MenuControl::Continue)
}

async fn chain_proxy_menu() -> Result<()> {
    chain::menu().await
}

async fn add_chain_node() -> Result<()> {
    println!("支持：SOCKS5、HTTP(S)、Shadowsocks、VLESS（TCP/TLS/Reality/WS）、Trojan（TLS/WS）");
    println!("不支持：Hysteria2、TUIC、WireGuard/WARP、未经验证的分享链接格式");
    let parsed = input::validated_text("粘贴分享链接", None, false, chain_proxy::parse_share_uri)?;
    println!(
        "识别结果：{} | {} | {}",
        parsed.name,
        parsed.protocol_name(),
        parsed.address()
    );
    if !parsed.supports_udp_over_tcp() {
        println!("提示：该节点不支持 UDP-over-TCP；UDP 请求将失败，不会回退直连。");
    }
    let name = input::checked_text(
        "节点名称",
        Some(&parsed.name),
        false,
        chain_proxy::validate_node_name,
    )?;
    let node = parsed.with_name(name)?;
    deployment::update_chain_proxy(ChainProxyChange::Add(node.clone())).await?;
    println!("{} {}", "节点已添加：".green(), node.name);
    println!("默认路由仍为 DIRECT；可选择出口节点或设置默认路由。");
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
        && !input::confirm(
            "所选出口不支持 UDP-over-TCP，UDP 请求将失败；仍要切换？",
            false,
        )?
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
    println!("正在通过该节点执行协议握手和 HTTP 出口测试...");
    let elapsed = chain_proxy::test_proxy_handshake(&node, Duration::from_secs(10)).await?;
    println!(
        "{} {}（完整代理 {} ms）",
        "节点可用：".green(),
        node.name,
        elapsed.as_millis()
    );
    println!("已验证：地址可达、协议认证成功，并能通过该节点完成 HTTP 请求。");
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
        println!("    H2MUX: {}", h2mux_status(&node.h2mux));
    }
}

fn h2mux_status(options: &H2MuxOptions) -> String {
    if !options.enabled {
        return "off".to_owned();
    }
    format!(
        "on (max_connections={}, min_streams={}, max_streams={}, padding={})",
        options.max_connections, options.min_streams, options.max_streams, options.padding
    )
}

fn prompt_h2mux_options(current: &H2MuxOptions) -> Result<Option<H2MuxOptions>> {
    let Some(action) = select_numbered(
        "H2MUX 客户端偏好",
        &["关闭", "开启：连接数模式", "开启：最大 streams 模式"],
    )?
    else {
        return Ok(None);
    };
    if action == 0 {
        return Ok(Some(H2MuxOptions::default()));
    }
    loop {
        let mut options = H2MuxOptions {
            enabled: true,
            ..H2MuxOptions::default()
        };
        if action == 1 {
            options.max_connections = input::number("Max connections", current.max_connections)?;
            options.min_streams = input::number("Min streams", current.min_streams)?;
        } else {
            options.max_connections = 0;
            options.min_streams = 0;
            options.max_streams = input::number("Max streams", current.max_streams)?;
        }
        options.padding = input::confirm("启用 H2MUX padding？", current.padding)?;
        if let Err(error) = options.validate() {
            println!("错误！{error:#}");
            continue;
        }
        return Ok(Some(options));
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
    if !input::confirm(format!("确认删除链式节点 {}？", node.name), false)? {
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
    let server = input::checked_text("VPS 公网域名或 IP", None, false, |value| {
        client::normalize_server_address(value).map(|_| ())
    })?;
    let content = client::render(&state.profiles[selected], format, &server)?;
    println!("\n{content}\n");
    if state.profiles[selected].h2mux.enabled && matches!(format, ClientFormat::Nekobox) {
        println!("提示：NekoBox 分享链接不包含 H2MUX 客户端偏好；普通节点连接仍可使用。");
    }
    if state.profiles[selected].self_signed_certificate
        && state.profiles[selected].protocol() != Protocol::NaiveProxy
    {
        println!(
            "{}",
            "注意：导出内容为自签名证书启用了 insecure；生产环境建议换用受信任证书。".yellow()
        );
    }
    Ok(())
}

async fn fast_add_config_menu() -> Result<MenuControl> {
    loop {
        match fast_add_config_menu_once().await {
            Err(error) if input::is_back(&error) => continue,
            result => return result,
        }
    }
}

async fn fast_add_config_menu_once() -> Result<MenuControl> {
    let protocol_items = protocol_menu_items();
    let protocol_number = select_keyed("选择协议", &protocol_items)?;
    if protocol_number == 0 {
        return Ok(MenuControl::Continue);
    }
    let protocol = Protocol::from_menu_number(protocol_number)
        .with_context(|| format!("协议编号无效：{protocol_number}"))?;
    let shadowsocks_mode = if protocol == Protocol::Shadowsocks {
        println!("\nShadowsocks 模式:\n\n1) Shadowsocks 2022\n2) Shadowsocks 2022 + ShadowTLS v3（推荐）\n0) 返回\n");
        loop {
            match parse_shadowsocks_mode(&read_menu_choice(2)?) {
                Some(Some(mode)) => break mode,
                Some(None) => return Ok(MenuControl::Continue),
                None => println!("无效序号；请输入 0 到 2 之间的数字。"),
            }
        }
    } else {
        config::ShadowsocksMode::Plain
    };
    let port = input::validated_text(
        "请输入端口（直接回车随机）",
        None,
        true,
        |value| parse_port_choice(value).context("请输入 1 到 65535 的端口"),
    )?;
    let port = match port {
        PortChoice::Back => return Ok(MenuControl::Continue),
        PortChoice::Random => None,
        PortChoice::Fixed(port) => Some(port),
    };
    if protocol == Protocol::NaiveProxy {
        let server_name =
            input::checked_text("请输入域名/SNI", None, false, config::validate_server_name)?;
        let Some(mode) = select_numbered(
            "TLS 证书模式",
            &["已有受信任证书（推荐）", "自签名测试模式（不推荐）"],
        )?
        else {
            return Ok(MenuControl::Continue);
        };
        let (certificate, certificate_key) = if mode == 0 {
            let cert = input::file_path("PEM 证书路径")?;
            let key = input::file_path("PEM 私钥路径")?;
            (Some(cert.into()), Some(key.into()))
        } else {
            println!("警告：自签名证书仅供测试，不推荐用于生产环境。");
            (None, None)
        };
        cli::ensure_shoes_for_add(false).await?;
        let server_address = resolve_menu_server_address().await?;
        let result = fast_add::execute(fast_add::AddRequest {
            interactive: true,
            vless_enc: Default::default(),
            name: None,
            protocol,
            port,
            server_address: Some(server_address),
            server_name: Some(server_name),
            shadowsocks_cipher: None,
            shadowsocks_password: None,
            shadowsocks_mode: config::ShadowsocksMode::Plain,
            shadowtls_password: None,
            shadowtls_handshake: None,
            certificate,
            certificate_key,
            naive_self_signed: mode == 1,
            naive_username: None,
            naive_password: None,
            naive_padding: true,
            naive_fallback: None,
        })
        .await?;
        cli::print_add_result(&result);
        return Ok(control_after_success(1));
    }
    let (shadowsocks_cipher, shadowsocks_password) = if protocol == Protocol::Shadowsocks {
        let Some(cipher) = select_shadowsocks_cipher(shadowsocks_mode)? else {
            return Ok(MenuControl::Continue);
        };
        let entered_password = input::password("请设置密码（留空安全随机生成）", true)?;
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
    deploy_fast_config(
        protocol,
        port,
        shadowsocks_cipher,
        shadowsocks_password,
        shadowsocks_mode,
    )
    .await
}

fn select_shadowsocks_cipher(mode: config::ShadowsocksMode) -> Result<Option<ShadowsocksCipher>> {
    let ciphers = if mode == config::ShadowsocksMode::ShadowTlsV3 {
        vec![
            ShadowsocksCipher::Aes128Gcm2022,
            ShadowsocksCipher::Aes256Gcm2022,
            ShadowsocksCipher::Chacha20IetfPoly13052022,
        ]
    } else {
        vec![
            ShadowsocksCipher::Aes128Gcm,
            ShadowsocksCipher::Aes256Gcm,
            ShadowsocksCipher::Chacha20IetfPoly1305,
            ShadowsocksCipher::Aes128Gcm2022,
            ShadowsocksCipher::Aes256Gcm2022,
            ShadowsocksCipher::Chacha20IetfPoly13052022,
        ]
    };
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

const SNELL_CIPHERS: [SnellCipher; 3] = [
    SnellCipher::Aes128Gcm,
    SnellCipher::Aes256Gcm,
    SnellCipher::Chacha20IetfPoly1305,
];
const SNELL_CIPHER_LABELS: [&str; 3] = [
    "aes-128-gcm（默认，Mihomo 已验证）",
    "高级：aes-256-gcm",
    "高级：chacha20-ietf-poly1305",
];

fn snell_new_node_choice(value: &str) -> Option<Option<SnellCipher>> {
    if value.trim().is_empty() {
        return Some(Some(SnellCipher::default()));
    }
    parse_numbered_choice(value, SNELL_CIPHERS.len())
        .map(|selected| selected.map(|index| SNELL_CIPHERS[index]))
}

fn warn_unverified_snell_cipher(cipher: SnellCipher) {
    if let Some(warning) = cipher.mihomo_warning() {
        println!("{warning}");
    }
}

fn select_snell_cipher(prompt: &str) -> Result<Option<SnellCipher>> {
    let Some(selected) = select_numbered(prompt, &SNELL_CIPHER_LABELS)? else {
        return Ok(None);
    };
    let cipher = SNELL_CIPHERS[selected];
    warn_unverified_snell_cipher(cipher);
    Ok(Some(cipher))
}

fn select_new_snell_cipher() -> Result<Option<SnellCipher>> {
    println!("\n选择 Snell v3 加密方式（回车使用 aes-128-gcm）:\n");
    for (index, label) in SNELL_CIPHER_LABELS.iter().enumerate() {
        println!("{}) {label}", index + 1);
    }
    println!("0) 返回\n");
    loop {
        let value = read_menu_choice(SNELL_CIPHERS.len())?;
        match snell_new_node_choice(&value) {
            Some(Some(cipher)) => {
                warn_unverified_snell_cipher(cipher);
                return Ok(Some(cipher));
            }
            Some(None) => return Ok(None),
            None => println!("无效序号；请输入 0 到 3，或直接回车使用默认值。"),
        }
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

fn prompt_vless_enc_mode() -> Result<Option<config::VlessEncMode>> {
    let Some(index) = select_numbered(
        "VLESS Encryption 外观",
        &[
            "native（默认）",
            "xorpub（混淆公钥）",
            "random（关闭 TCP splice）",
        ],
    )?
    else {
        return Ok(None);
    };
    let mode = [
        config::VlessEncMode::Native,
        config::VlessEncMode::Xorpub,
        config::VlessEncMode::Random,
    ][index];
    if mode == config::VlessEncMode::Random {
        println!("提示：random 会关闭 TCP splice。");
    }
    Ok(Some(mode))
}

fn prompt_vless_enc_auth() -> Result<Option<config::VlessEncAuth>> {
    let Some(index) = select_numbered(
        "VLESS Encryption 认证",
        &[
            "x25519（默认）",
            "mlkem768（链接约 1.6 KB，二维码可能无法扫描）",
        ],
    )?
    else {
        return Ok(None);
    };
    let auth = [config::VlessEncAuth::X25519, config::VlessEncAuth::Mlkem768][index];
    if auth == config::VlessEncAuth::Mlkem768 {
        println!("提示：mlkem768 分享链接约 1.6 KB，二维码可能无法扫描。");
    }
    Ok(Some(auth))
}

fn prompt_vless_enc_options() -> Result<Option<crate::vless_encryption::Options>> {
    prompt_vless_enc_options_with(prompt_vless_enc_mode, prompt_vless_enc_auth, || {
        input::confirm("开启 Vision？", false)
    })
}

fn prompt_vless_enc_options_with(
    mode: impl FnOnce() -> Result<Option<config::VlessEncMode>>,
    auth: impl FnOnce() -> Result<Option<config::VlessEncAuth>>,
    vision: impl FnOnce() -> Result<bool>,
) -> Result<Option<crate::vless_encryption::Options>> {
    let Some(mode) = mode()? else {
        return Ok(None);
    };
    let Some(auth) = auth()? else {
        return Ok(None);
    };
    let vision = vision()?;
    Ok(Some(crate::vless_encryption::Options {
        mode,
        auth,
        vision,
    }))
}

async fn offer_vless_enc_regeneration(profile: &config::ManagedProfile) -> Result<()> {
    if profile.protocol() != Protocol::VlessEnc {
        return Ok(());
    }
    while input::confirm("重新生成密钥？（会使刚才的分享链接失效）", false)? {
        let result =
            deployment::update_and_activate(profile.id, ProfileChange::RegenerateCredentials)
                .await?;
        let uri = client::stored_share_uri(&result.profile, None)?;
        cli::print_profile_details_with_qr(&result.profile, Some(&uri));
    }
    Ok(())
}

async fn deploy_fast_config(
    protocol: Protocol,
    port: Option<u16>,
    shadowsocks_cipher: Option<ShadowsocksCipher>,
    shadowsocks_password: Option<String>,
    shadowsocks_mode: config::ShadowsocksMode,
) -> Result<MenuControl> {
    let vless_enc = if protocol == Protocol::VlessEnc {
        let Some(options) = prompt_vless_enc_options()? else {
            return Ok(MenuControl::Continue);
        };
        options
    } else {
        Default::default()
    };
    let server_name = if protocol.uses_reality(AnyTlsMode::Tls) {
        Some(prompt_probed_sni("Reality SNI", crate::sni::Mode::Reality).await?)
    } else if shadowsocks_mode == config::ShadowsocksMode::ShadowTlsV3 {
        Some(prompt_probed_sni("ShadowTLS SNI", crate::sni::Mode::ShadowTls).await?)
    } else {
        None
    };
    let server_address = resolve_menu_server_address().await?;
    let request = fast_add::AddRequest {
        interactive: true,
        vless_enc,
        name: None,
        protocol,
        port,
        server_address: Some(server_address),
        server_name: None,
        shadowsocks_cipher,
        shadowsocks_password,
        shadowsocks_mode,
        shadowtls_password: None,
        shadowtls_handshake: None,
        certificate: None,
        certificate_key: None,
        naive_self_signed: false,
        naive_username: None,
        naive_password: None,
        naive_padding: true,
        naive_fallback: None,
    };
    let result = if let Some(server_name) = server_name {
        fast_add::execute_with_sni(request, server_name).await?
    } else {
        fast_add::execute(request).await?
    };
    cli::print_add_result(&result);
    offer_vless_enc_regeneration(&result.generation.profile).await?;
    Ok(control_after_success(1))
}

async fn resolve_menu_server_address() -> Result<String> {
    match fast_add::resolve_server_address(None).await {
        Ok(address) => Ok(address),
        Err(error) => {
            eprintln!("自动检测公网地址失败：{error:#}");
            let entered =
                input::checked_text("请输入 VPS 公网域名或 IP", None, false, |value| {
                    client::normalize_server_address(value).map(|_| ())
                })?;
            fast_add::resolve_server_address(Some(&entered)).await
        }
    }
}

async fn advanced_add_config_menu() -> Result<()> {
    let choices = Protocol::all()
        .map(Protocol::advanced_label)
        .collect::<Vec<_>>();
    let Some(selected) = select_numbered("选择协议", &choices)? else {
        return Ok(());
    };
    let protocol =
        Protocol::from_menu_number(selected + 1).context("协议菜单与中央注册表不一致")?;
    let name = input::checked_text("配置名称", Some(protocol.slug()), false, |name| {
        config::validate_profile_name(name, &config::load_state()?.profiles, None)
    })?;
    let port = input::port("监听端口", Some(443))?;
    let mut options = GenerationOptions::default();
    if protocol == Protocol::VlessEnc {
        let Some(selected) = prompt_vless_enc_options()? else {
            return Ok(());
        };
        options.vless_enc_mode = selected.mode;
        options.vless_enc_auth = selected.auth;
        options.vless_enc_vision = selected.vision;
    }
    let mut shadowtls_server_name = None;
    if matches!(protocol, Protocol::Shadowsocks) {
        let Some(mode) = select_numbered(
            "Shadowsocks 模式",
            &["普通 SS2022", "SS2022 + ShadowTLS v3（推荐）"],
        )?
        else {
            return Ok(());
        };
        options.shadowsocks_mode = if mode == 1 {
            config::ShadowsocksMode::ShadowTlsV3
        } else {
            config::ShadowsocksMode::Plain
        };
        let ciphers = if options.shadowsocks_mode == config::ShadowsocksMode::ShadowTlsV3 {
            vec![
                "2022-blake3-aes-256-gcm（推荐）",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-chacha20-ietf-poly1305",
            ]
        } else {
            vec![
                "2022-blake3-aes-256-gcm（推荐）",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-chacha20-ietf-poly1305",
                "aes-256-gcm",
                "aes-128-gcm",
                "chacha20-ietf-poly1305",
            ]
        };
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
        if options.shadowsocks_mode == config::ShadowsocksMode::ShadowTlsV3 {
            let password = input::password("SS2022 密钥（留空则安全生成）", true)?;
            options.shadowsocks_password = (!password.is_empty()).then_some(password);
            let shadow_password = input::password("ShadowTLS 密码（留空则安全生成）", true)?;
            options.shadowtls_password = (!shadow_password.is_empty()).then_some(shadow_password);
            let sni = prompt_probed_sni("ShadowTLS SNI", crate::sni::Mode::ShadowTls).await?;
            shadowtls_server_name = Some(sni.clone());
            let handshake = input::checked_text(
                "Handshake destination（host:port）",
                Some(&(format!("{sni}:443"))),
                false,
                config::validate_host_port,
            )?;
            options.shadowtls_handshake = Some(handshake);
            options.udp_enabled = false;
        }
    }
    if matches!(protocol, Protocol::Snell) {
        let Some(cipher) = select_new_snell_cipher()? else {
            return Ok(());
        };
        options.snell_cipher = cipher;
        let password = input::password("Snell v3 密码（留空则安全随机生成）", true)?;
        options.snell_password = (!password.is_empty()).then_some(password);
        options.udp_enabled = input::confirm("启用 Snell UDP-over-TCP？", true)?;
    }
    if matches!(protocol, Protocol::Socks5) {
        let Some(authentication) =
            select_numbered("认证", &["用户名 + 密码（推荐）", "无认证（不推荐）"])?
        else {
            return Ok(());
        };
        if authentication == 0 {
            let username = input::text("SOCKS5 用户名（留空则安全随机生成）", None, true)?;
            options.socks5_username = (!username.is_empty()).then_some(username);
            let password = input::password("SOCKS5 密码（留空则安全随机生成）", true)?;
            options.socks5_password = (!password.is_empty()).then_some(password);
        } else {
            options.socks5_no_auth = true;
            println!("警告：SOCKS5 无认证且无传输加密，公开到公网可能被第三方滥用。");
        }
        options.udp_enabled = input::confirm("启用 UDP ASSOCIATE？", true)?;
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
            let user_name = input::text("AnyTLS 用户名", Some(&default_name), false)?;
            let password = input::password("AnyTLS 密码（留空则安全随机生成）", true)?;
            options.anytls_users.push(if password.is_empty() {
                config::generated_anytls_user(user_name)
            } else {
                AnyTlsUser {
                    name: user_name,
                    password,
                }
            });
            if !input::confirm("继续添加 AnyTLS 用户？", false)? {
                break;
            }
        }
        if input::confirm("使用推荐 padding_scheme？", true)? {
            options.anytls_padding_scheme = Some(vec![
                "stop=8".to_owned(),
                "0=30-30".to_owned(),
                "1=50-100".to_owned(),
            ]);
        }
        if input::confirm("配置认证失败 fallback？", false)? {
            options.anytls_fallback = Some(input::checked_text(
                "AnyTLS fallback（host:port）",
                Some("127.0.0.1:80"),
                false,
                config::validate_host_port,
            )?);
        }
    }
    if protocol == Protocol::NaiveProxy {
        let username = input::text("NaiveProxy 用户名（留空安全随机生成）", None, true)?;
        options.naive_username = (!username.is_empty()).then_some(username);
        let password = input::password("NaiveProxy 密码（留空安全随机生成）", true)?;
        options.naive_password = (!password.is_empty()).then_some(password);
        options.naive_padding = input::confirm("启用 NaiveProxy padding？", true)?;
        if input::confirm("配置静态 fallback 目录？", false)? {
            options.naive_fallback = Some(input::checked_text(
                "fallback 绝对路径",
                None,
                false,
                config::validate_naive_fallback,
            )?);
        }
    }
    let reality_outer = protocol.uses_reality(options.anytls_mode);
    let server_name = if matches!(protocol, Protocol::Shadowsocks)
        && options.shadowsocks_mode == config::ShadowsocksMode::ShadowTlsV3
    {
        shadowtls_server_name.context("缺少已检测的 ShadowTLS SNI")?
    } else if matches!(
        protocol,
        Protocol::Shadowsocks | Protocol::Snell | Protocol::Socks5 | Protocol::VlessEnc
    ) {
        config::DEFAULT_SNI.to_owned()
    } else if reality_outer {
        prompt_probed_sni("Reality SNI", crate::sni::Mode::Reality).await?
    } else {
        let default_server_name = config::resolve_server_name(None, protocol, options.anytls_mode);
        input::checked_text(
            "证书域名/服务器名称",
            Some(&(default_server_name)),
            false,
            config::validate_server_name,
        )?
    };
    let reality_dest = if reality_outer {
        Some(input::checked_text(
            "Reality fallback",
            Some(&(format!("{server_name}:443"))),
            false,
            config::validate_host_port,
        )?)
    } else {
        None
    };
    let needs_certificate = protocol.requires_certificate(options.anytls_mode);
    let (certificate, certificate_key) = if needs_certificate
        && input::confirm(
            if protocol == Protocol::NaiveProxy {
                "使用已有受信任 PEM 证书和私钥？（推荐）"
            } else {
                "使用已有 PEM 证书和私钥？（否则自动生成自签名证书）"
            },
            protocol == Protocol::NaiveProxy,
        )? {
        let cert = input::file_path("PEM 证书路径")?;
        let key = input::file_path("PEM 私钥路径")?;
        (Some(cert.into()), Some(key.into()))
    } else {
        if protocol == Protocol::NaiveProxy {
            options.naive_self_signed = true;
            println!("警告：NaiveProxy 自签名证书仅供测试，不推荐用于生产环境。");
        }
        (None, None)
    };

    let server_address = resolve_menu_server_address().await?;
    let result = deployment::generate_and_activate(GenerationRequest {
        name: Some(name),
        protocol,
        port,
        output: crate::utils::CONFIG_FILE.into(),
        server_address: Some(server_address.clone()),
        server_name,
        reality_dest,
        certificate,
        certificate_key,
        options,
    })
    .await?;
    cli::print_credentials(&result);
    match client::share_uri(&result.profile, &server_address) {
        Ok(share_uri) => cli::print_share_uri_with_qr(&share_uri),
        Err(error) => {
            println!("\n未生成标准分享链接：{error:#}");
            println!("配置已成功部署；客户端导出请按上方提示处理。");
        }
    }
    println!("{}", "配置验证通过，服务已启动。".green());
    offer_vless_enc_regeneration(&result.profile).await?;
    Ok(())
}

async fn update_menu() -> Result<MenuControl> {
    let Some(selected) = select_numbered("更新中心", &UPDATE_CENTER_ITEMS)? else {
        return Ok(MenuControl::Continue);
    };
    match selected {
        0 => Ok(if cli::run_self_update(None, false).await? {
            MenuControl::Exit
        } else {
            MenuControl::Continue
        }),
        1 => shoes_update_menu().await.map(|_| MenuControl::Continue),
        2 => {
            cli::print_update_status().await?;
            Ok(MenuControl::Continue)
        }
        _ => unreachable!("更新中心编号已验证"),
    }
}

async fn shoes_update_menu() -> Result<()> {
    let Some(selected) = select_numbered("shoes 内核", &SHOES_UPDATE_ITEMS)? else {
        return Ok(());
    };
    let report = match selected {
        0 => cli::update_shoes(InstallMethod::Cargo).await?,
        1 => {
            let target = installer::SHOES_RELEASE_TAG.to_owned();
            let known = installer::load_provenance();
            let needs_override = std::path::Path::new(crate::utils::SHOES_BIN).is_file()
                && !installer::downgrade_allowed(known.version.as_deref(), Some(&target), false);
            let prompt = if needs_override {
                match known.version.as_deref() {
                    Some(current) => format!("GitHub Release {target} 低于当前已知 shoes {current}。明确允许降级？"),
                    None => format!("无法确认当前 shoes 的安装来源（常见于由 v0.1.x 安装的实例）。确认没有手动替换过 shoes 后，允许安装 GitHub Release {target}？安装成功后会记录来源。"),
                }
            } else {
                format!("安装 shoes GitHub Release {target}（高级选项）？")
            };
            if !input::confirm(prompt, false)? {
                return Ok(());
            }
            cli::update_shoes_with_options(InstallMethod::Release, needs_override).await?
        }
        _ => unreachable!("shoes 更新菜单编号已验证"),
    };
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
    cli::execute_service(action)
}

fn uninstall_menu() -> Result<()> {
    if !input::confirm("确认卸载 shoes？默认保留 /etc/shoes 配置", false)? {
        return Ok(());
    }
    let purge = input::confirm("同时永久删除 /etc/shoes 配置与凭据？", false)?;
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
    fn input_errors_and_cancellation_are_classified() {
        assert_eq!(
            control_after_error(&anyhow::Error::new(MenuEof).context("读取")),
            MenuControl::Exit
        );
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert_eq!(
            control_after_error(&anyhow::Error::new(eof)),
            MenuControl::Exit
        );
        assert_eq!(
            control_after_error(&anyhow::anyhow!("失败")),
            MenuControl::Continue
        );
        assert!(prompt_vless_enc_options_with(
            || Ok(None),
            || panic!("cancelled"),
            || panic!("cancelled")
        )
        .unwrap()
        .is_none());
        assert!(prompt_vless_enc_options_with(
            || Ok(Some(config::VlessEncMode::default())),
            || Ok(None),
            || panic!("cancelled")
        )
        .unwrap()
        .is_none());
        assert_eq!(parse_shadowsocks_mode("3"), None);
        assert_eq!(parse_shadowsocks_mode("bad"), None);
        assert_eq!(parse_shadowsocks_mode("0"), Some(None));
        assert_eq!(parse_shadowsocks_mode(""), parse_shadowsocks_mode("1"));
    }

    #[test]
    fn changing_port_requires_explicit_random_choice() {
        for input in ["", "0", "  "] {
            assert_eq!(parse_port_change(input), Some(PortChoice::Back));
        }
        for input in ["r", "R"] {
            assert_eq!(parse_port_change(input), Some(PortChoice::Random));
        }
        for port in [1, 443, 65535] {
            assert_eq!(
                parse_port_change(&port.to_string()),
                Some(PortChoice::Fixed(port))
            );
        }
        for input in ["65536", "-1", "abc"] {
            assert_eq!(parse_port_change(input), None);
        }
    }

    #[tokio::test]
    async fn bootstrap_detection_fallback_respects_terminal() {
        let failure = || async { anyhow::bail!("offline") };
        assert!(bootstrap_address(failure, true, || Ok(String::new()))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            bootstrap_address(failure, true, || Ok("example.com".into()))
                .await
                .unwrap(),
            Some("example.com".into())
        );
        let error = bootstrap_address(failure, false, || panic!("must not read stdin"))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("prs add reality --server-address <IP或域名>"));
        assert_eq!(
            bootstrap_address(
                || async { Ok("203.0.113.1".into()) },
                false,
                || panic!("unneeded prompt")
            )
            .await
            .unwrap(),
            Some("203.0.113.1".into())
        );
    }

    #[test]
    fn update_center_numbers_are_stable_and_explicit() {
        assert_eq!(
            UPDATE_CENTER_ITEMS,
            ["更新 ping-rust（推荐）", "更新 shoes 内核", "检查更新状态",]
        );
        assert_eq!(SHOES_UPDATE_ITEMS[0], "安装 ping-rust 已验证版本（推荐）");
        assert_eq!(
            SHOES_UPDATE_ITEMS[1],
            "安装 shoes 最新 GitHub Release（高级）"
        );
    }

    #[test]
    fn uses_zero_for_exit_and_sequential_protocol_numbers() {
        let protocol_items = protocol_menu_items();
        assert_eq!(MAIN_MENU_ITEMS.first().unwrap().0, 1);
        assert_eq!(MAIN_MENU_ITEMS.last(), Some(&(0, "退出")));
        assert_eq!(protocol_items.last(), Some(&(0, "返回")));
        for protocol in Protocol::all() {
            assert!(protocol_items.iter().any(|item| {
                item.0 == protocol.menu_number() && item.1 == protocol.menu_label()
            }));
            assert_eq!(
                Protocol::from_menu_number(protocol.menu_number()),
                Some(protocol)
            );
        }
        assert_eq!(Protocol::from_menu_number(10), Some(Protocol::VmessWsTls));
        assert_eq!(Protocol::from_menu_number(11), Some(Protocol::Socks5));
        assert_eq!(Protocol::from_menu_number(12), Some(Protocol::Snell));
        assert_eq!(Protocol::from_menu_number(13), Some(Protocol::NaiveProxy));
        assert_eq!(protocol_items[10], (11, "SOCKS5"));
        assert_eq!(protocol_items[11], (12, "Snell v3"));
    }

    #[test]
    fn snell_new_node_defaults_to_mihomo_verified_cipher_and_keeps_advanced_choices() {
        assert_eq!(SnellCipher::default(), SnellCipher::Aes128Gcm);
        assert_eq!(
            snell_new_node_choice(""),
            Some(Some(SnellCipher::Aes128Gcm))
        );
        assert_eq!(
            snell_new_node_choice("2"),
            Some(Some(SnellCipher::Aes256Gcm))
        );
        assert_eq!(
            snell_new_node_choice("3"),
            Some(Some(SnellCipher::Chacha20IetfPoly1305))
        );
        assert_eq!(snell_new_node_choice("0"), Some(None));
        assert_eq!(snell_new_node_choice("4"), None);
        assert_eq!(
            SnellCipher::Aes256Gcm.mihomo_warning(),
            Some("未经客户端验证，Mihomo 仅支持 aes-128-gcm")
        );
        assert_eq!(SnellCipher::Aes128Gcm.mihomo_warning(), None);
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
        assert_eq!(parse_keyed_choice("0", &protocol_menu_items()), Some(0));
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
            h2mux: Default::default(),
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
            naive_certificate_validity: None,
        };

        assert_eq!(select_profile(&[profile]).unwrap(), Some(0));
    }

    #[test]
    fn anytls_reality_view_keeps_details_when_standard_uri_is_unsupported() {
        let profile = config::ManagedProfile {
            h2mux: Default::default(),
            id: uuid::Uuid::new_v4(),
            name: "anytls-reality".to_owned(),
            port: 443,
            server_address: Some("203.0.113.9".to_owned()),
            credentials: Credentials::AnyTls {
                users: vec![AnyTlsUser {
                    name: "default".to_owned(),
                    password: "secret".to_owned(),
                }],
                server_name: config::DEFAULT_SNI.to_owned(),
                alpn_protocols: vec!["h2".to_owned(), "http/1.1".to_owned()],
                udp_enabled: true,
                security: config::AnyTlsSecurity::Reality {
                    private_key: "never-print-private".to_owned(),
                    public_key: "public".to_owned(),
                    short_id: "0123456789abcdef".to_owned(),
                },
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
            naive_certificate_validity: None,
        };

        let (uri, warning) = share_uri_for_view(&profile);
        assert!(uri.is_none());
        let warning = warning.expect("unsupported standard URI should become a warning");
        assert!(warning.contains("请改用 sing-box 导出"));
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
            h2mux: Default::default(),
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
            naive_certificate_validity: None,
        };
        assert_eq!(profile.display_name(), "VLESS-REALITY-53453");
        assert_eq!(profile.config_file_name(), "VLESS-REALITY-53453.yaml");
        assert!(!profile.display_name().contains(&profile.id.to_string()));
    }
}
