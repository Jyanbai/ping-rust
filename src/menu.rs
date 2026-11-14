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
    (8, "链式代理"),
    (9, "工具"),
    (10, "帮助与关于"),
    (0, "退出"),
];

const OPERATIONS_MENU_ITEMS: [&str; 8] = [
    "导出客户端配置",
    "高级添加配置",
    "SNI 检测",
    "SNI 扫描",
    "端口检查",
    "开启 BBR",
    "备份配置",
    "恢复配置",
];

const SERVICE_MENU_ITEMS: [&str; 7] = [
    "启动",
    "停止",
    "重启",
    "状态",
    "启用并启动",
    "禁用",
    "查看日志",
];

const UPDATE_CENTER_ITEMS: [&str; 3] =
    ["更新 ping-rust（推荐）", "更新 shoes 内核", "检查更新状态"];

const SHOES_UPDATE_ITEMS: [&str; 2] = [
    "安装 ping-rust 已验证版本（推荐）",
    "安装 shoes 最新 GitHub Release（高级）",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChangeAction {
    VlessEncMode,
    VlessEncAuth,
    VlessEncVision,
    Sudoku,
    SudokuAscii,
    SudokuPadding,
    RegenerateSudokuPassword,
    H2Mux,
    Port,
    Name,
    ServerAddress,
    RegenerateCredentials,
    Password,
    RealityServerName,
    XhttpPath,
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
    Back,
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

fn control_after_pause(result: Result<()>) -> Result<MenuControl> {
    match result {
        Ok(()) => Ok(MenuControl::Continue),
        Err(error) if control_after_error(&error) == MenuControl::Exit => Ok(MenuControl::Exit),
        Err(error) => Err(error),
    }
}

/// 首次默认部署失败（连不上 GitHub、没有 systemd 等）时提示错误并照常进入主菜单，
/// 否则 state 一直不存在，每次启动都会重跑部署并退出，工具、更新、恢复等入口全部不可用。
/// 输入结束（EOF）仍退出菜单；Ctrl+C 中断仍交给 main 恢复光标后退出。
fn control_after_bootstrap(result: Result<bool>) -> Result<MenuControl> {
    match result {
        Ok(_) => Ok(MenuControl::Continue),
        Err(error) if input::is_back(&error) => Ok(MenuControl::Continue),
        Err(error) if crate::is_interrupted(&error) => Err(error),
        Err(error) if control_after_error(&error) == MenuControl::Exit => Ok(MenuControl::Exit),
        Err(error) => {
            eprintln!("{}", format!("首次默认部署失败：{error:#}").red());
            eprintln!("已跳过默认部署并进入主菜单；可在菜单 1 中添加配置，或在菜单 9 中使用工具。");
            Ok(MenuControl::Continue)
        }
    }
}

/// 启动时的节点文件检查（含旧版本迁移）失败——聚合配置被手动改过、与管理状态不一致、
/// 缺失或未通过 shoes 校验——时提示原因并照常进入主菜单，否则 `sudo prs` 直接退出，
/// 连 9) 工具 → 8) 恢复配置 都用不了。检查失败时不写入（提交失败会自行回滚）；
/// 之后添加、更改、删除节点和修改链式代理在提交前都会再次检查一致性并单独报错。
/// Ctrl+C 中断仍交给 main 恢复光标后退出。
/// 启动检查失败时返回诊断与恢复指引，由主界面每次清屏后重新显示，避免被清屏抹掉。
fn continue_after_profile_check(result: Result<bool>) -> Result<Option<(String, String)>> {
    match result {
        Ok(_) => Ok(None),
        Err(error) if crate::is_interrupted(&error) => Err(error),
        Err(error) => Ok(Some((
            format!("检查受管配置失败：{error:#}"),
            format!(
                "已进入主菜单，但添加、更改、删除节点和修改链式代理会继续报错；可在 9) 工具 → 8) 恢复配置 中恢复备份，或把 {} 改回与 ping-rust 管理状态一致。",
                crate::utils::CONFIG_FILE
            ),
        ))),
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
    match input.trim().parse::<usize>().ok()? {
        1 => Some(Some(config::ShadowsocksMode::Plain)),
        2 => Some(Some(config::ShadowsocksMode::ShadowTlsV3)),
        0 => Some(None),
        _ => None,
    }
}

fn control_after_success(_main_menu_choice: usize) -> MenuControl {
    MenuControl::Continue
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
        println!("无效序号！");
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
        println!("无效序号！");
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

/// 菜单里的首次默认部署要先确认（回车 = 部署），放在公网地址探测和 shoes 下载之前：
/// 部署失败后 state 仍不存在，每次进菜单都会重试，连不上 GitHub 时要白等几分钟。
/// 标准输入不是终端时（脚本、管道）保持原来的直接部署；输入 0 等同于跳过。
pub(crate) fn bootstrap_confirmed(
    terminal: bool,
    ask: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    if !terminal {
        return Ok(true);
    }
    match ask() {
        Err(error) if input::is_back(&error) => Ok(false),
        result => result,
    }
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

/// state 文件不存在（新装机器、取消了首次默认部署）表示还没有节点，不是读取失败。
fn summary_state(
    path: &std::path::Path,
    load: impl FnOnce() -> Result<config::ManagedState>,
) -> Result<config::ManagedState> {
    if path.exists() {
        load()
    } else {
        Ok(config::ManagedState::default())
    }
}

fn node_summary(state: Result<config::ManagedState>) -> String {
    let state = match state {
        Ok(state) => state,
        Err(error) => {
            let reason = error.to_string().lines().collect::<Vec<_>>().join(" ");
            return format!("节点：无法读取（{reason}）");
        }
    };
    if state.profiles.is_empty() {
        return "节点 (0):\n暂无节点".to_owned();
    }
    let count = state.profiles.len();
    let mut lines = vec![format!("节点 ({count}):")];
    for profile in &state.profiles {
        // 与查看配置、分享信息使用同一个协议名，不另起一套显示名。
        lines.push(format!(
            "• {} - 端口: {}",
            profile.protocol_name(),
            profile.port
        ));
    }
    lines.join("\n")
}

pub async fn run() -> Result<()> {
    if control_after_bootstrap(cli::bootstrap_default_reality_for_menu().await)?
        == MenuControl::Exit
    {
        return Ok(());
    }
    // 状态无法读取时仍提供工具、恢复等入口，节点摘要负责显示读取失败提示。
    let mut profile_check = if config::load_state().is_ok() {
        continue_after_profile_check(config::ensure_profile_files().await)?
    } else {
        None
    };
    loop {
        input::clear_screen()?;
        println!(
            "------------- ping-rust v{} -------------",
            env!("CARGO_PKG_VERSION")
        );
        println!("https://github.com/Jyanbai/ping-rust\n");
        let shoes_status = if service::is_active().unwrap_or(false) {
            "running"
        } else if std::path::Path::new(crate::utils::SHOES_BIN).is_file() {
            "stopped"
        } else {
            "not installed"
        };
        if shoes_status == "running" {
            println!("shoes: {}\n", "• running".green());
        } else {
            println!("shoes: • {shoes_status}\n");
        }
        let state = summary_state(
            std::path::Path::new(crate::utils::STATE_FILE),
            config::load_state,
        );
        println!("{}\n", node_summary(state));
        if let Some((failure, guidance)) = &profile_check {
            eprintln!("{}", failure.red());
            eprintln!("{guidance}\n");
        }
        let selected = match select_keyed("", MAIN_MENU_ITEMS) {
            Err(error) if control_after_error(&error) == MenuControl::Exit => return Ok(()),
            result => result?,
        };
        input::reset_navigation();
        input::clear_screen()?;
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
                    chain_proxy_menu().await?;
                    Ok(MenuControl::Continue)
                }
                9 => operations_menu().await,
                10 => {
                    println!("ping-rust {}", env!("CARGO_PKG_VERSION"));
                    println!("Rust 实现的 shoes 菜单式安装与管理工具");
                    println!("https://github.com/Jyanbai/ping-rust");
                    println!("常用命令：");
                    println!("  prs add reality / prs add ss  添加配置");
                    println!("  prs info / prs url / prs qr  查看配置、链接和二维码");
                    println!(
                        "  prs sni check [域名...]  检测 SNI（省略域名使用默认名单和现有节点）"
                    );
                    println!("  prs sni scan  扫描 SNI");
                    println!("链式代理：prs → 8) 链式代理（节点、Pool、Chain、路由和测试）");
                    println!("高级帮助：ping-rust --help");
                    Ok(MenuControl::Continue)
                }
                _ => anyhow::bail!("菜单返回了无效选项"),
            }
        }
        .await;
        let control = match result {
            Ok(control) => {
                if control == MenuControl::Continue && !input::returned_to_parent() {
                    control_after_pause(input::pause_main_menu())?
                } else {
                    control
                }
            }
            Err(error) => {
                if crate::is_interrupted(&error) {
                    crate::restore_cursor_and_exit();
                }
                let control = control_after_error(&error);
                if control == MenuControl::Continue && !input::is_back(&error) {
                    eprintln!("{}", format!("错误：{error:#}").red());
                    control_after_pause(input::pause_main_menu())?
                } else {
                    control
                }
            }
        };
        if control == MenuControl::Exit {
            return Ok(());
        }
        // 恢复配置等操作之后重新检查，问题已解决时不再显示过期诊断。
        if profile_check.is_some() && config::load_state().is_ok() {
            profile_check = continue_after_profile_check(config::ensure_profile_files().await)?;
        }
    }
}

async fn prompt_probed_sni(label: &str, mode: crate::sni::Mode) -> Result<String> {
    loop {
        let choice = select_keyed(
            "选择 SNI 方式",
            &[
                (1, "自动选择"),
                (2, "检测与推荐"),
                (3, "手动输入"),
                (0, "返回"),
            ],
        )?;
        match choice {
            0 => return Err(input::back()),
            1 => return crate::sni_probe::resolve(None, true).await,
            2 => match recommend_sni(mode).await {
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
                None => println!("无效序号！"),
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
    loop {
        let Some(selected) = select_profile(&state.profiles)? else {
            return Ok(());
        };
        let profile = state.profiles[selected].clone();
        loop {
            match change_profile_menu(&profile).await {
                Err(error) if input::is_back(&error) => continue,
                Ok(()) if input::returned_to_parent() && state.profiles.len() > 1 => break,
                result => return result,
            }
        }
    }
}

fn read_xhttp_path_change(
    reader: &mut impl io::BufRead,
    writer: &mut impl io::Write,
    current: &str,
) -> Result<Option<ProfileChange>> {
    let path = input::read_text(
        reader,
        writer,
        "新 XHTTP path",
        Some(current),
        false,
        |path| {
            config::validate_xhttp_path(path)?;
            Ok(path.to_owned())
        },
    )?;
    if path == current {
        return Ok(None);
    }
    Ok(Some(ProfileChange::XhttpPath(path)))
}

fn change_actions(profile: &config::ManagedProfile) -> Vec<(ChangeAction, &'static str)> {
    let mut actions = vec![
        (ChangeAction::Port, "更改端口"),
        (ChangeAction::Name, "更改配置名称"),
        (ChangeAction::ServerAddress, "更改客户端公网地址"),
        (ChangeAction::RegenerateCredentials, "重新生成全部协议凭据"),
    ];
    match profile.protocol() {
        Protocol::VlessSudoku => {
            actions.push((ChangeAction::SudokuAscii, "更改 Sudoku ascii 模式"));
            actions.push((ChangeAction::SudokuPadding, "更改 Sudoku padding"));
            actions.push((
                ChangeAction::RegenerateSudokuPassword,
                "重新生成 Sudoku 密码",
            ));
        }
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
            actions.push((ChangeAction::Sudoku, "开启或关闭 Sudoku 外观"));
            actions.push((
                ChangeAction::RegenerateSudokuPassword,
                "重新生成 Sudoku 密码",
            ));
        }
        Protocol::Reality | Protocol::TrojanReality | Protocol::VlessXhttpReality => {
            if profile.protocol() == Protocol::VlessXhttpReality {
                actions.push((ChangeAction::XhttpPath, "更改 XHTTP path"));
            }
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
    actions
}

async fn change_profile_menu(profile: &config::ManagedProfile) -> Result<()> {
    let actions = change_actions(profile);
    let action_labels = actions.iter().map(|(_, label)| *label).collect::<Vec<_>>();
    let Some(action_index) = select_numbered("选择更改项目", &action_labels)? else {
        return Ok(());
    };
    let action = actions[action_index].0;
    let change = match action {
        ChangeAction::SudokuAscii | ChangeAction::SudokuPadding => {
            let Credentials::VlessSudoku { sudoku, .. } = &profile.credentials else {
                bail!("配置协议不一致");
            };
            let mut settings = sudoku.clone();
            if matches!(action, ChangeAction::SudokuAscii) {
                let Some(index) = select_numbered(
                    "Sudoku ascii 模式",
                    &["prefer_entropy", "entropy", "prefer_ascii", "ascii"],
                )?
                else {
                    return Ok(());
                };
                use crate::sudoku::SudokuAscii;
                settings.ascii = [
                    SudokuAscii::PreferEntropy,
                    SudokuAscii::Entropy,
                    SudokuAscii::PreferAscii,
                    SudokuAscii::Ascii,
                ][index];
            } else {
                let Some(updated) =
                    read_sudoku_padding(&mut io::stdin().lock(), &mut io::stdout(), &settings)?
                else {
                    return Ok(());
                };
                settings = updated;
            }
            ProfileChange::Sudoku(Some(settings))
        }
        ChangeAction::Sudoku | ChangeAction::RegenerateSudokuPassword => {
            let sudoku = match &profile.credentials {
                Credentials::VlessEnc { sudoku, .. } => sudoku.as_ref(),
                Credentials::VlessSudoku { sudoku, .. } => Some(sudoku),
                _ => bail!("配置协议不一致"),
            };
            let regenerate = matches!(action, ChangeAction::RegenerateSudokuPassword);
            let Some(change) = sudoku_menu_change(sudoku, regenerate, |prompt, default| {
                input::confirm(prompt, default)
            })?
            else {
                return Ok(());
            };
            change
        }
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
                "VPS 公网域名或 IP（默认：自动检测）",
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
        ChangeAction::RegenerateCredentials => ProfileChange::RegenerateCredentials,
        ChangeAction::Password => {
            let password = input::password("新密码（默认：随机生成）", true)?;
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
        ChangeAction::XhttpPath => {
            let Credentials::VlessXhttpReality { xhttp, .. } = &profile.credentials else {
                bail!("该配置不是 VLESS-XHTTP-REALITY");
            };
            let Some(change) =
                read_xhttp_path_change(&mut io::stdin().lock(), &mut io::stdout(), &xhttp.path)?
            else {
                return Ok(());
            };
            change
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
            let password = input::password("ShadowTLS 密码（默认：随机生成）", true)?;
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
            let password = input::password("新密码（默认：随机生成）", true)?;
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

    deployment::update_and_activate(profile.id, change).await?;
    input::clear_screen()?;
    println!("{}", "配置更改成功。".green());
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
    input::clear_screen()?;
    cli::print_profile_details_with_qr(profile, share_uri.as_deref());
    if let Some(warning) = share_warning {
        println!("未生成标准分享链接：{warning}");
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
    deployment::delete_and_activate(profile.id).await?;
    input::clear_screen()?;
    println!("{}", "配置删除成功。".green());
    Ok(())
}

async fn operations_menu() -> Result<MenuControl> {
    loop {
        match operations_menu_once().await {
            Err(error) if input::is_back(&error) => continue,
            Ok(MenuControl::Back) => return Ok(MenuControl::Continue),
            Ok(MenuControl::Continue) if input::returned_to_parent() => continue,
            result => return result,
        }
    }
}

async fn operations_menu_once() -> Result<MenuControl> {
    let Some(selected) = select_numbered("工具", &OPERATIONS_MENU_ITEMS)? else {
        return Ok(MenuControl::Back);
    };
    match selected {
        0 => export_menu(),
        1 => advanced_add_config_menu().await,
        2 => {
            let command = input::validated_text(
                "输入 SNI 域名，空格分隔（默认：默认名单和现有节点）",
                None,
                true,
                sni_check_command,
            )?;
            crate::sni::run(command).await
        }
        3 => {
            crate::sni::run(crate::sni::Command::Scan {
                yes: false,
                protocol: crate::sni::Mode::Reality,
            })
            .await
        }
        4 => {
            let port = input::port("检查端口", Some(443))?;
            cli::print_port_status(port, operations::check_port(port, true, true));
            Ok(())
        }
        5 => {
            if input::confirm("写入 sysctl 配置并启用 BBR？", false)? {
                operations::enable_bbr()?;
                println!("{}", "BBR 已启用。".green());
            }
            Ok(())
        }
        6 => {
            let path = operations::backup(None)?;
            println!("备份已创建：{}", path.display());
            Ok(())
        }
        7 => {
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
        _ => unreachable!("工具菜单编号已验证"),
    }?;
    Ok(MenuControl::Continue)
}

fn sni_check_command(domains: &str) -> Result<crate::sni::Command> {
    crate::sni::manual(domains, crate::sni::Mode::Reality)?;
    Ok(crate::sni::Command::Check {
        domains: domains.split_whitespace().map(str::to_owned).collect(),
        csv: None,
        subnet: None,
        protocol: None,
    })
}

async fn chain_proxy_menu() -> Result<()> {
    chain::menu().await
}

async fn add_chain_node() -> Result<()> {
    let parsed = input::validated_text("粘贴分享链接", None, false, chain_proxy::parse_share_uri)?;
    println!(
        "识别结果：{} | {} | {}",
        parsed.name,
        parsed.protocol_name(),
        parsed.address()
    );
    let name = input::checked_text(
        "节点名称",
        Some(&parsed.name),
        false,
        chain_proxy::validate_node_name,
    )?;
    let node = parsed.with_name(name)?;
    deployment::update_chain_proxy(ChainProxyChange::Add(node.clone())).await?;
    println!("{} {}", "节点已添加：".green(), node.name);
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
    Ok(())
}

async fn fast_add_config_menu() -> Result<MenuControl> {
    loop {
        match fast_add_config_menu_once().await {
            Err(error) if input::is_back(&error) => continue,
            Ok(MenuControl::Back) => return Ok(MenuControl::Continue),
            Ok(MenuControl::Continue) if input::returned_to_parent() => continue,
            result => return result,
        }
    }
}

async fn fast_add_config_menu_once() -> Result<MenuControl> {
    let protocol_items = protocol_menu_items();
    let protocol_number = select_keyed("选择协议", &protocol_items)?;
    if protocol_number == 0 {
        return Ok(MenuControl::Back);
    }
    let protocol = Protocol::from_menu_number(protocol_number)
        .with_context(|| format!("协议编号无效：{protocol_number}"))?;
    'options: loop {
        let shadowsocks_mode = if protocol == Protocol::Shadowsocks {
            println!("\nShadowsocks 模式:\n\n1) Shadowsocks 2022\n2) Shadowsocks 2022 + ShadowTLS v3\n0) 返回\n");
            loop {
                match parse_shadowsocks_mode(&read_menu_choice(2)?) {
                    Some(Some(mode)) => break mode,
                    Some(None) => return Ok(MenuControl::Continue),
                    None => println!("无效序号！"),
                }
            }
        } else {
            config::ShadowsocksMode::Plain
        };
        let anytls_mode = if protocol == Protocol::AnyTls {
            let Some(mode) = select_anytls_mode()? else {
                return Ok(MenuControl::Continue);
            };
            mode
        } else {
            AnyTlsMode::default()
        };
        let port = match input::validated_text("请输入端口", Some("随机"), true, |value| {
            if value == "随机" {
                return Ok(PortChoice::Random);
            }
            parse_port_choice(value).context("请输入 1 到 65535 的端口")
        }) {
            Err(error)
                if input::is_back(&error)
                    && matches!(protocol, Protocol::Shadowsocks | Protocol::AnyTls) =>
            {
                continue 'options
            }
            result => result?,
        };
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
                &["已有受信任证书", "自签名测试模式（仅供测试）"],
            )?
            else {
                return Ok(MenuControl::Continue);
            };
            let (certificate, certificate_key) = if mode == 0 {
                let cert = input::file_path("PEM 证书路径")?;
                let key = input::file_path("PEM 私钥路径")?;
                (Some(cert.into()), Some(key.into()))
            } else {
                (None, None)
            };
            cli::ensure_shoes_for_add(true).await?;
            let server_address = resolve_menu_server_address().await?;
            let result = fast_add::execute(fast_add::AddRequest {
                interactive: true,
                vless_enc: Default::default(),
                xhttp_path: None,
                name: None,
                protocol,
                anytls_mode: AnyTlsMode::default(),
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
            let _ = result;
            input::clear_screen()?;
            println!("{}", "配置添加成功。".green());
            return Ok(control_after_success(1));
        }
        let (shadowsocks_cipher, shadowsocks_password) = if protocol == Protocol::Shadowsocks {
            let Some(cipher) = select_shadowsocks_cipher(shadowsocks_mode)? else {
                continue 'options;
            };
            let entered_password = input::password("请设置密码（默认：随机生成）", true)?;
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
        return deploy_fast_config(
            protocol,
            port,
            shadowsocks_cipher,
            shadowsocks_password,
            shadowsocks_mode,
            anytls_mode,
        )
        .await;
    }
}

const ANYTLS_MODE_LABELS: [&str; 2] = ["TLS", "REALITY"];

fn select_anytls_mode() -> Result<Option<AnyTlsMode>> {
    Ok(select_numbered("AnyTLS 外层安全模式", &ANYTLS_MODE_LABELS)?
        .map(|index| [AnyTlsMode::Tls, AnyTlsMode::Reality][index]))
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
    println!();
    loop {
        let value = read_menu_choice(ciphers.len())?;
        match parse_numbered_choice(&value, ciphers.len()) {
            Some(Some(index)) => return Ok(Some(ciphers[index])),
            Some(None) => return Ok(None),
            None => {}
        }
        println!("无效序号！");
    }
}

const SNELL_CIPHERS: [SnellCipher; 3] = [
    SnellCipher::Aes128Gcm,
    SnellCipher::Aes256Gcm,
    SnellCipher::Chacha20IetfPoly1305,
];
const SNELL_CIPHER_LABELS: [&str; 3] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];

fn snell_new_node_choice(value: &str) -> Option<Option<SnellCipher>> {
    parse_numbered_choice(value, SNELL_CIPHERS.len())
        .map(|selected| selected.map(|index| SNELL_CIPHERS[index]))
}

fn select_snell_cipher(prompt: &str) -> Result<Option<SnellCipher>> {
    let Some(selected) = select_numbered(prompt, &SNELL_CIPHER_LABELS)? else {
        return Ok(None);
    };
    let cipher = SNELL_CIPHERS[selected];
    Ok(Some(cipher))
}

fn select_new_snell_cipher() -> Result<Option<SnellCipher>> {
    println!("\n选择 Snell v3 加密方式:\n");
    for (index, label) in SNELL_CIPHER_LABELS.iter().enumerate() {
        println!("{}) {label}", index + 1);
    }
    println!("0) 返回\n");
    loop {
        let value = read_menu_choice(SNELL_CIPHERS.len())?;
        match snell_new_node_choice(&value) {
            Some(Some(cipher)) => {
                return Ok(Some(cipher));
            }
            Some(None) => return Ok(None),
            None => println!("无效序号！"),
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
    let Some(index) = select_numbered("VLESS Encryption 外观", &["native", "xorpub", "random"])?
    else {
        return Ok(None);
    };
    let mode = [
        config::VlessEncMode::Native,
        config::VlessEncMode::Xorpub,
        config::VlessEncMode::Random,
    ][index];
    Ok(Some(mode))
}

fn prompt_vless_enc_auth() -> Result<Option<config::VlessEncAuth>> {
    let Some(index) = select_numbered("VLESS Encryption 认证", &["x25519", "mlkem768"])? else {
        return Ok(None);
    };
    let auth = [config::VlessEncAuth::X25519, config::VlessEncAuth::Mlkem768][index];
    Ok(Some(auth))
}

fn prompt_vless_enc_options() -> Result<Option<crate::vless_encryption::Options>> {
    prompt_vless_enc_options_with(
        prompt_vless_enc_mode,
        prompt_vless_enc_auth,
        || input::confirm("开启 Vision？", false),
        || read_sudoku_prompt(&mut io::stdin().lock(), &mut io::stdout()),
    )
}

fn read_sudoku_prompt(reader: &mut impl io::BufRead, writer: &mut impl io::Write) -> Result<bool> {
    input::read_confirm(reader, writer, "启用 Sudoku 外观？", false)
}

fn read_sudoku_padding(
    reader: &mut impl io::BufRead,
    writer: &mut impl io::Write,
    current: &crate::sudoku::SudokuConfig,
) -> Result<Option<crate::sudoku::SudokuConfig>> {
    // A separate return choice keeps zero available as a valid padding value.
    if !input::read_confirm(reader, writer, "更改 Sudoku padding？", false)? {
        return Ok(None);
    }
    let mut selected = current.clone();
    loop {
        selected.padding_min =
            input::read_number(reader, writer, "最小 padding（0–100）", current.padding_min)?;
        selected.padding_max =
            input::read_number(reader, writer, "最大 padding（0–100）", current.padding_max)?;
        match selected.validate() {
            Ok(()) => return Ok(Some(selected)),
            Err(error) => writeln!(writer, "错误！{error}")?,
        }
    }
}

fn sudoku_menu_change(
    current: Option<&crate::sudoku::SudokuConfig>,
    regenerate: bool,
    confirm: impl FnOnce(&str, bool) -> Result<bool>,
) -> Result<Option<ProfileChange>> {
    if regenerate {
        if current.is_none() {
            bail!("请先开启 Sudoku 外观");
        }
        return Ok(Some(ProfileChange::RegenerateSudokuPassword));
    }
    let prompt = if current.is_some() {
        "关闭 Sudoku 外观？"
    } else {
        "启用 Sudoku 外观？"
    };
    if !confirm(prompt, false)? {
        return Ok(None);
    }
    Ok(Some(ProfileChange::Sudoku(if current.is_some() {
        None
    } else {
        Some(crate::sudoku::SudokuConfig::generated())
    })))
}

fn prompt_vless_enc_options_with(
    mut mode: impl FnMut() -> Result<Option<config::VlessEncMode>>,
    mut auth: impl FnMut() -> Result<Option<config::VlessEncAuth>>,
    mut vision: impl FnMut() -> Result<bool>,
    mut sudoku: impl FnMut() -> Result<bool>,
) -> Result<Option<crate::vless_encryption::Options>> {
    'mode: loop {
        let Some(mode) = mode()? else {
            return Ok(None);
        };
        'auth: loop {
            let Some(auth) = auth()? else {
                continue 'mode;
            };
            loop {
                let vision = match vision() {
                    Err(error) if input::is_back(&error) => continue 'auth,
                    result => result?,
                };
                let enabled = match sudoku() {
                    Err(error) if input::is_back(&error) => continue,
                    result => result?,
                };
                return Ok(Some(crate::vless_encryption::Options {
                    mode,
                    auth,
                    vision,
                    sudoku: crate::sudoku::SudokuOptions {
                        enabled,
                        ..Default::default()
                    },
                }));
            }
        }
    }
}

async fn deploy_fast_config(
    protocol: Protocol,
    port: Option<u16>,
    shadowsocks_cipher: Option<ShadowsocksCipher>,
    shadowsocks_password: Option<String>,
    shadowsocks_mode: config::ShadowsocksMode,
    anytls_mode: AnyTlsMode,
) -> Result<MenuControl> {
    let vless_enc = if protocol == Protocol::VlessEnc {
        let Some(options) = prompt_vless_enc_options()? else {
            return Ok(MenuControl::Continue);
        };
        options
    } else {
        Default::default()
    };
    cli::ensure_shoes_for_add(true).await?;
    let server_name = if protocol.uses_reality(anytls_mode) {
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
        xhttp_path: None,
        name: None,
        protocol,
        anytls_mode,
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
    let _ = result;
    input::clear_screen()?;
    println!("{}", "配置添加成功。".green());
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
    loop {
        let choices = Protocol::all()
            .map(Protocol::advanced_label)
            .collect::<Vec<_>>();
        let Some(selected) = select_numbered("选择协议", &choices)? else {
            return Ok(());
        };
        let protocol =
            Protocol::from_menu_number(selected + 1).context("协议菜单与中央注册表不一致")?;
        match advanced_add_protocol(protocol).await {
            Err(error) if input::is_back(&error) => continue,
            Ok(()) if input::returned_to_parent() => continue,
            result => return result,
        }
    }
}

async fn advanced_add_protocol(protocol: Protocol) -> Result<()> {
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
        options.sudoku = selected.sudoku.config()?;
    }
    let mut shadowtls_server_name = None;
    if matches!(protocol, Protocol::Shadowsocks) {
        loop {
            let Some(mode) = select_numbered(
                "Shadowsocks 模式",
                &["普通 SS2022", "SS2022 + ShadowTLS v3"],
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
                    "2022-blake3-aes-256-gcm",
                    "2022-blake3-aes-128-gcm",
                    "2022-blake3-chacha20-ietf-poly1305",
                ]
            } else {
                vec![
                    "2022-blake3-aes-256-gcm",
                    "2022-blake3-aes-128-gcm",
                    "2022-blake3-chacha20-ietf-poly1305",
                    "aes-256-gcm",
                    "aes-128-gcm",
                    "chacha20-ietf-poly1305",
                ]
            };
            let Some(cipher) = select_numbered("选择加密方式", &ciphers)? else {
                continue;
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
                let password = input::password("SS2022 密钥（默认：随机生成）", true)?;
                options.shadowsocks_password = (!password.is_empty()).then_some(password);
                let shadow_password = input::password("ShadowTLS 密码（默认：随机生成）", true)?;
                options.shadowtls_password =
                    (!shadow_password.is_empty()).then_some(shadow_password);
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
            break;
        }
    }
    if matches!(protocol, Protocol::Snell) {
        let Some(cipher) = select_new_snell_cipher()? else {
            return Ok(());
        };
        options.snell_cipher = cipher;
        let password = input::password("Snell v3 密码（默认：随机生成）", true)?;
        options.snell_password = (!password.is_empty()).then_some(password);
        options.udp_enabled = input::confirm("启用 Snell UDP-over-TCP？", true)?;
    }
    if matches!(protocol, Protocol::Socks5) {
        let Some(authentication) = select_numbered("认证", &["用户名 + 密码", "无认证"])?
        else {
            return Ok(());
        };
        if authentication == 0 {
            let username = input::text("SOCKS5 用户名（默认：随机生成）", None, true)?;
            options.socks5_username = (!username.is_empty()).then_some(username);
            let password = input::password("SOCKS5 密码（默认：随机生成）", true)?;
            options.socks5_password = (!password.is_empty()).then_some(password);
        } else {
            options.socks5_no_auth = true;
        }
        options.udp_enabled = input::confirm("启用 UDP ASSOCIATE？", true)?;
    }
    if matches!(protocol, Protocol::AnyTls) {
        let Some(mode) = select_anytls_mode()? else {
            return Ok(());
        };
        options.anytls_mode = mode;
        loop {
            let default_name = if options.anytls_users.is_empty() {
                "default".to_owned()
            } else {
                format!("user{}", options.anytls_users.len() + 1)
            };
            let user_name = input::text("AnyTLS 用户名", Some(&default_name), false)?;
            let password = input::password("AnyTLS 密码（默认：随机生成）", true)?;
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
        if input::confirm("使用默认 padding_scheme？", true)? {
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
        let username = input::text("NaiveProxy 用户名（默认：随机生成）", None, true)?;
        options.naive_username = (!username.is_empty()).then_some(username);
        let password = input::password("NaiveProxy 密码（默认：随机生成）", true)?;
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
        Protocol::Shadowsocks
            | Protocol::Snell
            | Protocol::Socks5
            | Protocol::VlessEnc
            | Protocol::VlessSudoku
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
                "使用已有受信任 PEM 证书和私钥？"
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
    let _ = result;
    input::clear_screen()?;
    println!("{}", "配置添加成功。".green());
    Ok(())
}

async fn update_menu() -> Result<MenuControl> {
    loop {
        let Some(selected) = select_numbered("更新中心", &UPDATE_CENTER_ITEMS)? else {
            return Ok(MenuControl::Continue);
        };
        match selected {
            0 => {
                cli::run_self_update(None, false).await?;
            }
            1 => shoes_update_menu().await?,
            2 => cli::print_update_status().await?,
            _ => unreachable!("更新中心编号已验证"),
        }
        if !input::returned_to_parent() {
            return Ok(MenuControl::Continue);
        }
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
    let Some(selected) = select_numbered("服务管理", &SERVICE_MENU_ITEMS)? else {
        return Ok(());
    };
    if selected == 6 {
        return service::logs(100);
    }
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
    fn xhttp_reality_menu_validates_path_without_extra_confirmation() {
        let state: config::ManagedState = serde_json::from_str(include_str!(
            "../tests/fixtures/yaml/vless-xhttp-reality/state.json"
        ))
        .unwrap();
        let actions = change_actions(&state.profiles[0]);
        for label in ["更改端口", "更改 SNI", "更改 XHTTP path"] {
            assert!(actions.iter().any(|(_, action)| *action == label));
        }
        assert!(!actions
            .iter()
            .any(|(_, label)| label.contains("Vision") || label.contains("H2MUX")));
        assert!(
            read_xhttp_path_change(&mut io::Cursor::new("\n"), &mut Vec::new(), "/current")
                .unwrap()
                .is_none()
        );
        let mut output = Vec::new();
        let change = read_xhttp_path_change(
            &mut io::Cursor::new("invalid\n/changed\n"),
            &mut output,
            "/current",
        )
        .unwrap();
        assert!(matches!(change, Some(ProfileChange::XhttpPath(path)) if path == "/changed"));
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("失效"));
        assert!(!output.contains("[y/N]"));
        assert!(output.contains("错误！XHTTP path"));
        assert!(input::is_back(
            &read_xhttp_path_change(&mut io::Cursor::new("0\n"), &mut Vec::new(), "/current")
                .err()
                .unwrap()
        ));
    }

    #[test]
    fn bootstrap_confirmation_only_asks_on_terminals_and_back_skips() {
        assert!(bootstrap_confirmed(false, || unreachable!("非终端不应询问")).unwrap());
        for (answer, expected) in [("\n", true), ("y\n", true), ("n\n", false), ("0\n", false)] {
            let mut output = Vec::new();
            let confirmed = bootstrap_confirmed(true, || {
                input::read_confirm(&mut answer.as_bytes(), &mut output, "现在部署？", true)
            })
            .unwrap();
            assert_eq!(confirmed, expected, "输入 {answer:?}");
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "现在部署？ [Y/n]（输入 0 返回）："
            );
        }
        let eof = bootstrap_confirmed(true, || {
            input::read_confirm(&mut &b""[..], &mut Vec::new(), "现在部署？", true)
        })
        .unwrap_err();
        assert_eq!(control_after_error(&eof), MenuControl::Exit);
    }

    #[test]
    fn bootstrap_failure_continues_to_main_menu_but_eof_and_interrupt_do_not() {
        assert_eq!(
            control_after_bootstrap(Ok(true)).unwrap(),
            MenuControl::Continue
        );
        assert_eq!(
            control_after_bootstrap(Ok(false)).unwrap(),
            MenuControl::Continue
        );
        for failure in [
            anyhow::anyhow!("请求 shoes 固定 Release v0.3.7 失败"),
            anyhow::anyhow!("未找到 systemctl；当前系统可能未使用 systemd"),
        ] {
            assert_eq!(
                control_after_bootstrap(Err(failure)).unwrap(),
                MenuControl::Continue
            );
        }
        let back = input::read_text(
            &mut &b"0\n"[..],
            &mut Vec::new(),
            "公网地址",
            None,
            false,
            |value| Ok(value.to_owned()),
        )
        .unwrap_err();
        assert!(input::is_back(&back));
        assert_eq!(
            control_after_bootstrap(Err(back)).unwrap(),
            MenuControl::Continue
        );
        assert_eq!(
            control_after_bootstrap(Err(anyhow::Error::new(MenuEof).context("读取"))).unwrap(),
            MenuControl::Exit
        );
        let interrupted = anyhow::Error::new(io::Error::from(io::ErrorKind::Interrupted));
        assert!(crate::is_interrupted(
            &control_after_bootstrap(Err(interrupted)).unwrap_err()
        ));
    }

    #[test]
    fn profile_check_failure_continues_to_main_menu_but_interrupt_does_not() {
        assert!(continue_after_profile_check(Ok(true)).unwrap().is_none());
        assert!(continue_after_profile_check(Ok(false)).unwrap().is_none());
        for failure in [
            anyhow::anyhow!("第 1 项监听地址 0.0.0.0:24432 与管理状态端口 24431 不一致")
                .context("旧版聚合配置与管理状态不一致，无法安全迁移节点文件"),
            anyhow::anyhow!("读取配置 /etc/shoes/config.yaml 失败"),
            anyhow::anyhow!("shoes --dry-run 拒绝了候选配置"),
        ] {
            let reason = format!("{failure:#}");
            let (message, guidance) = continue_after_profile_check(Err(failure))
                .unwrap()
                .expect("启动检查失败必须返回供主界面重新显示的诊断");
            assert_eq!(message, format!("检查受管配置失败：{reason}"));
            assert!(guidance.contains("9) 工具 → 8) 恢复配置"), "{guidance}");
        }
        let interrupted = anyhow::Error::new(io::Error::from(io::ErrorKind::Interrupted))
            .context("等待 shoes 校验");
        assert!(crate::is_interrupted(
            &continue_after_profile_check(Err(interrupted)).unwrap_err()
        ));
    }

    #[test]
    fn result_page_enter_continues_eof_exits_and_other_errors_propagate() {
        assert_eq!(control_after_pause(Ok(())).unwrap(), MenuControl::Continue);
        for eof in [
            anyhow::Error::new(MenuEof).context("读取结果页"),
            anyhow::Error::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
        ] {
            assert_eq!(control_after_pause(Err(eof)).unwrap(), MenuControl::Exit);
        }
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::Interrupted] {
            let error = control_after_pause(Err(io::Error::from(kind).into())).unwrap_err();
            assert_eq!(error.downcast_ref::<io::Error>().unwrap().kind(), kind);
        }
    }

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
            || panic!("cancelled"),
            || panic!("cancelled")
        )
        .unwrap()
        .is_none());
        let mut modes = [Some(config::VlessEncMode::default()), None].into_iter();
        assert!(prompt_vless_enc_options_with(
            || Ok(modes.next().unwrap()),
            || Ok(None),
            || panic!("cancelled"),
            || panic!("cancelled"),
        )
        .unwrap()
        .is_none());
        assert_eq!(parse_shadowsocks_mode("3"), None);
        assert_eq!(parse_shadowsocks_mode("bad"), None);
        assert_eq!(parse_shadowsocks_mode("0"), Some(None));
        assert_eq!(parse_shadowsocks_mode(""), None);
    }

    #[test]
    fn encryption_wizard_returns_one_level_and_preserves_selected_parameters() {
        let mut modes = [config::VlessEncMode::Native, config::VlessEncMode::Xorpub].into_iter();
        let mut auths = [
            None,
            Some(config::VlessEncAuth::X25519),
            Some(config::VlessEncAuth::Mlkem768),
        ]
        .into_iter();
        let mut visions = [Err(input::back()), Ok(true), Ok(false)].into_iter();
        let mut sudokus = [Err(input::back()), Ok(true)].into_iter();
        let options = prompt_vless_enc_options_with(
            || Ok(Some(modes.next().expect("returned to mode"))),
            || Ok(auths.next().expect("returned to auth")),
            || visions.next().expect("returned to Vision"),
            || sudokus.next().expect("retried Sudoku"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(options.mode, config::VlessEncMode::Xorpub);
        assert_eq!(options.auth, config::VlessEncAuth::Mlkem768);
        assert!(!options.vision);
        assert!(options.sudoku.enabled);
        assert!(modes.next().is_none() && auths.next().is_none());
        assert!(visions.next().is_none() && sudokus.next().is_none());
    }

    #[test]
    fn vless_sudoku_menu_keeps_actions_and_padding_validation() {
        let state: config::ManagedState = serde_json::from_str(include_str!(
            "../tests/fixtures/yaml/vless-sudoku/state.json"
        ))
        .unwrap();
        let actions = change_actions(&state.profiles[0]);
        for expected in [
            ChangeAction::Port,
            ChangeAction::SudokuAscii,
            ChangeAction::SudokuPadding,
            ChangeAction::RegenerateSudokuPassword,
        ] {
            assert!(actions.iter().any(|(action, _)| *action == expected));
        }
        assert!(!actions
            .iter()
            .any(|(action, _)| *action == ChangeAction::Sudoku));
        let current = crate::sudoku::SudokuConfig::generated();
        assert!(matches!(
            sudoku_menu_change(Some(&current), true, |_, _| panic!("no confirmation")).unwrap(),
            Some(ProfileChange::RegenerateSudokuPassword)
        ));
        assert!(
            read_sudoku_padding(&mut "\n".as_bytes(), &mut Vec::new(), &current)
                .unwrap()
                .is_none()
        );
        let error =
            read_sudoku_padding(&mut "0\n".as_bytes(), &mut Vec::new(), &current).unwrap_err();
        assert!(input::is_back(&error));
        let mut output = Vec::new();
        let updated = read_sudoku_padding(
            &mut "y\n101\n0\n20\n10\n0\n10\n".as_bytes(),
            &mut output,
            &current,
        )
        .unwrap()
        .unwrap();
        assert_eq!((updated.padding_min, updated.padding_max), (0, 10));
        assert_eq!(updated.password, current.password);
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("0–100"));
        assert!(text.contains("不能小于"));
    }

    #[test]
    fn sudoku_menu_defaults_back_toggle_and_password_confirmation() {
        let mut output = Vec::new();
        for (answer, enabled) in [("\n", false), ("n\n", false), ("y\n", true)] {
            let mut reader = answer.as_bytes();
            assert_eq!(
                read_sudoku_prompt(&mut reader, &mut output).unwrap(),
                enabled
            );
        }
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("TCP splice"));
        assert!(text.contains("[y/N]（输入 0 返回）"));
        assert!(input::is_back(
            &read_sudoku_prompt(&mut "0\n".as_bytes(), &mut Vec::new()).unwrap_err()
        ));
        assert!(sudoku_menu_change(None, false, |_, default| {
            assert!(!default);
            Ok(false)
        })
        .unwrap()
        .is_none());
        assert!(matches!(
            sudoku_menu_change(None, false, |_, default| {
                assert!(!default);
                Ok(true)
            })
            .unwrap(),
            Some(ProfileChange::Sudoku(Some(_)))
        ));
        let config = crate::sudoku::SudokuConfig::generated();
        assert!(matches!(
            sudoku_menu_change(Some(&config), false, |_, default| {
                assert!(!default);
                Ok(true)
            })
            .unwrap(),
            Some(ProfileChange::Sudoku(None))
        ));
        assert!(matches!(
            sudoku_menu_change(Some(&config), true, |_, _| panic!("no confirmation")).unwrap(),
            Some(ProfileChange::RegenerateSudokuPassword)
        ));
        assert!(matches!(
            sudoku_menu_change(Some(&config), true, |_, default| {
                assert!(!default);
                Ok(true)
            })
            .unwrap(),
            Some(ProfileChange::RegenerateSudokuPassword)
        ));
        assert!(sudoku_menu_change(None, true, |_, _| panic!("disabled")).is_err());
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
    fn issue_104_protocol_order_labels_and_numeric_mapping() {
        let expected = [
            (Protocol::Reality, "VLESS-REALITY"),
            (Protocol::Hysteria2, "Hysteria2"),
            (Protocol::Shadowsocks, "Shadowsocks"),
            (Protocol::VlessXhttpReality, "VLESS-XHTTP-REALITY"),
            (Protocol::VlessEnc, "VLESS-ENC"),
            (Protocol::NaiveProxy, "NaiveProxy"),
            (Protocol::AnyTls, "AnyTLS"),
            (Protocol::Tuic, "TUIC"),
            (Protocol::VlessTlsVision, "VLESS-TLS-Vision"),
            (Protocol::TrojanTls, "Trojan-TLS"),
            (Protocol::VlessWsTls, "VLESS-WS-TLS"),
            (Protocol::TrojanReality, "Trojan-REALITY"),
            (Protocol::Snell, "Snell v3"),
            (Protocol::VmessWsTls, "VMess-WS-TLS"),
            (Protocol::Socks5, "SOCKS5"),
            (Protocol::VlessSudoku, "VLESS-Sudoku"),
        ];
        assert_eq!(
            Protocol::all().collect::<Vec<_>>(),
            expected.map(|(p, _)| p)
        );
        let mut items = Vec::new();
        for (index, (protocol, label)) in expected.into_iter().enumerate() {
            let number = index + 1;
            assert_eq!(protocol.menu_number(), number);
            assert_eq!(protocol.menu_label(), label);
            assert_eq!(protocol.advanced_label(), label);
            assert_eq!(Protocol::from_menu_number(number), Some(protocol));
            items.push((number, label));
            assert_eq!(
                parse_keyed_choice(&number.to_string(), &protocol_menu_items()),
                Some(number)
            );
        }
        items.push((0, "返回"));
        assert_eq!(protocol_menu_items(), items);
        assert_eq!(parse_keyed_choice("0", &items), Some(0));
        for invalid in ["17", "-1", "abc", ""] {
            assert_eq!(parse_keyed_choice(invalid, &items), None);
        }
        assert_eq!(Protocol::from_menu_number(0), None);
        assert_eq!(Protocol::from_menu_number(17), None);
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
        assert_eq!(Protocol::from_menu_number(14), Some(Protocol::VmessWsTls));
        assert_eq!(Protocol::from_menu_number(15), Some(Protocol::Socks5));
        assert_eq!(Protocol::from_menu_number(13), Some(Protocol::Snell));
        assert_eq!(Protocol::from_menu_number(6), Some(Protocol::NaiveProxy));
        assert_eq!(protocol_items[14], (15, "SOCKS5"));
        assert_eq!(protocol_items[12], (13, "Snell v3"));
    }

    #[test]
    fn snell_new_node_defaults_to_mihomo_verified_cipher_and_keeps_advanced_choices() {
        assert_eq!(SnellCipher::default(), SnellCipher::Aes128Gcm);
        assert_eq!(snell_new_node_choice(""), None);
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
    fn main_menu_numbers_and_labels_match_issue_76() {
        assert_eq!(
            MAIN_MENU_ITEMS,
            &[
                (1, "添加配置"),
                (2, "更改配置"),
                (3, "查看配置"),
                (4, "删除配置"),
                (5, "运行管理"),
                (6, "更新"),
                (7, "卸载"),
                (8, "链式代理"),
                (9, "工具"),
                (10, "帮助与关于"),
                (0, "退出"),
            ]
        );
        let numbers: std::collections::HashSet<_> =
            MAIN_MENU_ITEMS.iter().map(|(number, _)| number).collect();
        let labels: std::collections::HashSet<_> =
            MAIN_MENU_ITEMS.iter().map(|(_, label)| label).collect();
        assert_eq!(numbers.len(), MAIN_MENU_ITEMS.len());
        assert_eq!(labels.len(), MAIN_MENU_ITEMS.len());
    }

    #[test]
    fn tools_menu_order_and_self_update_entry_are_explicit() {
        assert_eq!(
            OPERATIONS_MENU_ITEMS.as_slice(),
            [
                "导出客户端配置",
                "高级添加配置",
                "SNI 检测",
                "SNI 扫描",
                "端口检查",
                "开启 BBR",
                "备份配置",
                "恢复配置",
            ]
        );
        assert!(!OPERATIONS_MENU_ITEMS
            .iter()
            .any(|item| item.contains("更新 ping-rust")));
        assert_eq!(
            UPDATE_CENTER_ITEMS
                .iter()
                .filter(|item| item.contains("更新 ping-rust"))
                .count(),
            1
        );
    }

    #[test]
    fn service_menu_keeps_six_actions_and_appends_logs() {
        assert_eq!(
            SERVICE_MENU_ITEMS,
            [
                "启动",
                "停止",
                "重启",
                "状态",
                "启用并启动",
                "禁用",
                "查看日志"
            ]
        );
    }

    fn summary_profiles() -> Vec<config::ManagedProfile> {
        let reality = config::ManagedProfile {
            h2mux: Default::default(),
            id: uuid::Uuid::nil(),
            name: "reality-20443".into(),
            port: 20443,
            server_address: Some("203.0.113.1".into()),
            credentials: Credentials::Reality {
                user_id: uuid::Uuid::nil(),
                private_key: "test-private-key".into(),
                public_key: "test-public-key".into(),
                short_id: "test-short-id".into(),
                server_name: "sni.example.com".into(),
            },
            certificate_path: None,
            certificate_key_path: None,
            self_signed_certificate: false,
            naive_certificate_validity: None,
        };
        let mut ss = reality.clone();
        ss.name = "ss-31002".into();
        ss.port = 31002;
        ss.credentials = Credentials::Shadowsocks {
            cipher: ShadowsocksCipher::Aes128Gcm2022,
            password: "test-password".into(),
            udp_enabled: true,
            shadowtls: None,
        };
        let mut hy2 = reality.clone();
        hy2.name = "hy2-40001".into();
        hy2.port = 40001;
        hy2.credentials = Credentials::Hysteria2 {
            password: "test-password".into(),
            server_name: "sni.example.com".into(),
            alpn_protocols: vec!["h3".into()],
        };
        vec![reality, ss, hy2]
    }

    #[test]
    fn node_summary_handles_empty_three_and_six_profiles_without_secrets() {
        assert_eq!(
            node_summary(Ok(config::ManagedState::default())),
            "节点 (0):\n暂无节点"
        );
        let mut state = config::ManagedState {
            profiles: summary_profiles(),
            ..Default::default()
        };
        let three = node_summary(Ok(state.clone()));
        assert_eq!(
            three,
            format!(
                "节点 (3):\n• {} - 端口: 20443\n• {} - 端口: 31002\n• {} - 端口: 40001",
                state.profiles[0].protocol_name(),
                state.profiles[1].protocol_name(),
                state.profiles[2].protocol_name(),
            )
        );
        for index in 4..=6 {
            let mut profile = state.profiles[0].clone();
            profile.name = format!("node-{index}");
            profile.port = 20440 + index;
            state.profiles.push(profile);
        }
        let six = node_summary(Ok(state));
        assert!(six.starts_with("节点 (6):\n"));
        assert_eq!(
            six.lines()
                .filter(|line| line.trim_start().starts_with('•'))
                .count(),
            6
        );
        assert!(six.contains("• VLESS-Reality-Vision - 端口: 20445"));
        assert!(six.contains("• VLESS-Reality-Vision - 端口: 20446"));
        assert!(!six.contains("node-"));
        for summary in [three, six] {
            for line in summary.lines() {
                assert!(!line.trim_start().starts_with(|c: char| c.is_ascii_digit()));
            }
            for secret in [
                "00000000-0000-0000-0000-000000000000",
                "test-private-key",
                "test-public-key",
                "test-short-id",
                "test-password",
                "sni.example.com",
                "203.0.113.1",
                "vless://",
                "ss://",
            ] {
                assert!(!summary.contains(secret), "节点摘要泄露了测试凭据");
            }
        }
    }

    #[test]
    fn missing_state_file_means_no_nodes_not_read_failure() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("ping-rust-state.json");
        let state = summary_state(&missing, || anyhow::bail!("读取管理状态失败"));
        assert_eq!(node_summary(state), "节点 (0):\n暂无节点");
        std::fs::write(&missing, "{").unwrap();
        let state = summary_state(&missing, || anyhow::bail!("管理状态 JSON 已损坏"));
        assert_eq!(
            node_summary(state),
            "节点：无法读取（管理状态 JSON 已损坏）"
        );
    }

    #[test]
    fn node_summary_read_failure_is_a_single_notice_line() {
        let output = node_summary(Err(anyhow::anyhow!("管理状态 JSON 已损坏\n请恢复备份")));
        assert_eq!(output, "节点：无法读取（管理状态 JSON 已损坏 请恢复备份）");
        assert_eq!(output.lines().count(), 1);
    }

    #[test]
    fn sni_tool_check_uses_cli_defaults_and_accepts_return() {
        for (text, expected) in [
            ("", vec![]),
            (
                "a.example.com b.example.com",
                vec!["a.example.com", "b.example.com"],
            ),
        ] {
            let crate::sni::Command::Check {
                domains,
                csv,
                subnet,
                protocol,
            } = sni_check_command(text).unwrap()
            else {
                panic!("SNI 检测必须使用命令行 Check");
            };
            assert_eq!(domains, expected);
            assert!(csv.is_none());
            assert!(subnet.is_none());
            assert!(protocol.is_none());
        }
        assert!(sni_check_command("https://example.com").is_err());
        let error = input::read_text(
            &mut io::Cursor::new(b"0\n"),
            &mut Vec::new(),
            "SNI 域名",
            None,
            true,
            sni_check_command,
        )
        .unwrap_err();
        assert!(input::is_back(&error));
        assert_eq!(control_after_error(&error), MenuControl::Continue);
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
    fn all_successful_operations_return_to_main_menu() {
        assert_eq!(control_after_success(1), MenuControl::Continue);
        assert_eq!(control_after_success(3), MenuControl::Continue);
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
