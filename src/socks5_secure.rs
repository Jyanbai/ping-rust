//! 加固命令：持锁提交、激活、探测以及配置/防火墙/服务的补偿事务。
use std::{
    io,
    net::SocketAddr,
    ops::AsyncFnOnce,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
};
use uuid::Uuid;

use crate::{
    config::{
        socks5_secure::{SecureMode, SecurePlan},
        Credentials, ManagedProfile,
    },
    service::Systemctl,
    utils,
};

mod firewall;
#[cfg(test)]
mod tests;

#[derive(Default)]
pub(crate) struct Interrupt {
    phase: Mutex<InterruptPhase>,
}

#[derive(Default, PartialEq, Eq)]
enum InterruptPhase {
    #[default]
    Idle,
    Applying,
    Interrupted(ShutdownSignal),
    ExitRequested(ShutdownSignal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShutdownSignal {
    Interrupt,
    #[cfg(unix)]
    Terminate,
    #[cfg(unix)]
    Hangup,
}

impl ShutdownSignal {
    pub(crate) fn exit_code(self) -> i32 {
        match self {
            Self::Interrupt => 130,
            #[cfg(unix)]
            Self::Terminate => 143,
            #[cfg(unix)]
            Self::Hangup => 129,
        }
    }
}

impl std::fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Interrupt => "SIGINT",
            #[cfg(unix)]
            Self::Terminate => "SIGTERM",
            #[cfg(unix)]
            Self::Hangup => "SIGHUP",
        };
        write!(f, "收到 {name}，已取消 SOCKS5 加固")
    }
}

impl std::error::Error for ShutdownSignal {}

pub(crate) static INTERRUPT: Interrupt = Interrupt {
    phase: Mutex::new(InterruptPhase::Idle),
};

impl Interrupt {
    pub(crate) fn defer_signal(&self, signal: ShutdownSignal) -> bool {
        let mut phase = self.phase.lock().unwrap();
        match *phase {
            InterruptPhase::Idle => {
                // 退出动作在锁外执行，先禁止另一个线程开始写盘。
                *phase = InterruptPhase::ExitRequested(signal);
                false
            }
            InterruptPhase::Applying => {
                *phase = InterruptPhase::Interrupted(signal);
                true
            }
            InterruptPhase::Interrupted(_) => true,
            InterruptPhase::ExitRequested(_) => false,
        }
    }

    pub(crate) fn pending_signal(&self) -> Option<ShutdownSignal> {
        self.phase.lock().unwrap().pending_signal()
    }

    fn begin(&self) -> Result<InterruptGuard<'_>> {
        let mut phase = self.phase.lock().unwrap();
        if let Some(signal) = phase.pending_signal() {
            return Err(interrupted(signal));
        }
        if *phase == InterruptPhase::Applying {
            bail!("SOCKS5 加固事务已在执行");
        }
        *phase = InterruptPhase::Applying;
        Ok(InterruptGuard { interrupt: self })
    }
}

impl InterruptPhase {
    fn pending_signal(&self) -> Option<ShutdownSignal> {
        match *self {
            Self::Interrupted(signal) | Self::ExitRequested(signal) => Some(signal),
            Self::Applying | Self::Idle => None,
        }
    }
}

pub(crate) struct InterruptGuard<'a> {
    interrupt: &'a Interrupt,
}

impl InterruptGuard<'_> {
    fn check(&self) -> Result<()> {
        if let Some(signal) = self.interrupt.pending_signal() {
            return Err(interrupted(signal));
        }
        Ok(())
    }

    pub(crate) async fn cancelled(&self) -> anyhow::Error {
        loop {
            if let Err(error) = self.check() {
                return error;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn finish(&self, publish_state: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut phase = self.interrupt.phase.lock().unwrap();
        if let Some(signal) = phase.pending_signal() {
            return Err(interrupted(signal));
        }
        publish_state()?;
        *phase = InterruptPhase::Idle;
        Ok(())
    }
}

impl Drop for InterruptGuard<'_> {
    fn drop(&mut self) {
        let mut phase = self.interrupt.phase.lock().unwrap();
        if matches!(
            *phase,
            InterruptPhase::Applying | InterruptPhase::Interrupted(_)
        ) {
            *phase = InterruptPhase::Idle;
        }
    }
}

fn interrupted(signal: ShutdownSignal) -> anyhow::Error {
    io::Error::new(io::ErrorKind::Interrupted, signal).into()
}

pub(crate) async fn run(
    directory: &Path,
    id: Uuid,
    mode: Option<SecureMode>,
    is_active: impl FnOnce() -> Result<bool>,
    verify_runtime: impl AsyncFnOnce(&ManagedProfile) -> Result<()>,
) -> Result<()> {
    if let Some(profile) = SecurePlan::secure_profile(directory, id)? {
        verify_runtime(&profile)
            .await
            .context("磁盘配置已加固，运行态验证失败，请检查 shoes.service、监听及认证后重试")?;
        println!("节点 {} 已安全，无需修复", profile.name);
        return Ok(());
    }
    let mode = mode.context("节点配置已变化，请明确指定 --auth 或 --local 后重试")?;
    let mut plan =
        SecurePlan::prepare(directory, id, mode)?.context("节点配置已变化，请重试以验证运行态")?;
    if !is_active()? {
        bail!("shoes.service 未处于 active 状态，无法验证加固后的监听和认证。请按现有 unit 启动服务后重试");
    }
    let mut runtime = SystemRuntime {
        mode,
        firewall: firewall::FirewallPlan::default(),
        listeners: OtherListeners::default(),
        other_socks5_profiles: plan.other_socks5_profiles().cloned().collect(),
        managed_config: directory.join("config.yaml"),
        active_companions: Vec::new(),
        rollback_stop: None,
    };
    apply(&mut plan, &mut runtime, &INTERRUPT).await?;
    if mode == SecureMode::Auth {
        println!("认证已生效；远端客户端必须更新以下凭据。");
        match crate::client::stored_share_uri(&plan.profile, None) {
            Ok(uri) => crate::cli::print_profile_details_with_qr(&plan.profile, Some(&uri)),
            Err(_) => {
                crate::cli::print_profile_details_with_qr(&plan.profile, None);
                println!("节点未保存客户端地址；请使用 prs url {} --server-address <服务器地址> 导出链接。", plan.profile.id);
            }
        }
    } else {
        println!("节点已收紧为回环监听。");
        print!("{}", runtime.firewall.closure_report());
    }
    Ok(())
}

pub(crate) trait Runtime {
    async fn preflight(
        &mut self,
        plan: &SecurePlan,
        interrupt: &InterruptGuard<'_>,
    ) -> Result<Option<Uuid>>;
    async fn activate(&mut self) -> Result<()>;
    async fn verify(&mut self, profile: &ManagedProfile) -> Result<()>;
    async fn close_firewall(&mut self) -> Result<()>;
    async fn restore_firewall(&mut self) -> Result<()>;
    async fn stop_service(&mut self) -> Result<()>;
    async fn prepare_service_rollback(&mut self, _plan: &SecurePlan) -> Result<()> {
        Ok(())
    }
    async fn restore_service(&mut self, original: &ManagedProfile) -> Result<()>;
}

pub(crate) async fn apply(
    plan: &mut SecurePlan,
    runtime: &mut impl Runtime,
    interrupt: &Interrupt,
) -> Result<()> {
    // 防火墙修改结束后再根据实际状态补偿，服务等待可主动取消。
    let interrupt = interrupt.begin()?;
    let preflight = runtime.preflight(plan, &interrupt).await;
    interrupt.check()?;
    plan.original_invocation = preflight?;
    plan.commit_files()?;
    let mut activation_attempted = false;
    let change = async {
        interrupt.check()?;
        activation_attempted = true;
        tokio::select! {
            biased;
            error = interrupt.cancelled() => return Err(error),
            result = runtime.activate() => result.context("重启 shoes 失败")?,
        }
        interrupt.check()?;
        runtime
            .verify(&plan.profile)
            .await
            .context("验证监听或认证失败")?;
        plan.verify_config(false)?;
        interrupt.check()?;
        runtime
            .close_firewall()
            .await
            .context("关闭原防火墙规则失败")?;
        interrupt.check()?;
        runtime
            .verify(&plan.profile)
            .await
            .context("防火墙变更后验证失败")?;
        plan.verify_config(false)?;
        interrupt.finish(|| plan.publish_state())
    }
    .await;
    if let Err(error) = change {
        let mut failures = Vec::new();
        let firewall_restored = if let Err(error) = runtime.restore_firewall().await {
            failures.push(format!("防火墙={error:#}"));
            false
        } else {
            true
        };
        // 未恢复防火墙时，先停服再恢复旧配置，避免热重载重新开放原无认证监听。
        let can_restore_config = if activation_attempted && !firewall_restored {
            match runtime.stop_service().await {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("停止 shoes={error:#}"));
                    false
                }
            }
        } else {
            true
        };
        if activation_attempted && firewall_restored {
            if let Err(error) = runtime.prepare_service_rollback(plan).await {
                failures.push(format!("回滚停止钩子状态={error:#}"));
            }
        }
        let config_restored = if can_restore_config {
            if let Err(error) = plan.rollback_files() {
                failures.push(format!("配置={error:#}"));
                false
            } else {
                true
            }
        } else {
            // 停止钩子也可能修改聚合配置。只在候选配置仍一致时发布状态。
            if let Err(error) = plan.verify_config(false).and_then(|_| plan.publish_state()) {
                failures.push(format!("确认并保存保留的加固状态={error:#}"));
            } else {
                failures.push("为避免重新暴露原监听，暂保留加固配置".to_owned());
            }
            false
        };
        if config_restored && activation_attempted && firewall_restored {
            if let Err(error) = plan.mark_config_restored() {
                failures.push(format!("回滚启动钩子状态={error:#}"));
            }
            if let Err(error) = runtime
                .restore_service(&plan.original)
                .await
                .and_then(|_| plan.verify_config(true))
            {
                failures.push(format!("服务及原监听验证={error:#}"));
            }
        }
        if config_restored && failures.is_empty() {
            if let Err(error) = plan.finish_pending() {
                failures.push(format!("事务状态={error:#}"));
            }
        }
        let error = if crate::is_interrupted(&error) {
            error
        } else if let Err(signal) = interrupt.check() {
            signal.context(format!("{error:#}"))
        } else {
            error
        };
        if failures.is_empty() {
            if !activation_attempted {
                return Err(error.context("SOCKS5 加固已取消，原配置已恢复"));
            }
            return Err(error.context("SOCKS5 加固失败；原配置、防火墙及服务已恢复并再次验证"));
        }
        return Err(error.context(format!(
            "SOCKS5 加固失败，回滚不完整，请检查配置和 systemctl status shoes：{}",
            failures.join("；")
        )));
    }
    Ok(())
}

struct SystemRuntime {
    mode: SecureMode,
    firewall: firewall::FirewallPlan,
    listeners: OtherListeners,
    other_socks5_profiles: Vec<ManagedProfile>,
    managed_config: PathBuf,
    active_companions: Vec<String>,
    rollback_stop: Option<Result<()>>,
}

#[derive(Default)]
struct OtherListeners {
    tcp: Vec<SocketAddr>,
    quic: Vec<SocketAddr>,
}

impl SystemRuntime {
    async fn verify_other_authentication(&self, phase: &str) -> Result<()> {
        for profile in &self.other_socks5_profiles {
            let address = profile.listen_address()?.parse()?;
            verify_authentication(profile, address)
                .await
                .with_context(|| {
                    format!(
                        "端口 {} 的{phase}认证与受管配置不一致，请先同步 shoes.service 与受管配置",
                        profile.port
                    )
                })?;
        }
        Ok(())
    }

    async fn verify_udp_associations(&self, target: &ManagedProfile, phase: &str) -> Result<()> {
        for profile in std::iter::once(target).chain(&self.other_socks5_profiles) {
            let address = profile.listen_address()?.parse()?;
            match tokio::time::timeout(
                Duration::from_secs(5),
                verify_udp_associate(profile, address),
            )
            .await
            {
                Ok(result) => result,
                Err(error) => Err(error).context("SOCKS5 UDP ASSOCIATE 验证超时"),
            }
            .with_context(|| {
                format!(
                    "端口 {} 的{phase} UDP 设置与受管配置不一致，请先同步 shoes.service 与受管配置",
                    profile.port
                )
            })?;
        }
        Ok(())
    }

    async fn verify_config_source(&self, pid: u32, phase: &str) -> Result<()> {
        crate::service::require_managed_shoes_process(pid, &self.managed_config).with_context(
            || format!("{phase} shoes 进程未使用受管聚合配置；请先同步 shoes.service 与受管配置"),
        )?;
        if Systemctl::SecureTransaction.secure_main_pid().await? != Some(pid) {
            bail!("验证配置期间 shoes.service 的 MainPID 已改变，请重试");
        }
        Ok(())
    }
}

impl Runtime for SystemRuntime {
    async fn preflight(
        &mut self,
        plan: &SecurePlan,
        interrupt: &InterruptGuard<'_>,
    ) -> Result<Option<Uuid>> {
        require_tools(utils::command_exists)?;
        interrupt.check()?;
        plan.validate(interrupt).await?;
        let systemctl = Systemctl::SecureTransaction;
        let invocation = systemctl
            .secure_invocation_id()
            .await?
            .context("无法确认正在运行的 shoes.service 实例")?;
        // 重启会替换整个进程，先检查所有配置的服务端监听。
        for (address, quic) in plan.other_listeners() {
            let listeners = if quic {
                &mut self.listeners.quic
            } else {
                &mut self.listeners.tcp
            };
            listeners.push(address.parse().context("受管节点监听地址无效")?);
        }
        let (listener, main_pid) =
            verify_listener(&plan.original, systemctl, Some(&self.listeners))
                .await
                .context(
                    "原监听与受管配置不一致，无法安全回滚；请先同步 shoes.service 与受管配置",
                )?;
        verify_authentication(&plan.original, listener)
            .await
            .context("原认证与受管配置不一致，无法安全回滚；请先同步 shoes.service 与受管配置")?;
        self.verify_other_authentication("原").await?;
        self.verify_config_source(main_pid, "原").await?;
        self.verify_udp_associations(&plan.original, "原").await?;
        if self.mode == SecureMode::Local {
            self.firewall = firewall::FirewallPlan::capture(listener).await?;
        }
        systemctl
            .require_managed_shoes_exec_start(&self.managed_config)
            .await?;
        self.active_companions = systemctl.secure_active_companion_units().await?;
        // 监听探测无法确认非 SOCKS5 节点加载的凭据。还原磁盘也无法恢复旧进程内的配置。
        if plan.has_non_socks5_profiles() {
            systemctl
                .require_config_predates_shoes(&self.managed_config)
                .await?;
        }
        if systemctl.secure_invocation_id().await? != Some(invocation) {
            bail!("预检期间 shoes.service 实例已改变，请重试");
        }
        Ok(Some(invocation))
    }

    async fn activate(&mut self) -> Result<()> {
        Systemctl::SecureTransaction
            .restart_secure_transaction(None)
            .await
    }
    async fn verify(&mut self, profile: &ManagedProfile) -> Result<()> {
        let (expected, main_pid) =
            verify_listener(profile, Systemctl::SecureTransaction, Some(&self.listeners)).await?;
        verify_authentication(profile, expected).await?;
        self.verify_other_authentication("运行态").await?;
        self.verify_config_source(main_pid, "重启后的").await?;
        self.verify_udp_associations(profile, "运行态").await?;
        if Systemctl::SecureTransaction.secure_main_pid().await? != Some(main_pid) {
            bail!("验证 SOCKS5 UDP 期间 shoes.service 的 MainPID 已改变，请重试");
        }
        Ok(())
    }
    async fn close_firewall(&mut self) -> Result<()> {
        self.firewall.close().await
    }
    async fn restore_firewall(&mut self) -> Result<()> {
        self.firewall.restore().await
    }
    async fn stop_service(&mut self) -> Result<()> {
        Systemctl::SecureTransaction.stop_secure_transaction().await
    }
    async fn prepare_service_rollback(&mut self, plan: &SecurePlan) -> Result<()> {
        // 取消 systemctl 客户端并不会撤销它已提交的重启。先发停止作业，
        // 让候选实例的停止钩子在恢复文件之前执行。
        let stop = self.stop_service().await;
        let invocation = if stop.is_ok() {
            Ok(None)
        } else {
            Systemctl::SecureTransaction.secure_invocation_id().await
        };
        self.rollback_stop = Some(stop);
        plan.capture_rollback_stop(invocation)
    }
    async fn restore_service(&mut self, original: &ManagedProfile) -> Result<()> {
        let stop = self.rollback_stop.take().context("缺少回滚停止作业结果")?;
        let systemctl = Systemctl::SecureTransaction;
        systemctl.restart_secure_transaction(Some(stop)).await?;
        systemctl
            .restore_secure_companion_units(&self.active_companions)
            .await?;
        self.verify(original).await
    }
}

pub(crate) fn require_tools(exists: impl Fn(&str) -> bool) -> Result<()> {
    for (tool, package) in [("ss", "iproute2"), ("systemctl", "systemd")] {
        if !exists(tool) {
            bail!("未找到 {tool}，请安装 {package} 后重试");
        }
    }
    Ok(())
}

async fn listener_output(transport: char) -> Result<String> {
    // 分别查询两个地址族，避免 ss 的 `*` 掩盖额外的 IPv6 公网监听。
    let ipv4 = command("ss", &["-H".into(), format!("-l{transport}np4")], None).await?;
    let ipv6 = command("ss", &["-H".into(), format!("-l{transport}np6")], None).await?;
    Ok(format!(
        "{}\n{}",
        ipv4.replace("*:", "0.0.0.0:"),
        ipv6.replace("*:", "[::]:"),
    ))
}

pub(crate) async fn verify(profile: &ManagedProfile) -> Result<()> {
    let (expected, _) = verify_listener(profile, Systemctl::Foreground, None).await?;
    verify_authentication(profile, expected).await
}

async fn verify_authentication(profile: &ManagedProfile, expected: SocketAddr) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        probe(profile, probe_address(expected)),
    )
    .await
    .context("SOCKS5 认证验证超时")??;
    Ok(())
}

fn probe_address(expected: SocketAddr) -> SocketAddr {
    SocketAddr::new(
        if expected.ip().is_unspecified() {
            if expected.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            }
        } else {
            expected.ip()
        },
        expected.port(),
    )
}

async fn verify_listener(
    profile: &ManagedProfile,
    systemctl: Systemctl,
    others: Option<&OtherListeners>,
) -> Result<(SocketAddr, u32)> {
    if !systemctl.secure_is_active().await? {
        bail!("shoes.service 未处于 active 状态");
    }
    let expected: SocketAddr = profile.listen_address()?.parse()?;
    let main_pid = systemctl
        .secure_main_pid()
        .await?
        .context("shoes.service 的 MainPID 不可用")?;
    let output = listener_output('t').await?;
    check_listeners(&output, expected, main_pid)?;
    if let Some(others) = others {
        for &address in &others.tcp {
            check_listeners(&output, address, main_pid)?;
        }
        for local in owned_listeners(&output, main_pid) {
            let address = local
                .parse::<SocketAddr>()
                .context("无法解析 shoes TCP 监听地址")?;
            if address != expected && !others.tcp.contains(&address) {
                bail!("shoes 持有受管配置中没有的 TCP 监听端口 {}", address.port());
            }
        }
        if !others.quic.is_empty() {
            let output = listener_output('u').await?;
            for &address in &others.quic {
                check_listeners(&output, address, main_pid)?;
            }
        }
        if systemctl.secure_main_pid().await? != Some(main_pid) {
            bail!("检查监听期间 shoes.service 的 MainPID 已改变，请重试");
        }
    }
    Ok((expected, main_pid))
}

fn owned_listeners(output: &str, main_pid: u32) -> impl Iterator<Item = &str> {
    let owner = format!(",pid={main_pid},");
    output.lines().filter_map(move |line| {
        // 只校验 shoes 持有的 socket；其他进程可合法占用同端口的不同地址。
        let mut fields = line.split_whitespace();
        let local = fields.nth(3)?;
        fields
            .skip(1)
            .any(|field| field.contains(&owner))
            .then_some(local)
    })
}

pub(crate) fn check_listeners(output: &str, expected: SocketAddr, main_pid: u32) -> Result<()> {
    let mut found = false;
    for local in owned_listeners(output, main_pid) {
        let Some((_, port)) = local.rsplit_once(':') else {
            continue;
        };
        if port.parse::<u16>().ok() != Some(expected.port()) {
            continue;
        }
        let matches = local.parse::<SocketAddr>().ok() == Some(expected);
        if !matches {
            bail!(
                "端口 {} 的实际监听地址不符合预期 {}",
                expected.port(),
                expected
            );
        }
        found = true;
    }
    if !found {
        bail!("未找到 shoes 的预期监听 {expected}；请检查 ss -ltnp 和 shoes 日志");
    }
    Ok(())
}

pub(crate) async fn probe(profile: &ManagedProfile, target: SocketAddr) -> Result<TcpStream> {
    let Credentials::Socks5 {
        username, password, ..
    } = &profile.credentials
    else {
        bail!("非 SOCKS5 节点")
    };
    if username.is_some() {
        let mut anonymous = TcpStream::connect(target).await?;
        anonymous.write_all(&[5, 1, 0]).await?;
        let mut reply = [0; 2];
        match anonymous.read_exact(&mut reply).await {
            Ok(_) if reply == [5, 255] => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            _ => bail!("无凭据连接未被明确拒绝，认证尚未生效"),
        }
    }
    let mut stream = TcpStream::connect(target).await?;
    let authenticated = username.is_some();
    stream
        .write_all(&[5, 1, if authenticated { 2 } else { 0 }])
        .await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, if authenticated { 2 } else { 0 }] {
        bail!("SOCKS5 认证协商失败");
    }
    if let (Some(user), Some(pass)) = (username, password) {
        let mut auth = vec![1, u8::try_from(user.len())?];
        auth.extend_from_slice(user.as_bytes());
        auth.push(u8::try_from(pass.len())?);
        auth.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            bail!("SOCKS5 新凭据验证失败");
        }
    }
    Ok(stream)
}

async fn verify_udp_associate(profile: &ManagedProfile, address: SocketAddr) -> Result<()> {
    let Credentials::Socks5 { udp_enabled, .. } = &profile.credentials else {
        bail!("非 SOCKS5 节点");
    };
    let mut stream = probe(profile, probe_address(address)).await?;
    // 仅请求关联并立即关闭控制连接，不发送 UDP 数据或连接任何目标。
    stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let expected_reply = if *udp_enabled { 0 } else { 7 };
    if header[..3] != [5, expected_reply, 0] {
        bail!("SOCKS5 UDP ASSOCIATE 返回了非预期的应答");
    }
    let address_length = match header[3] {
        1 => 4,
        4 => 16,
        _ => bail!("SOCKS5 UDP ASSOCIATE 返回了无效的地址类型"),
    };
    let mut bound = [0; 18];
    stream.read_exact(&mut bound[..address_length + 2]).await?;
    if *udp_enabled && bound[address_length..address_length + 2] == [0, 0] {
        bail!("SOCKS5 UDP ASSOCIATE 返回了无效的端口");
    }
    Ok(())
}

// 无 shell 插值；所有子进程有超时，stdin 默认关闭。nft 命令通过私有临时文件传入。
async fn command(program: &str, args: &[String], input: Option<&[u8]>) -> Result<String> {
    run_command(program, args, input, None).await
}

async fn run_command(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    xtables_lock_file: Option<&Path>,
) -> Result<String> {
    let output = run_command_output(program, args, input, xtables_lock_file, Stdio::null()).await?;
    if !output.status.success() {
        bail!(
            "{program} 执行失败（{}），请检查该工具的配置",
            output.status
        );
    }
    String::from_utf8(output.stdout).context("命令输出不是 UTF-8")
}

async fn run_command_output(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    xtables_lock_file: Option<&Path>,
    stderr: Stdio,
) -> Result<std::process::Output> {
    use std::io::Write;
    let mut file = input.map(|_| tempfile::tempfile()).transpose()?;
    if let (Some(file), Some(input)) = (&mut file, input) {
        use std::io::{Seek, SeekFrom};
        file.write_all(input)?;
        file.seek(SeekFrom::Start(0))?;
    }
    let mut command = Command::from(utils::isolated_command(program));
    if let Some(path) = xtables_lock_file {
        command.env("XTABLES_LOCKFILE", path);
    }
    let child = command
        .args(args)
        .env("LC_ALL", "C")
        .stdin(file.map(Stdio::from).unwrap_or_else(Stdio::null))
        .stdout(Stdio::piped())
        .stderr(stderr)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("无法执行 {program}，请安装对应工具后重试"))?;
    tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .with_context(|| format!("{program} 执行超时"))?
        .with_context(|| format!("无法读取 {program} 的执行结果"))
}
