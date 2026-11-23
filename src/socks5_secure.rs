//! 加固命令：持锁提交、激活、探测以及配置/防火墙/服务的补偿事务。
use std::{io, net::SocketAddr, path::Path, process::Stdio, sync::Mutex, time::Duration};

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
    service, utils,
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
    Interrupted,
}

pub(crate) static INTERRUPT: Interrupt = Interrupt {
    phase: Mutex::new(InterruptPhase::Idle),
};

impl Interrupt {
    pub(crate) fn defer_signal(&self) -> bool {
        let mut phase = self.phase.lock().unwrap();
        if *phase == InterruptPhase::Idle {
            return false;
        }
        *phase = InterruptPhase::Interrupted;
        true
    }

    fn begin(&self) -> InterruptGuard<'_> {
        *self.phase.lock().unwrap() = InterruptPhase::Applying;
        InterruptGuard { interrupt: self }
    }
}

struct InterruptGuard<'a> {
    interrupt: &'a Interrupt,
}

impl InterruptGuard<'_> {
    fn check(&self) -> Result<()> {
        if *self.interrupt.phase.lock().unwrap() == InterruptPhase::Interrupted {
            return Err(interrupted());
        }
        Ok(())
    }

    fn finish(&self, publish_state: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut phase = self.interrupt.phase.lock().unwrap();
        if *phase == InterruptPhase::Interrupted {
            return Err(interrupted());
        }
        publish_state()?;
        *phase = InterruptPhase::Idle;
        Ok(())
    }
}

impl Drop for InterruptGuard<'_> {
    fn drop(&mut self) {
        *self.interrupt.phase.lock().unwrap() = InterruptPhase::Idle;
    }
}

fn interrupted() -> anyhow::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "收到 SIGINT，已取消 SOCKS5 加固",
    )
    .into()
}

pub(crate) async fn run(directory: &Path, id: Uuid, mode: SecureMode) -> Result<()> {
    let Some(mut plan) = SecurePlan::prepare(directory, id, mode)? else {
        println!("节点已安全，无需修复");
        return Ok(());
    };
    let mut runtime = SystemRuntime {
        mode,
        snapshot: None,
        was_active: false,
        firewall: firewall::FirewallPlan::default(),
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
    async fn preflight(&mut self, plan: &SecurePlan) -> Result<()>;
    async fn activate(&mut self) -> Result<()>;
    async fn verify(&mut self, profile: &ManagedProfile) -> Result<()>;
    async fn close_firewall(&mut self) -> Result<()>;
    async fn restore_firewall(&mut self) -> Result<()>;
    async fn restore_service(&mut self, original: &ManagedProfile) -> Result<()>;
}

pub(crate) async fn apply(
    plan: &mut SecurePlan,
    runtime: &mut impl Runtime,
    interrupt: &Interrupt,
) -> Result<()> {
    runtime.preflight(plan).await?;
    // 等待正在运行的外部操作结束，再根据实际状态补偿。
    let interrupt = interrupt.begin();
    plan.commit_files()?;
    let mut activation_attempted = false;
    let change = async {
        interrupt.check()?;
        activation_attempted = true;
        runtime.activate().await.context("重启 shoes 失败")?;
        interrupt.check()?;
        runtime
            .verify(&plan.profile)
            .await
            .context("验证监听或认证失败")?;
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
        interrupt.finish(|| plan.publish_state())
    }
    .await;
    if let Err(error) = change {
        let mut failures = Vec::new();
        // 每一项都尝试，不能因其中一项失败跳过后续恢复。
        if let Err(error) = plan.rollback() {
            failures.push(format!("配置={error:#}"));
        }
        if let Err(error) = runtime.restore_firewall().await {
            failures.push(format!("防火墙={error:#}"));
        }
        if activation_attempted {
            if let Err(error) = runtime.restore_service(&plan.original).await {
                failures.push(format!("服务及原监听验证={error:#}"));
            }
        }
        let error = if interrupt.check().is_err() && !crate::is_interrupted(&error) {
            interrupted().context(format!("{error:#}"))
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
    snapshot: Option<service::ServiceSnapshot>,
    was_active: bool,
    firewall: firewall::FirewallPlan,
}

impl Runtime for SystemRuntime {
    async fn preflight(&mut self, plan: &SecurePlan) -> Result<()> {
        require_tools(utils::command_exists)?;
        listener_output().await?;
        let snapshot = service::capture_snapshot()?;
        self.was_active = snapshot.was_active();
        self.snapshot = Some(snapshot);
        if self.mode == SecureMode::Local {
            let listener = plan.original.listen_address()?.parse()?;
            self.firewall = firewall::FirewallPlan::capture(listener).await?;
        }
        plan.validate().await
    }

    async fn activate(&mut self) -> Result<()> {
        if self.was_active {
            service::restart_and_verify()
        } else {
            service::activate_and_verify()
        }
    }
    async fn verify(&mut self, profile: &ManagedProfile) -> Result<()> {
        verify(profile).await
    }
    async fn close_firewall(&mut self) -> Result<()> {
        self.firewall.close().await
    }
    async fn restore_firewall(&mut self) -> Result<()> {
        self.firewall.restore().await
    }
    async fn restore_service(&mut self, original: &ManagedProfile) -> Result<()> {
        service::restore_snapshot(self.snapshot.take().context("服务快照已消费")?)?;
        if self.was_active {
            verify(original).await?;
        } else if service::is_active()? {
            bail!("回滚后服务仍处于 active，未恢复原停止状态");
        }
        Ok(())
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

async fn listener_output() -> Result<String> {
    // 分别查询两个地址族，避免 ss 的 `*` 掩盖额外的 IPv6 公网监听。
    let ipv4 = command("ss", &["-H".into(), "-ltnp4".into()], None).await?;
    let ipv6 = command("ss", &["-H".into(), "-ltnp6".into()], None).await?;
    Ok(format!(
        "{}\n{}",
        ipv4.replace("*:", "0.0.0.0:"),
        ipv6.replace("*:", "[::]:"),
    ))
}

async fn verify(profile: &ManagedProfile) -> Result<()> {
    if !service::is_active()? {
        bail!("shoes.service 未处于 active 状态");
    }
    let expected: SocketAddr = profile.listen_address()?.parse()?;
    let main_pid = service::main_pid()?.context("shoes.service 的 MainPID 不可用")?;
    let output = listener_output().await?;
    check_listeners(&output, expected, main_pid)?;
    let target = SocketAddr::new(
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
    );
    tokio::time::timeout(Duration::from_secs(5), probe(profile, target))
        .await
        .context("SOCKS5 认证验证超时")??;
    Ok(())
}

fn check_listeners(output: &str, expected: SocketAddr, main_pid: u32) -> Result<()> {
    let mut found = false;
    let owner = format!(",pid={main_pid},");
    for line in output.lines() {
        // 只校验 shoes 持有的 socket；其他进程可合法占用同端口的不同地址。
        if !line
            .split_whitespace()
            .skip(5)
            .any(|field| field.contains(&owner))
        {
            continue;
        }
        let Some(local) = line.split_whitespace().nth(3) else {
            continue;
        };
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

pub(crate) async fn probe(profile: &ManagedProfile, target: SocketAddr) -> Result<()> {
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
    Ok(())
}

// 无 shell 插值；所有子进程有超时，stdin 默认关闭。nft 命令通过私有临时文件传入。
async fn command(program: &str, args: &[String], input: Option<&[u8]>) -> Result<String> {
    use std::io::Write;
    let mut file = input.map(|_| tempfile::tempfile()).transpose()?;
    if let (Some(file), Some(input)) = (&mut file, input) {
        use std::io::{Seek, SeekFrom};
        file.write_all(input)?;
        file.seek(SeekFrom::Start(0))?;
    }
    let child = Command::from(utils::isolated_command(program))
        .args(args)
        .env("LC_ALL", "C")
        .stdin(file.map(Stdio::from).unwrap_or_else(Stdio::null))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("无法执行 {program}，请安装对应工具后重试"))?;
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .with_context(|| format!("{program} 执行超时"))??;
    if !output.status.success() {
        bail!(
            "{program} 执行失败（{}），请检查该工具的配置",
            output.status
        );
    }
    String::from_utf8(output.stdout).context("命令输出不是 UTF-8")
}
