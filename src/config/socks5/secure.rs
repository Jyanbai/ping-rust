use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{self, Read},
    net::{Ipv4Addr, Ipv6Addr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use super::*;
use crate::service;
#[cfg(target_os = "linux")]
use tokio::signal::unix::{signal, Signal, SignalKind};

#[cfg(test)]
#[path = "secure_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecureMode {
    Auth,
    Local,
}

pub(crate) async fn secure(
    selector: &str,
    dry_run: bool,
    choose: impl FnOnce() -> Result<Option<SecureMode>>,
) -> Result<()> {
    utils::require_linux_root()?;
    let directory = Path::new(utils::CONFIG_DIR);
    let Some((plan, _lock)) = prepare_locked(
        directory,
        selector,
        Path::new(utils::LOCK_FILE),
        dry_run,
        choose,
        verify_running,
    )?
    else {
        return Ok(());
    };
    if dry_run {
        print!("{}", plan.diff(directory));
        return Ok(());
    }

    service::check_socks5_restart_scope()?;
    verify_running(&plan.original).context("无法确认原服务正常，请恢复原监听后重试")?;
    validate_candidate_with_shoes(&plan.runtime, directory)
        .await
        .map_err(|_| {
            anyhow::anyhow!("shoes --dry-run 校验失败，配置未提交；请检查 shoes 安装和当前受管配置")
        })?;

    eprintln!("将重启受管 shoes.service，同机节点的连接可能短暂中断。");
    let mode = plan.mode;
    let profile = commit_with_signal_protection(move || {
        plan.commit(directory, |profile| {
            service::restart_and_verify()?;
            verify_running(profile)
        })
    })
    .await?;
    match mode {
        SecureMode::Auth => {
            println!("SOCKS5 已启用认证，监听地址保持不变。请更新客户端凭据。");
            print_auth_export(&profile);
        }
        SecureMode::Local => {
            println!(
                "SOCKS5 已收紧为 {}，远端连接已不可达。",
                profile.listen_address()?
            );
            println!("如曾对外开放此端口，请另行检查防火墙规则。");
        }
    }
    Ok(())
}

fn prepare_locked(
    directory: &Path,
    selector: &str,
    lock_path: &Path,
    dry_run: bool,
    choose: impl FnOnce() -> Result<Option<SecureMode>>,
    verify_pending: impl FnOnce(&ManagedProfile) -> Result<()>,
) -> Result<Option<(SecurePlan, Option<utils::ExclusiveLock>)>> {
    let load_locked = || {
        let mut lock = utils::try_exclusive_lock(lock_path, !dry_run)?;
        let mut target = SecureTarget::load(directory, selector)?;
        if lock.is_none() && target.profile().socks5_risk_warning().is_none() {
            lock = utils::try_exclusive_lock(lock_path, true)?;
            target = SecureTarget::load(directory, selector)?;
        }
        Ok::<_, anyhow::Error>((target, lock))
    };
    let (before, lock) = load_locked()?;
    let (target, _lock) = if before.profile().socks5_risk_warning().is_some() {
        drop(lock);
        let Some(mode) = choose()? else {
            println!("已取消 SOCKS5 加固。");
            return Ok(None);
        };
        let changed = "所选 SOCKS5 节点已变更，请重新运行加固命令";
        let (after, lock) = load_locked().context(changed)?;
        if before.profile().id != after.profile().id {
            bail!("{changed}");
        }
        if after.profile().socks5_risk_warning().is_some() {
            if !before.matches(&after)? {
                bail!("{changed}");
            }
            return Ok(Some((after.build(mode)?, lock)));
        }
        (after, lock)
    } else {
        (before, lock)
    };
    if target.pending_state {
        if dry_run {
            println!("磁盘上的 SOCKS5 配置已加固，管理状态待同步；预览未验证运行中的服务，也未写入状态。");
            return Ok(None);
        }
        verify_pending(target.profile()).context(
            "磁盘上的 SOCKS5 配置已加固，但未能确认服务已加载；请核对配置、重启 shoes.service 后重试",
        )?;
        save_state_to(&directory.join("ping-rust-state.json"), &target.state)
            .context("已验证运行中的 SOCKS5 加固，但同步管理状态失败，请重试")?;
        println!("SOCKS5 加固已生效，管理状态已同步，无需修复。");
    } else {
        println!("该 SOCKS5 节点已有认证或仅监听回环地址，无需修复。");
    }
    Ok(None)
}

async fn commit_with_signal_protection(
    commit: impl FnOnce() -> Result<ManagedProfile> + Send + 'static,
) -> Result<ManagedProfile> {
    #[cfg(target_os = "linux")]
    let result = {
        let install = |kind| signal(kind).context("无法安装加固信号处理，配置未提交");
        let mut terminate = install(SignalKind::terminate())?;
        let mut hangup = install(SignalKind::hangup())?;
        let mut interrupt = install(SignalKind::interrupt())?;
        let _guard = crate::INTERRUPT_EXIT.lock().await;
        let mut task = tokio::task::spawn_blocking(commit);
        let result = tokio::select! {
            biased;
            (name, code) = next_commit_signal(&mut terminate, &mut hangup, &mut interrupt) => {
                let _ = writeln!(io::stderr(), "收到 {name}，等待 SOCKS5 加固完成或回滚。");
                let _ = match task.await {
                    Ok(Ok(_)) => writeln!(io::stderr(), "SOCKS5 加固已提交并验证，请用 sudo prs info 查看结果。"),
                    Ok(Err(error)) => writeln!(io::stderr(), "{error:#}"),
                    Err(error) => writeln!(io::stderr(), "SOCKS5 配置提交任务异常结束：{error}"),
                };
                exit_after_signal(code);
            }
            result = &mut task => result,
        };
        // Tokio keeps the signal handler installed after dropping the receiver.
        tokio::spawn(async move {
            let (_, code) = next_commit_signal(&mut terminate, &mut hangup, &mut interrupt).await;
            exit_after_signal(code);
        });
        result
    };
    #[cfg(not(target_os = "linux"))]
    let result = tokio::task::spawn_blocking(commit).await;
    result.context("SOCKS5 配置提交任务异常结束")?
}

#[cfg(target_os = "linux")]
async fn next_commit_signal(
    terminate: &mut Signal,
    hangup: &mut Signal,
    interrupt: &mut Signal,
) -> (&'static str, i32) {
    tokio::select! {
        _ = terminate.recv() => ("SIGTERM", 143),
        _ = hangup.recv() => ("SIGHUP", 129),
        _ = interrupt.recv() => ("SIGINT", 130),
    }
}

#[cfg(target_os = "linux")]
fn exit_after_signal(code: i32) -> ! {
    if code == 130 {
        crate::restore_cursor_and_exit();
    }
    std::process::exit(code)
}

struct SecureTarget {
    state: ManagedState,
    servers: Vec<ServerConfig>,
    index: usize,
    document: Option<Vec<u8>>,
    pending_state: bool,
}

impl SecureTarget {
    fn load(directory: &Path, selector: &str) -> Result<Self> {
        let config_path = directory.join("config.yaml");
        let state_path = directory.join("ping-rust-state.json");
        for path in [&config_path, &state_path] {
            commit::read_managed_file(path)?
                .with_context(|| format!("未找到受管配置文件 {}", path.display()))?;
        }
        let mut state = load_state_before_socks5_migration(&state_path)?;
        let original = crate::client::select_profile(&state.profiles, Some(selector))?;
        if original.protocol() != Protocol::Socks5 {
            bail!("所选节点不是 SOCKS5");
        }
        let index = state
            .profiles
            .iter()
            .position(|profile| profile.id == original.id)
            .context("未找到所选 SOCKS5 节点")?;
        let servers = load_servers(&config_path)?;
        let server = servers.get(index).context("聚合配置缺少所选 SOCKS5 节点")?;
        let read_document = |profile: &ManagedProfile| {
            commit::managed_profile_directory_exists(&directory.join("profiles"))?;
            commit::read_managed_file(&profile_path(directory, profile))
        };
        let mut document = None;
        if let Some(recovered) = recover_profile(original, server)? {
            document = read_document(original)?;
            if document.is_some() {
                state.profiles[index] = recovered;
            }
        }
        let pending_state = document.is_some();
        migrate_listen(&mut state, &servers).context("聚合配置与管理状态不一致，无法安全加固")?;
        ensure_chain_proxy_matches_state(&servers, &state)?;
        if state.profiles[index].socks5_risk_warning().is_some() {
            document = read_document(&state.profiles[index])?;
        }
        if let Some(bytes) = &document {
            let on_disk: ServerConfig = crate::yaml::from_slice(bytes)
                .map_err(|_| anyhow::anyhow!("所选 SOCKS5 profile 无法解析"))?;
            if crate::yaml::to_string(&on_disk)? != crate::yaml::to_string(&servers[index])? {
                bail!("所选 SOCKS5 profile 与聚合配置不一致，请先恢复一致后重试");
            }
        }
        Ok(Self {
            state,
            servers,
            index,
            document,
            pending_state,
        })
    }

    fn profile(&self) -> &ManagedProfile {
        &self.state.profiles[self.index]
    }

    fn matches(&self, other: &Self) -> Result<bool> {
        Ok(self.document == other.document
            && serde_json::to_value(self.profile())? == serde_json::to_value(other.profile())?
            && crate::yaml::to_string(&self.servers[self.index])?
                == crate::yaml::to_string(&other.servers[other.index])?)
    }

    fn build(self, mode: SecureMode) -> Result<SecurePlan> {
        let Self {
            mut state,
            mut servers,
            index,
            ..
        } = self;
        let profile = &mut state.profiles[index];
        let original = profile.clone();
        let server = &mut servers[index];
        match mode {
            SecureMode::Auth => {
                apply_profile_change(server, profile, ProfileChange::Socks5Authentication(true))?;
            }
            SecureMode::Local => {
                let address = socket_address(&original)?;
                let loopback = if address.is_ipv4() {
                    "127.0.0.1"
                } else {
                    "::1"
                };
                let Credentials::Socks5 { listen, .. } = &mut profile.credentials else {
                    unreachable!("已验证 SOCKS5 协议");
                };
                *listen = Some(Socks5Listen::new(loopback));
                profile.server_address = Some(loopback.to_owned());
                server.address = profile.listen_address()?;
            }
        }
        let documents = profile_documents(&servers, &state.profiles)?;
        let runtime = commit::aggregate_profile_documents(&documents, &state.profiles)?;
        Ok(SecurePlan {
            mode,
            original,
            state,
            index,
            documents,
            runtime,
        })
    }
}

fn recover_profile(
    original: &ManagedProfile,
    server: &ServerConfig,
) -> Result<Option<ManagedProfile>> {
    let Credentials::Socks5 {
        username: None,
        password: None,
        listen,
        ..
    } = &original.credentials
    else {
        return Ok(None);
    };
    if listen.is_some() && original.socks5_risk_warning().is_none() {
        return Ok(None);
    }
    if listen.is_some() {
        original.validate_socks5_listen()?;
    }
    let ServerProtocol::Socks {
        username, password, ..
    } = &server.protocol
    else {
        return Ok(None);
    };
    let Ok(address) = server.address.parse::<SocketAddr>() else {
        return Ok(None);
    };
    let previous = listen
        .as_ref()
        .map(|_| socket_address(original))
        .transpose()?;
    let (host, _) = server.address.rsplit_once(':').expect("已解析监听地址");
    let mut recovered = original.clone();
    match (username, password) {
        (Some(user), Some(secret))
            if !address.ip().is_loopback()
                && previous.is_none_or(|previous| previous == address) =>
        {
            validate_socks5_component("用户名", user)?;
            validate_socks5_component("密码", secret)?;
        }
        (None, None)
            if matches!(host, "127.0.0.1" | "[::1]")
                && previous.is_none_or(|previous| previous.is_ipv4() == address.is_ipv4()) =>
        {
            recovered.server_address = Some(host.trim_matches(['[', ']']).to_owned());
        }
        _ => return Ok(None),
    }
    let Credentials::Socks5 {
        listen,
        username: stored_user,
        password: stored_password,
        ..
    } = &mut recovered.credentials
    else {
        unreachable!("已验证 SOCKS5 协议");
    };
    *listen = Some(Socks5Listen::new(host.trim_matches(['[', ']'])));
    stored_user.clone_from(username);
    stored_password.clone_from(password);
    Ok(Some(recovered))
}

struct SecurePlan {
    mode: SecureMode,
    original: ManagedProfile,
    state: ManagedState,
    index: usize,
    documents: BTreeMap<String, Vec<u8>>,
    runtime: String,
}

impl SecurePlan {
    fn profile(&self) -> &ManagedProfile {
        &self.state.profiles[self.index]
    }

    fn diff(&self, directory: &Path) -> String {
        let mut output = String::new();
        let filename = self.profile().config_file_name();
        let original = socket_address(&self.original).expect("已验证原监听");
        let before = if original.ip().is_unspecified() {
            original.to_string()
        } else {
            format!("<已脱敏>:{}", original.port())
        };
        let after = self.profile().listen_address().expect("已验证新监听");
        if !profile_path(directory, self.profile()).exists() {
            writeln!(output, "将从原聚合条目创建缺失的 profile {filename}。").unwrap();
        }
        for path in [format!("profiles/{filename}"), "config.yaml".to_owned()] {
            writeln!(
                output,
                "--- {path}\n+++ {path}\n@@ SOCKS5 端口 {} @@",
                self.original.port
            )
            .unwrap();
            match self.mode {
                SecureMode::Auth => {
                    writeln!(output, "  address: {before}\n  protocol:\n    type: socks\n+    username: <已脱敏>\n+    password: <已脱敏>").unwrap();
                }
                SecureMode::Local => {
                    writeln!(output, "- address: {before}\n+ address: {after}").unwrap();
                }
            }
        }
        for name in self.documents.keys().filter(|name| **name != filename) {
            if !directory.join("profiles").join(name).exists() {
                writeln!(
                    output,
                    "将从聚合配置补齐缺失的 profiles/{name}（省略内容）。"
                )
                .unwrap();
            }
        }
        output
    }

    fn commit(
        self,
        directory: &Path,
        mut restart_and_verify: impl FnMut(&ManagedProfile) -> Result<()>,
    ) -> Result<ManagedProfile> {
        let profile = self.profile();
        commit::commit_profile_with_activation(
            directory,
            &self.documents,
            &profile.config_file_name(),
            &self.runtime,
            &self.state,
            |restore| restart_and_verify(if restore { &self.original } else { profile }),
        )?;
        Ok(profile.clone())
    }
}

fn profile_path(directory: &Path, profile: &ManagedProfile) -> PathBuf {
    directory.join("profiles").join(profile.config_file_name())
}

fn print_auth_export(profile: &ManagedProfile) {
    if let Ok(uri) = crate::client::stored_share_uri(profile, None) {
        println!("{uri}");
        return;
    }
    if let Credentials::Socks5 {
        username: Some(username),
        password: Some(password),
        ..
    } = &profile.credentials
    {
        println!(
            "请填入客户端可达的服务器地址，端口 {}，用户名 {username}，密码 {password}。",
            profile.port
        );
        println!(
            "生成分享链接：sudo prs url {} --server-address <服务器地址>",
            profile.id
        );
    }
}

fn socket_address(profile: &ManagedProfile) -> Result<SocketAddr> {
    profile
        .listen_address()?
        .parse()
        .context("SOCKS5 监听地址无效")
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

fn verify_running(profile: &ManagedProfile) -> Result<()> {
    if !service::is_active()? {
        bail!("shoes.service 未处于 active 状态");
    }
    let pid = service::main_pid()?.context("shoes.service 缺少 MainPID")?;
    let expected = socket_address(profile)?;
    wait_for_listener(expected, pid)?;
    let mut target = expected;
    if target.ip().is_unspecified() {
        target.set_ip(if target.is_ipv4() {
            Ipv4Addr::LOCALHOST.into()
        } else {
            Ipv6Addr::LOCALHOST.into()
        });
    }
    verify_socks5_handshake(target, profile)?;
    if !service::is_active()? || service::main_pid()? != Some(pid) {
        bail!("监听验证过程中 shoes.service 退出或重启");
    }
    Ok(())
}

fn wait_for_listener(expected: SocketAddr, pid: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if service::has_exclusive_tcp_listener(pid, expected)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("无法确认 shoes 主进程独占 TCP 监听 {expected}；请检查端口或绑定冲突");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn connect_probe(target: SocketAddr, method: u8) -> Result<TcpStream> {
    let mut stream =
        TcpStream::connect_timeout(&target, PROBE_TIMEOUT).context("无法连接 SOCKS5 监听地址")?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT))?;
    stream
        .write_all(&[5, 1, method])
        .context("发送 SOCKS5 方法协商失败")?;
    Ok(stream)
}

fn verify_socks5_handshake(target: SocketAddr, profile: &ManagedProfile) -> Result<TcpStream> {
    let mut stream = connect_probe(target, 0)?;
    let mut reply = [0; 2];
    if let Credentials::Socks5 {
        username: Some(username),
        password: Some(password),
        ..
    } = &profile.credentials
    {
        match stream.read_exact(&mut reply) {
            Ok(()) if reply == [5, 255] => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) => {}
            Ok(()) => bail!("SOCKS5 未拒绝无凭据客户端"),
            Err(error) => return Err(error).context("验证 SOCKS5 无凭据连接被拒失败"),
        }
        stream = connect_probe(target, 2)?;
        stream
            .read_exact(&mut reply)
            .context("读取 SOCKS5 认证协商响应失败")?;
        if reply != [5, 2] {
            bail!("SOCKS5 未启用用户名密码认证");
        }
        let mut auth = vec![1, u8::try_from(username.len())?];
        auth.extend_from_slice(username.as_bytes());
        auth.push(u8::try_from(password.len())?);
        auth.extend_from_slice(password.as_bytes());
        stream
            .write_all(&auth)
            .context("发送 SOCKS5 认证请求失败")?;
        stream
            .read_exact(&mut reply)
            .context("读取 SOCKS5 认证结果失败")?;
        if reply != [1, 0] {
            bail!("SOCKS5 拒绝了新凭据");
        }
    } else {
        stream
            .read_exact(&mut reply)
            .context("读取 SOCKS5 回环或原服务协商响应失败")?;
        if reply != [5, 0] {
            bail!("SOCKS5 未接受预期的本地或原无认证连接");
        }
    }
    Ok(stream)
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn listener_check_works_without_external_commands() {
        const CHILD: &str = "PING_RUST_TEST_SOCKS5_LISTENER_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let expected = "127.0.0.1:1080".parse().unwrap();
            let error = wait_for_listener(expected, u32::MAX).unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("/proc/{}/fd", u32::MAX)),
                "{message}"
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::socks5::secure::listener_tests::listener_check_works_without_external_commands",
            ])
            .env(CHILD, "1")
            .env("PATH", "")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
