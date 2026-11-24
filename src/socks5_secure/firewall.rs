//! 按原监听地址和 TCP 端口清理专用放行规则。
use super::*;
use serde_json::{json, Value};
use std::{net::IpAddr, ops::Range};

trait FirewallExecutor {
    fn available(&self, program: &str) -> bool;
    async fn with_xtables_lock<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        operation(self).await
    }
    fn ufw_rules_file(&self, v6: bool) -> Result<String> {
        let path = ufw_rules_path(v6);
        std::fs::read_to_string(path)
            .with_context(|| format!("无法读取 UFW 内部规则 {}", path.display()))
    }
    fn replace_ufw_rules_file(&mut self, v6: bool, before: &str, after: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            replace_ufw_rules_file(
                ufw_rules_path(v6),
                Path::new("/run/ufw.lock"),
                before,
                after,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (v6, before, after);
            bail!("只能在 Linux 上更新 UFW 持久规则");
        }
    }
    async fn execute(
        &mut self,
        program: &str,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<String>;
}

#[cfg(target_os = "linux")]
fn replace_ufw_rules_file(path: &Path, lock_path: &Path, before: &str, after: &str) -> Result<()> {
    use rustix::fs::{fcntl_lock, open, FlockOperation, Mode, OFlags};
    use std::{
        fs,
        io::Write,
        os::unix::fs::{fchown, MetadataExt},
    };

    // ufw 使用 lockf 锁定 /run/ufw.lock。进程级 flock 与这个 POSIX 记录锁互不协调。
    let lock = open(
        lock_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .with_context(|| format!("无法打开 UFW 锁 {}", lock_path.display()))?;
    fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive)
        .context("无法取得 UFW 写锁，请等待其他防火墙操作完成后重试")?;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("无法读取 UFW 持久规则 {} 的元数据", path.display()))?;
    if !metadata.is_file() {
        bail!("UFW 持久规则 {} 不是普通文件，请检查防火墙", path.display());
    }
    let mut candidate =
        tempfile::NamedTempFile::new_in(path.parent().context("UFW 规则路径没有父目录")?)
            .context("无法创建 UFW 持久规则候选文件")?;
    candidate
        .write_all(after.as_bytes())
        .context("无法写入 UFW 持久规则候选文件")?;
    fchown(
        candidate.as_file(),
        Some(metadata.uid()),
        Some(metadata.gid()),
    )
    .context("无法保留 UFW 持久规则的所有者和组")?;
    candidate
        .as_file()
        .set_permissions(metadata.permissions())
        .context("无法保留 UFW 持久规则权限")?;
    candidate
        .as_file()
        .sync_all()
        .context("无法同步 UFW 持久规则候选文件")?;
    let current = fs::read_to_string(path)
        .with_context(|| format!("无法读取 UFW 内部规则 {}", path.display()))?;
    if current != before {
        bail!("UFW 持久规则已并发修改，请检查后重试");
    }
    candidate
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("无法更新 UFW 持久规则 {}", path.display()))?;
    Ok(())
}

#[derive(Default)]
struct SystemFirewall {
    xtables_lock_file: Option<std::path::PathBuf>,
}

impl FirewallExecutor for SystemFirewall {
    fn available(&self, program: &str) -> bool {
        utils::command_exists(program)
    }

    #[cfg(target_os = "linux")]
    async fn with_xtables_lock<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};

        let lock_path =
            std::env::var_os("XTABLES_LOCKFILE").unwrap_or_else(|| "/run/xtables.lock".into());
        let lock = open(
            lock_path,
            OFlags::RDONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .context("无法打开 xtables 锁，请检查防火墙")?;
        let acquire = async {
            loop {
                match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                    Err(rustix::io::Errno::WOULDBLOCK) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    result => return result,
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(15), acquire)
            .context("等待 xtables 写锁超时，请检查防火墙")?
            .context("无法取得 xtables 写锁，请检查防火墙")?;
        // 父进程持有系统锁；同一事务的子进程使用私有锁，避免再次等待系统锁。
        let private_lock = tempfile::NamedTempFile::new().context("无法创建 xtables 私有锁")?;
        let mut backend = Self {
            xtables_lock_file: Some(private_lock.path().to_owned()),
        };
        let result = operation(&mut backend).await;
        drop(lock);
        result
    }

    async fn execute(
        &mut self,
        program: &str,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<String> {
        run_command(program, args, input, self.xtables_lock_file.as_deref()).await
    }
}

#[derive(Default)]
pub(super) struct FirewallPlan {
    rules: Vec<Rule>,
    attempted: Vec<Attempt>,
    listener: Option<SocketAddr>,
}

enum Rule {
    Ufw {
        text: String,
        listener: SocketAddr,
    },
    Rich {
        base: Vec<String>,
        text: String,
    },
    Iptables {
        program: &'static str,
        text: String,
    },
    Nft {
        spec: Value,
        chain_handle: u64,
        may_use_netfilter_persistent: bool,
    },
}

// 只记录已发起删除的规则。原顺序用于定位恢复点，不用于恢复整条链。
struct Attempt {
    rule: usize,
    before: Vec<LiveRule>,
    position: usize,
    ufw: Option<UfwAttempt>,
}

struct UfwAttempt {
    file: UfwFile,
    entry: Range<usize>,
    kernel: Vec<LiveRule>,
    kernel_position: usize,
}

#[derive(PartialEq, Eq)]
struct LiveRule {
    text: String,
    handle: Option<u64>,
}

impl From<&str> for LiveRule {
    fn from(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            handle: None,
        }
    }
}

impl FirewallPlan {
    pub(super) async fn capture(listener: SocketAddr) -> Result<Self> {
        Self::capture_with(listener, &mut SystemFirewall::default()).await
    }

    async fn capture_with(
        listener: SocketAddr,
        backend: &mut impl FirewallExecutor,
    ) -> Result<Self> {
        let mut plan = Self {
            listener: Some(listener),
            ..Self::default()
        };
        let mut managed_ufw = false;
        if backend.available("ufw") {
            let status = ufw_status(backend).await?;
            if status.contains("Status: active") {
                managed_ufw = true;
                for line in status.lines() {
                    if ufw_rule_number(line, listener).is_some() {
                        let (_, text) = ufw_entry(line).context("无法解析 UFW 规则")?;
                        let rule = Rule::Ufw {
                            text: text.to_owned(),
                            listener,
                        };
                        rule.current(backend).await?;
                        plan.rules.push(rule);
                    }
                }
            }
        }
        let managed_firewalld = if backend.available("firewall-cmd") {
            service_running(backend, "firewalld.service").await?
        } else {
            false
        };
        let runtime_rich_rules = if managed_firewalld {
            let permanent = capture_firewalld(backend, listener, &["--permanent".into()]).await?;
            let runtime = capture_firewalld(backend, listener, &[]).await?;
            for rule in &runtime {
                let Rule::Rich { base, text } = rule else {
                    unreachable!()
                };
                let permanent_base = permanent_rich_base(base);
                if !permanent.iter().any(|rule| {
                    matches!(rule, Rule::Rich { base, text: persisted } if base == &permanent_base && persisted == text)
                }) {
                    bail!("firewalld 区域 {} 有匹配 TCP 端口 {} 的纯运行时 rich rule，无法查询其剩余超时并安全回滚。请先检查并手动处理该规则后重试", base[0], listener.port());
                }
            }
            plan.rules.extend(permanent);
            runtime
        } else {
            Vec::new()
        };
        let (program, family) = if listener.is_ipv4() {
            ("iptables", "ip")
        } else {
            ("ip6tables", "ip6")
        };
        let has_iptables = backend.available(program);
        let iptables_nft = has_iptables
            && backend
                .execute(program, &["--version".into()], None)
                .await?
                .contains("(nf_tables)");
        let has_nft = backend.available("nft");
        if iptables_nft && !has_nft {
            bail!("{program} 使用 nf_tables，请安装 nftables 后重试");
        }
        // nft 同时处理兼容规则和同一张表里的原生规则，按 handle 只删除一次。
        // UFW 和 firewalld 分别处理其受管规则。
        if has_nft {
            let items = nft_list(backend, json!({"ruleset": null})).await?;
            for item in &items {
                let rule = &item["rule"];
                let table = rule["table"].as_str().unwrap_or_default();
                if (managed_firewalld && table == "firewalld")
                    || (managed_ufw && table.starts_with("ufw"))
                {
                    continue;
                }
                if nft_input_port_allow(rule, &items, listener) {
                    rule["handle"].as_u64().context("nft rule 缺少 handle")?;
                    let chain_handle = items
                        .iter()
                        .map(|item| &item["chain"])
                        .find(|chain| nft_same_chain(chain, rule))
                        .and_then(|chain| chain["handle"].as_u64())
                        .context("nft input 链缺少 handle")?;
                    plan.rules.push(Rule::Nft {
                        spec: rule.clone(),
                        chain_handle,
                        may_use_netfilter_persistent: iptables_nft
                            && rule["family"] == family
                            && matches!(table, "filter" | "nat" | "mangle" | "raw" | "security"),
                    });
                }
            }
        }
        if has_iptables && !iptables_nft {
            for rule in iptables_input(backend, program).await?.lines() {
                if iptables_delete_args(rule, listener).is_some() {
                    plan.rules.push(Rule::Iptables {
                        program,
                        text: rule.to_owned(),
                    });
                }
            }
        }
        // 限时规则无法原样补回。等其他防火墙修改成功后再删除运行态 rich rule。
        plan.rules.extend(runtime_rich_rules);
        Ok(plan)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        self.close_with(&mut SystemFirewall::default()).await
    }

    async fn close_with(&mut self, backend: &mut impl FirewallExecutor) -> Result<()> {
        for (index, rule) in self.rules.iter().enumerate() {
            let before = rule.current(backend).await?;
            if let Some(position) = rule.position(&before) {
                if let Rule::Rich { base, text } = rule {
                    if !rich_is_permanent(base) {
                        let permanent_base = permanent_rich_base(base);
                        if !self.attempted.iter().any(|attempt| {
                            matches!(&self.rules[attempt.rule], Rule::Rich { base, text: persisted }
                                if base == &permanent_base && persisted == text)
                        }) {
                            bail!("firewalld 运行时 rich rule 已无对应持久规则，无法安全修改，请检查防火墙");
                        }
                    }
                }
                let ufw = match rule {
                    Rule::Ufw { listener, .. } => {
                        Some(UfwAttempt::capture(backend, *listener, &before, position).await?)
                    }
                    _ => None,
                };
                // 超时或失败也可能已经改动了规则，回滚时先重新查询。
                self.attempted.push(Attempt {
                    rule: index,
                    before,
                    position,
                    ufw,
                });
                rule.delete(backend, self.attempted.last().unwrap()).await?;
            }
        }
        if let Some(listener) = self.listener {
            if !Self::capture_with(listener, backend)
                .await?
                .rules
                .is_empty()
            {
                bail!("防火墙仍有匹配原监听地址和 TCP 端口的专用放行规则，请检查并重试");
            }
        }
        Ok(())
    }

    pub(super) async fn restore(&mut self) -> Result<()> {
        self.restore_with(&mut SystemFirewall::default()).await
    }

    async fn restore_with(&mut self, backend: &mut impl FirewallExecutor) -> Result<()> {
        let mut failures = Vec::new();
        while let Some(attempt) = self.attempted.pop() {
            if let Err(error) = self.rules[attempt.rule].restore(backend, &attempt).await {
                failures.push(format!("{error:#}"));
            }
        }
        if !failures.is_empty() {
            bail!("防火墙恢复失败：{}", failures.join("；"));
        }
        Ok(())
    }

    pub(super) fn closure_report(&self) -> String {
        let (mut runtime, mut persistent) = (0, 0);
        let (mut nft, mut iptables) = (false, false);
        for attempt in &self.attempted {
            match &self.rules[attempt.rule] {
                Rule::Ufw { .. } => {
                    runtime += 1;
                    persistent += 1;
                }
                Rule::Rich { base, .. } => {
                    if rich_is_permanent(base) {
                        persistent += 1;
                    } else {
                        runtime += 1;
                    }
                }
                Rule::Nft {
                    may_use_netfilter_persistent,
                    ..
                } => {
                    runtime += 1;
                    nft = true;
                    iptables |= *may_use_netfilter_persistent;
                }
                Rule::Iptables { .. } => {
                    runtime += 1;
                    iptables = true;
                }
            }
        }
        closure_report(runtime, persistent, nft, iptables)
    }
}

fn closure_report(runtime: usize, persistent: usize, nft: bool, iptables: bool) -> String {
    if runtime + persistent == 0 {
        return "未移除防火墙规则。\n".into();
    }
    let mut report =
        format!("已移除 {runtime} 条运行时放行规则，已移除 {persistent} 条持久放行规则。\n");
    if nft {
        report.push_str("原生 nftables 规则仅从运行时移除，重新加载 /etc/nftables.conf 等持久配置后可能恢复。\n");
    }
    if iptables {
        report.push_str("原生 iptables/ip6tables 规则仅从运行时移除，netfilter-persistent 等服务重载后可能恢复。\n");
    }
    report
}

impl Rule {
    async fn current(&self, backend: &mut impl FirewallExecutor) -> Result<Vec<LiveRule>> {
        match self {
            Rule::Ufw { text, listener } => {
                let status = ufw_status(backend).await?;
                if !status.contains("Status: active") {
                    bail!("UFW 已停用，请检查 ufw status");
                }
                let scope = ufw_inbound_scope(text).context("无法解析 UFW 规则范围")?;
                let mut displayed = 0;
                for (_, entry) in status.lines().filter_map(ufw_entry) {
                    if entry != text.as_str() && ufw_inbound_scope(entry) == Some(scope) {
                        bail!("UFW 存在相同范围的其他规则，请检查 ufw status numbered");
                    }
                    displayed += usize::from(entry == text.as_str());
                }
                let live = UfwFile::load(backend, listener.is_ipv6())?.rules;
                let count = live
                    .iter()
                    .filter(|entry| ufw_tuple_allow(&entry.text, *listener))
                    .count();
                if count != displayed || count > 1 {
                    bail!("UFW 显示规则与内部规则无法一一对应，请检查 ufw status numbered 和 user.rules");
                }
                Ok(live)
            }
            Rule::Rich { base, .. } => Ok(list_rich_rules(backend, base)
                .await?
                .lines()
                .map(str::trim)
                .map(LiveRule::from)
                .collect()),
            Rule::Iptables { program, .. } => Ok(iptables_input(backend, program)
                .await?
                .lines()
                .filter(|line| line.starts_with("-A INPUT "))
                .map(LiveRule::from)
                .collect()),
            Rule::Nft {
                spec, chain_handle, ..
            } => {
                let items = nft_list(
                    backend,
                    json!({"chain": {
                        "family": spec["family"], "table": spec["table"], "name": spec["chain"],
                    }}),
                )
                .await?;
                if !items.iter().any(|item| {
                    let chain = &item["chain"];
                    nft_same_chain(chain, spec) && chain["handle"].as_u64() == Some(*chain_handle)
                }) {
                    bail!("nft input 链已变化，请检查防火墙");
                }
                items
                    .iter()
                    .filter_map(|item| item.get("rule"))
                    .map(|rule| {
                        let handle = rule["handle"].as_u64().context("nft rule 缺少 handle")?;
                        let text = nft_rule_key(rule);
                        if rule["handle"] == spec["handle"] && text != nft_rule_key(spec) {
                            bail!("nft 规则已被替换，请检查防火墙");
                        }
                        Ok(LiveRule {
                            text,
                            handle: Some(handle),
                        })
                    })
                    .collect()
            }
        }
    }

    fn position(&self, live: &[LiveRule]) -> Option<usize> {
        match self {
            Rule::Ufw { listener, .. } => live
                .iter()
                .position(|rule| ufw_tuple_allow(&rule.text, *listener)),
            Rule::Rich { text, .. } | Rule::Iptables { text, .. } => {
                live.iter().position(|rule| rule.text == *text)
            }
            Rule::Nft { spec, .. } => live
                .iter()
                .position(|rule| rule.handle == spec["handle"].as_u64()),
        }
    }

    async fn delete(&self, backend: &mut impl FirewallExecutor, attempt: &Attempt) -> Result<()> {
        match self {
            Rule::Ufw { listener, .. } => {
                let ufw = attempt.ufw.as_ref().context("缺少 UFW 规则快照")?;
                ufw.delete(backend, *listener).await?;
            }
            Rule::Rich { base, text } => {
                let mut args = base.clone();
                args.push(format!("--remove-rich-rule={text}"));
                backend.execute("firewall-cmd", &args, None).await?;
            }
            Rule::Iptables { program, text } => {
                delete_iptables_rule(backend, program, text).await?;
            }
            Rule::Nft { spec, .. } => {
                let handle = spec["handle"].as_u64().context("nft rule 缺少 handle")?;
                delete_nft_rule(backend, spec, handle).await?;
            }
        }
        Ok(())
    }

    async fn restore(&self, backend: &mut impl FirewallExecutor, attempt: &Attempt) -> Result<()> {
        if matches!(self, Rule::Iptables { .. }) {
            return backend
                .with_xtables_lock(async |backend| self.restore_rule(backend, attempt).await)
                .await;
        }
        self.restore_rule(backend, attempt).await
    }

    async fn restore_rule(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &Attempt,
    ) -> Result<()> {
        if let Rule::Rich { base, .. } = self {
            if !rich_is_permanent(base) {
                bail!("无法确认 firewalld 运行时 rich rule 的原剩余超时，请检查防火墙");
            }
        }
        let current = self.current(backend).await?;
        if let Rule::Ufw { listener, .. } = self {
            return self
                .restore_ufw(backend, attempt, &current, *listener)
                .await;
        }
        let text = &attempt.before[attempt.position].text;
        let original_count = matching_rule_count(&attempt.before, text);
        let current_count = matching_rule_count(&current, text);
        if current_count >= original_count {
            if !matches!(self, Rule::Rich { .. }) && !contains_rule_order(&attempt.before, &current)
            {
                bail!("原放行规则的相对顺序已变化，请检查防火墙");
            }
            if current
                .iter()
                .position(|rule| rule.text == *text)
                .is_some_and(|position| position < after_new_denials(&attempt.before, &current))
            {
                bail!("原放行规则会覆盖新增拒绝规则，无法确认恢复顺序，请检查防火墙");
            }
            return Ok(());
        }
        if let Rule::Rich { base, text } = self {
            let mut args = base.clone();
            args.push(format!("--add-rich-rule={text}"));
            backend.execute("firewall-cmd", &args, None).await?;
            if matching_rule_count(&self.current(backend).await?, text) <= current_count {
                bail!("原放行规则未恢复，请检查防火墙");
            }
            return Ok(());
        }
        let position = checked_firewall_restore_position(
            &attempt.before,
            attempt.position,
            &current,
            matches!(self, Rule::Iptables { .. }),
        )?;
        match self {
            Rule::Ufw { .. } | Rule::Rich { .. } => unreachable!(),
            Rule::Iptables { program, text } => {
                insert_iptables(backend, program, text, position, current.len()).await?;
                let after = self
                    .current(backend)
                    .await
                    .context("无法复查恢复的 iptables 放行规则")?;
                if let Err(error) = verify_insert_order(&current, &after, position, text) {
                    if let Err(cleanup) = undo_iptables_insert(backend, program, text, &after).await
                    {
                        return Err(
                            error.context(format!("撤销 iptables 放行规则插入失败：{cleanup:#}"))
                        );
                    }
                    return Err(error);
                }
                Ok(())
            }
            Rule::Nft { spec, .. } => {
                let mut rule = spec.clone();
                rule.as_object_mut().unwrap().remove("handle");
                let operation = if let Some(next) = current.get(position) {
                    rule["handle"] = next.handle.context("nft 恢复定位缺少 handle")?.into();
                    json!({"insert": {"rule": rule}})
                } else {
                    json!({"add": {"rule": rule}})
                };
                // 从写入回显取 handle，即使管理员同时加了同样的规则也只撤回本次放行。
                let output = nft_command(backend, operation).await?;
                let handle = nft_items(&output)?
                    .iter()
                    .find_map(|item| {
                        [&item["insert"]["rule"], &item["add"]["rule"]]
                            .into_iter()
                            .find_map(|rule| rule["handle"].as_u64())
                    })
                    .filter(|handle| !current.iter().any(|rule| rule.handle == Some(*handle)))
                    .context("nft 未返回新放行规则的 handle，请检查防火墙")?;
                let mut still_inserted = true;
                let verified = self.current(backend).await.and_then(|after| {
                    still_inserted = after
                        .iter()
                        .any(|rule| rule.handle == Some(handle) && rule.text == *text);
                    verify_insert_order(&current, &after, position, text)?;
                    if after[position].handle != Some(handle) {
                        bail!("无法确认恢复的 nft 放行规则，请检查防火墙");
                    }
                    Ok(())
                });
                if let Err(error) = verified {
                    if !still_inserted {
                        return Err(error);
                    }
                    return Err(match delete_nft_rule(backend, spec, handle).await {
                        Ok(()) => error,
                        Err(cleanup) => {
                            error.context(format!("撤销 nft 放行规则插入失败：{cleanup:#}"))
                        }
                    });
                }
                Ok(())
            }
        }
    }

    async fn restore_ufw(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &Attempt,
        current: &[LiveRule],
        listener: SocketAddr,
    ) -> Result<()> {
        let original = attempt.ufw.as_ref().context("缺少 UFW 规则快照")?;
        if self.position(current).is_none() {
            let position =
                checked_firewall_restore_position(&attempt.before, attempt.position, current, true)
                    .context("无法恢复 UFW 持久规则，请检查 ufw status numbered")?;
            let file = UfwFile::load(backend, listener.is_ipv6())?;
            if file.rules.as_slice() != current {
                bail!("UFW 持久规则已并发修改，请检查后重试");
            }
            let mut restored = file.contents.clone();
            let offset = if file.contents == original.file_without_allow() {
                original.entry.start
            } else {
                file.offsets[position]
            };
            restored.insert_str(offset, &original.file.contents[original.entry.clone()]);
            backend.replace_ufw_rules_file(listener.is_ipv6(), &file.contents, &restored)?;
        }
        let persistent = self.current(backend).await?;
        let position = self
            .position(&persistent)
            .context("UFW 持久规则未恢复，请检查 ufw status numbered")?;
        if !contains_rule_order(&attempt.before, &persistent)
            || position < after_new_denials(&attempt.before, &persistent)
        {
            bail!("UFW 持久规则未恢复原相对顺序，请检查 ufw status numbered");
        }

        let (program, chain) = ufw_kernel_chain(listener);
        let kernel = ufw_kernel_rules(backend, program, chain).await?;
        match ufw_kernel_count(&kernel, listener, chain) {
            0 => {
                // 单独补回目标规则，避免重载整个防火墙。
                let before = &original.kernel;
                let position = checked_firewall_restore_position(
                    before,
                    original.kernel_position,
                    &kernel,
                    true,
                )
                .context("无法恢复 UFW 内核规则")?;
                let text = &before[original.kernel_position].text;
                insert_iptables(backend, program, text, position, kernel.len()).await?;
                let verified = async {
                    let restored = ufw_kernel_rules(backend, program, chain).await?;
                    verify_insert_order(&kernel, &restored, position, text)?;
                    let persistent = self.current(backend).await?;
                    if !contains_rule_order(&attempt.before, &persistent)
                        || self.position(&persistent).is_none_or(|position| {
                            position < after_new_denials(&attempt.before, &persistent)
                        })
                    {
                        bail!("补回内核规则时 UFW 持久规则已变化，请检查 ufw status numbered");
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = verified {
                    let cleanup = async {
                        let live = ufw_kernel_rules(backend, program, chain).await?;
                        undo_iptables_insert(backend, program, text, &live).await
                    }
                    .await;
                    if let Err(cleanup) = cleanup {
                        return Err(
                            error.context(format!("撤销 UFW 内核放行规则插入失败：{cleanup:#}"))
                        );
                    }
                    return Err(error);
                }
                return Ok(());
            }
            1 => {}
            count => bail!("UFW 内核规则数量为 {count}，预期为 1，请检查 ufw show raw"),
        }
        if !contains_rule_order(&original.kernel, &kernel)
            || kernel
                .iter()
                .position(|rule| {
                    iptables_delete_args_in_chain(&rule.text, listener, chain).is_some()
                })
                .is_some_and(|position| position < after_new_denials(&original.kernel, &kernel))
        {
            bail!("UFW 内核规则未恢复原相对顺序，请检查 ufw show raw");
        }
        Ok(())
    }
}

impl UfwAttempt {
    async fn capture(
        backend: &mut impl FirewallExecutor,
        listener: SocketAddr,
        before: &[LiveRule],
        position: usize,
    ) -> Result<Self> {
        let file = UfwFile::load(backend, listener.is_ipv6())?;
        if file.rules != before {
            bail!("UFW 持久规则已并发修改，请检查后重试");
        }
        let (program, chain) = ufw_kernel_chain(listener);
        let entry = file.allow_entry(position, listener, chain)?;
        let kernel = ufw_kernel_rules(backend, program, chain).await?;
        if ufw_kernel_count(&kernel, listener, chain) != 1 {
            bail!("UFW 内核规则与持久规则无法一一对应，请检查 {program} -S {chain}");
        }
        let kernel_position = kernel
            .iter()
            .position(|rule| iptables_delete_args_in_chain(&rule.text, listener, chain).is_some())
            .unwrap();
        Ok(Self {
            file,
            entry,
            kernel,
            kernel_position,
        })
    }

    async fn delete(
        &self,
        backend: &mut impl FirewallExecutor,
        listener: SocketAddr,
    ) -> Result<()> {
        // ufw delete 会重载两族用户链。只编辑目标 tuple 及对应内核规则，保留运行时规则。
        let (program, chain) = ufw_kernel_chain(listener);
        let mut args = vec!["-w".into()];
        args.extend(
            iptables_delete_args_in_chain(&self.kernel[self.kernel_position].text, listener, chain)
                .context("无法解析待删除的 UFW 内核规则")?,
        );
        backend.execute(program, &args, None).await?;
        backend.replace_ufw_rules_file(
            listener.is_ipv6(),
            &self.file.contents,
            &self.file_without_allow(),
        )?;
        let live = ufw_kernel_rules(backend, program, chain).await?;
        if ufw_kernel_count(&live, listener, chain) != 0 {
            bail!("UFW 运行时放行规则未移除，请检查 {program} -S {chain}");
        }
        Ok(())
    }

    fn file_without_allow(&self) -> String {
        let mut updated = self.file.contents.clone();
        updated.replace_range(self.entry.clone(), "");
        updated
    }
}

fn ufw_kernel_chain(listener: SocketAddr) -> (&'static str, &'static str) {
    if listener.is_ipv4() {
        ("iptables", "ufw-user-input")
    } else {
        ("ip6tables", "ufw6-user-input")
    }
}

async fn ufw_kernel_rules(
    backend: &mut impl FirewallExecutor,
    program: &str,
    chain: &str,
) -> Result<Vec<LiveRule>> {
    // ufw status numbered 使用持久配置列出用户规则，可能先于内核更新。
    let output = backend
        .execute(program, &["-w".into(), "-S".into(), chain.into()], None)
        .await
        .with_context(|| format!("无法查询 UFW 内核规则，请检查 {program} -S {chain}"))?;
    Ok(output
        .lines()
        .filter(|line| line.starts_with("-A "))
        .map(LiveRule::from)
        .collect())
}

fn ufw_kernel_count(rules: &[LiveRule], listener: SocketAddr, chain: &str) -> usize {
    rules
        .iter()
        .filter(|rule| iptables_delete_args_in_chain(&rule.text, listener, chain).is_some())
        .count()
}

async fn delete_iptables_rule(
    backend: &mut impl FirewallExecutor,
    program: &str,
    text: &str,
) -> Result<()> {
    let words = shell_words(text);
    let mut args = vec!["-w".into(), "-D".into()];
    args.extend_from_slice(&words[1..]);
    backend.execute(program, &args, None).await?;
    Ok(())
}

async fn undo_iptables_insert(
    backend: &mut impl FirewallExecutor,
    program: &str,
    text: &str,
    live: &[LiveRule],
) -> Result<()> {
    match matching_rule_count(live, text) {
        0 => Ok(()),
        1 => delete_iptables_rule(backend, program, text).await,
        _ => bail!("链中有多条同文放行规则，无法识别本次插入，请检查防火墙"),
    }
}

async fn insert_iptables(
    backend: &mut impl FirewallExecutor,
    program: &str,
    text: &str,
    position: usize,
    current_len: usize,
) -> Result<()> {
    let words = shell_words(text);
    let mut args = vec!["-w".into()];
    if position == current_len {
        args.extend(words);
    } else {
        args.extend(["-I".into(), words[1].clone(), (position + 1).to_string()]);
        args.extend_from_slice(&words[2..]);
    }
    backend.execute(program, &args, None).await?;
    Ok(())
}

fn matching_rule_count(rules: &[LiveRule], text: &str) -> usize {
    rules.iter().filter(|rule| rule.text == text).count()
}

fn contains_rule_order<'a>(
    original: &[LiveRule],
    current: impl IntoIterator<Item = &'a LiveRule>,
) -> bool {
    let mut current = current.into_iter();
    original
        .iter()
        .all(|rule| current.any(|other| other.text == rule.text))
}

fn verify_insert_order(
    before: &[LiveRule],
    after: &[LiveRule],
    position: usize,
    text: &str,
) -> Result<()> {
    if after.len() != before.len() + 1
        || after[position].text != text
        || after[..position] != before[..position]
        || after[position + 1..] != before[position..]
    {
        bail!("无法确认恢复的放行规则与现有规则的相对顺序，请检查防火墙");
    }
    Ok(())
}

fn checked_firewall_restore_position(
    before: &[LiveRule],
    original: usize,
    current: &[LiveRule],
    use_occurrence: bool,
) -> Result<usize> {
    let position = restore_position(before, original, current, use_occurrence)
        .max(after_new_denials(before, current));
    verify_restore_position(before, original, current, position)
}

fn after_new_denials(before: &[LiveRule], current: &[LiveRule]) -> usize {
    let mut seen = std::collections::HashMap::new();
    let mut position = 0;
    for (index, rule) in current.iter().enumerate() {
        let count = seen.entry(&rule.text).or_insert(0);
        *count += 1;
        let is_new = if rule.handle.is_some() {
            !before.contains(rule)
        } else {
            *count > matching_rule_count(before, &rule.text)
        };
        if is_new && rule_denies(rule) {
            position = index + 1;
        }
    }
    position
}

fn rule_denies(rule: &LiveRule) -> bool {
    if rule.handle.is_some() {
        return serde_json::from_str::<Value>(&rule.text).is_ok_and(|spec| {
            spec["expr"].as_array().is_some_and(|expr| {
                expr.iter()
                    .any(|part| part.get("drop").is_some() || part.get("reject").is_some())
            })
        });
    }
    if matches!(
        rule.text.split_whitespace().next(),
        Some("deny" | "reject" | "deny_log" | "deny_log-all" | "reject_log" | "reject_log-all")
    ) {
        return true;
    }
    shell_words(&rule.text).windows(2).any(|words| {
        matches!(words[0].as_str(), "-j" | "--jump")
            && matches!(words[1].as_str(), "DROP" | "REJECT")
    })
}

fn verify_restore_position(
    before: &[LiveRule],
    original: usize,
    current: &[LiveRule],
    position: usize,
) -> Result<usize> {
    let restored = current[..position]
        .iter()
        .chain(std::iter::once(&before[original]))
        .chain(&current[position..]);
    if !contains_rule_order(before, restored) {
        bail!("无法确定原放行规则的恢复顺序，请检查防火墙");
    }
    Ok(position)
}

fn restore_position(
    before: &[LiveRule],
    original: usize,
    current: &[LiveRule],
    use_occurrence: bool,
) -> usize {
    // 优先找原后继。没有可用的后继时追加，随后检查能否保留原相对顺序。
    let locate = |anchor_index: usize| {
        let anchor = &before[anchor_index];
        if let Some(handle) = anchor.handle {
            if let Some(index) = current
                .iter()
                .position(|rule| rule.handle == Some(handle) && rule.text == anchor.text)
            {
                return Some(index);
            }
        }
        let original_count = matching_rule_count(before, &anchor.text);
        // iptables 没有 handle；同名规则数量未变时用第几次出现定位。
        if !use_occurrence && original_count != 1 {
            return None;
        }
        let mut matches = current
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.text == anchor.text)
            .map(|(index, _)| index);
        if matches.clone().count() != original_count {
            return None;
        }
        let occurrence = matching_rule_count(&before[..anchor_index], &anchor.text);
        matches.nth(occurrence)
    };
    for anchor in original + 1..before.len() {
        if let Some(index) = locate(anchor) {
            return index;
        }
    }
    // 让并发加入的拒绝规则保有优先级。
    current.len()
}

async fn ufw_status(backend: &mut impl FirewallExecutor) -> Result<String> {
    backend
        .execute("ufw", &["status".into(), "numbered".into()], None)
        .await
}

fn ufw_rules_path(v6: bool) -> &'static Path {
    Path::new(if v6 {
        "/etc/ufw/user6.rules"
    } else {
        "/etc/ufw/user.rules"
    })
}

struct UfwFile {
    contents: String,
    rules: Vec<LiveRule>,
    offsets: Vec<usize>,
}

impl UfwFile {
    fn load(backend: &impl FirewallExecutor, v6: bool) -> Result<Self> {
        let contents = backend.ufw_rules_file(v6)?;
        let mut rules = Vec::new();
        let mut offsets = Vec::new();
        let mut offset = 0;
        for line in contents.split_inclusive('\n') {
            if line.trim_end() == "### END RULES ###" {
                offsets.push(offset);
                return Ok(Self {
                    contents,
                    rules,
                    offsets,
                });
            }
            if let Some(tuple) = line.strip_prefix("### tuple ###") {
                let mut fields = tuple.split_whitespace().collect::<Vec<_>>();
                let has_comment = fields
                    .last()
                    .is_some_and(|field| field.starts_with("comment="));
                let field_count = fields.len() - usize::from(has_comment);
                match field_count {
                    // 兼容早期 UFW 文件中省略的方向字段。
                    6 | 8 => fields.insert(field_count, "in"),
                    7 | 9 => {}
                    _ => bail!("无法解析 UFW 内部规则，请检查 user.rules 和 user6.rules"),
                }
                rules.push(LiveRule::from(fields.join(" ").as_str()));
                offsets.push(offset);
            }
            offset += line.len();
        }
        bail!("UFW 持久配置缺少规则区结束标记，请检查 user.rules 和 user6.rules")
    }

    fn allow_entry(
        &self,
        position: usize,
        listener: SocketAddr,
        chain: &str,
    ) -> Result<Range<usize>> {
        let start = self.offsets[position];
        let mut lines = self.contents[start..self.offsets[position + 1]].split_inclusive('\n');
        let tuple = lines.next().context("缺少 UFW tuple")?;
        let rule = lines.next().context("UFW tuple 缺少对应规则")?;
        if iptables_delete_args_in_chain(rule.trim_end(), listener, chain).is_none()
            || lines.any(|line| !line.trim().is_empty())
        {
            bail!("UFW tuple 与专用放行规则无法一一对应，请检查 user.rules 和 user6.rules");
        }
        Ok(start..start + tuple.len() + rule.len())
    }
}

fn ufw_tuple_allow(tuple: &str, listener: SocketAddr) -> bool {
    let fields = tuple.split_whitespace().collect::<Vec<_>>();
    let ["allow", "tcp", port, destination, "any", source, "in"] = fields.as_slice() else {
        return false;
    };
    port.parse::<u16>().ok() == Some(listener.port())
        && matches_destination(address_scope(destination), listener.ip())
        && unrestricted(address_scope(source), listener.ip())
}

fn ufw_entry(line: &str) -> Option<(u32, &str)> {
    let (number, text) = line.trim_start().strip_prefix('[')?.split_once(']')?;
    Some((number.trim().parse().ok()?, text.trim()))
}

fn ufw_inbound_scope(text: &str) -> Option<(&str, &str)> {
    let text = text.split_once(" #").map_or(text, |(rule, _)| rule);
    let (destination, source) = ["ALLOW IN", "DENY IN", "REJECT IN", "LIMIT IN"]
        .iter()
        .find_map(|&action| text.split_once(action))?;
    let source = source.trim();
    let source = source
        .strip_suffix(" (log)")
        .or_else(|| source.strip_suffix(" (log-all)"))
        .unwrap_or(source);
    Some((destination.trim(), source.trim_end()))
}

fn ufw_is_v6(text: &str) -> bool {
    text.contains(" (v6)")
        || text
            .split_whitespace()
            .any(|field| address_scope(field).is_some_and(|(ip, _)| ip.is_ipv6()))
}

async fn iptables_input(backend: &mut impl FirewallExecutor, program: &str) -> Result<String> {
    backend
        .execute(program, &["-w".into(), "-S".into(), "INPUT".into()], None)
        .await
}

async fn nft_list(backend: &mut impl FirewallExecutor, target: Value) -> Result<Vec<Value>> {
    let output = nft_command(backend, json!({"list": target})).await?;
    nft_items(&output)
}

fn nft_items(output: &str) -> Result<Vec<Value>> {
    let mut value: Value = serde_json::from_str(output).context("解析 nft 规则失败")?;
    let Value::Array(items) = value["nftables"].take() else {
        bail!("nft 输出缺少规则列表");
    };
    Ok(items)
}

async fn nft_command(backend: &mut impl FirewallExecutor, operation: Value) -> Result<String> {
    let mut args = vec!["-j".into(), "-s".into()];
    if operation.get("insert").is_some() || operation.get("add").is_some() {
        args.extend(["-a".into(), "-e".into()]);
    }
    args.extend(["-f".into(), "-".into()]);
    let input = serde_json::to_vec(&json!({"nftables": [operation]}))?;
    backend.execute("nft", &args, Some(&input)).await
}

async fn delete_nft_rule(
    backend: &mut impl FirewallExecutor,
    spec: &Value,
    handle: u64,
) -> Result<()> {
    nft_command(
        backend,
        json!({"delete": {"rule": {
            "family": spec["family"], "table": spec["table"],
            "chain": spec["chain"], "handle": handle,
        }}}),
    )
    .await?;
    Ok(())
}

fn nft_rule_key(rule: &Value) -> String {
    json!({"expr": rule["expr"], "comment": rule["comment"]}).to_string()
}

fn nft_same_chain(chain: &Value, rule: &Value) -> bool {
    chain["family"] == rule["family"]
        && chain["table"] == rule["table"]
        && chain["name"] == rule["chain"]
        && chain["hook"] == "input"
        && chain["type"] == "filter"
}

async fn service_running(backend: &mut impl FirewallExecutor, unit: &str) -> Result<bool> {
    // is-active 的 inactive 返回非零，使用 show 得到可区分查询失败的状态。
    Ok(backend
        .execute(
            "systemctl",
            &[
                "show".into(),
                "--property=ActiveState".into(),
                "--value".into(),
                unit.into(),
            ],
            None,
        )
        .await?
        .trim()
        == "active")
}

async fn capture_firewalld(
    backend: &mut impl FirewallExecutor,
    listener: SocketAddr,
    prefix: &[String],
) -> Result<Vec<Rule>> {
    let mut zones_args = prefix.to_vec();
    zones_args.push("--get-zones".into());
    let zones = backend.execute("firewall-cmd", &zones_args, None).await?;
    let mut rules = Vec::new();
    for zone in zones.split_whitespace() {
        let mut base = prefix.to_vec();
        base.push(format!("--zone={zone}"));
        let mut sources = base.clone();
        sources.push("--list-sources".into());
        if backend
            .execute("firewall-cmd", &sources, None)
            .await?
            .trim()
            .is_empty()
        {
            // 普通端口放行作用于双栈，只清理能明确限定地址族的 rich rule。
            let output = list_rich_rules(backend, &base).await?;
            rules.extend(firewalld_rules(&output, listener, &base));
        }
    }
    Ok(rules)
}

async fn list_rich_rules(backend: &mut impl FirewallExecutor, base: &[String]) -> Result<String> {
    let mut args = base.to_vec();
    args.push("--list-rich-rules".into());
    backend.execute("firewall-cmd", &args, None).await
}

fn permanent_rich_base(base: &[String]) -> Vec<String> {
    std::iter::once("--permanent".to_owned())
        .chain(base.iter().cloned())
        .collect()
}

fn rich_is_permanent(base: &[String]) -> bool {
    base.first().is_some_and(|arg| arg == "--permanent")
}

fn firewalld_rules(output: &str, listener: SocketAddr, base: &[String]) -> Vec<Rule> {
    output
        .lines()
        .map(str::trim)
        .filter(|rule| firewalld_rich_port_allow(rule, listener))
        .map(|rule| Rule::Rich {
            base: base.to_vec(),
            text: rule.to_owned(),
        })
        .collect()
}

pub(super) fn ufw_rule_number(line: &str, listener: SocketAddr) -> Option<u32> {
    let (number, rule) = ufw_entry(line)?;
    let (destination, source) = rule.split_once("ALLOW IN")?;
    let ip = listener.ip();
    let destination = destination.trim();
    let source = source.trim();
    if ufw_is_v6(rule) != ip.is_ipv6() {
        return None;
    }
    let destination = destination.strip_suffix(" (v6)").unwrap_or(destination);
    let tcp_port = format!("{}/tcp", listener.port());
    let mut fields = destination.split_whitespace();
    let matches = match (fields.next(), fields.next(), fields.next()) {
        (Some(port), None, None) => port == tcp_port && ip.is_unspecified(),
        (Some(address), Some(port), None) => {
            port == tcp_port && matches_destination(address_scope(address), ip)
        }
        _ => false,
    };
    // 受管节点没有来源范围，保留显式限制来源的规则。
    let anywhere = if ip.is_ipv6() {
        "Anywhere (v6)"
    } else {
        "Anywhere"
    };
    let source_address = source.strip_suffix(" (v6)").unwrap_or(source);
    if !matches || (source != anywhere && !unrestricted(address_scope(source_address), ip)) {
        return None;
    }
    Some(number)
}

pub(super) fn iptables_delete_args(line: &str, listener: SocketAddr) -> Option<Vec<String>> {
    // 自定义链可能同时供 INPUT/OUTPUT/FORWARD 使用。
    iptables_delete_args_in_chain(line, listener, "INPUT")
}

fn iptables_delete_args_in_chain(
    line: &str,
    listener: SocketAddr,
    expected_chain: &str,
) -> Option<Vec<String>> {
    let mut words = shell_words(line);
    let [append, chain, options @ ..] = words.as_slice() else {
        return None;
    };
    if append != "-A" || chain != expected_chain {
        return None;
    }
    let (options, remainder) = options.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let ip = listener.ip();
    let port = listener.port().to_string();
    let (mut tcp, mut dport, mut accept) = (false, false, false);
    let mut destination = ip.is_unspecified();
    for [name, value] in options {
        match (name.as_str(), value.as_str()) {
            ("-p", "tcp") => tcp = true,
            ("-m", "tcp") => {}
            ("--dport", value) if value == port => dport = true,
            ("-j", "ACCEPT") => accept = true,
            ("-s", value) if unrestricted(address_scope(value), ip) => {}
            ("-d", value) if matches_destination(address_scope(value), ip) => destination = true,
            _ => return None,
        }
    }
    if !(tcp && dport && accept && destination) {
        return None;
    }
    // 用完整规则删除，避免规则顺序变化后按编号删错。
    words[0] = "-D".into();
    Some(words)
}

fn firewalld_rich_port_allow(rule: &str, listener: SocketAddr) -> bool {
    let words = shell_words(rule);
    let [rule, elements @ .., action] = words.as_slice() else {
        return false;
    };
    if rule != "rule" || action != "accept" {
        return false;
    }
    let ip = listener.ip();
    let family = if ip.is_ipv4() {
        "family=ipv4"
    } else {
        "family=ipv6"
    };
    let port = format!("port={}", listener.port());
    let mut dport = false;
    let mut destination = ip.is_unspecified();
    let mut family_scoped = false;
    let mut elements = elements;
    while !elements.is_empty() {
        elements = match elements {
            [attribute, rest @ ..] if attribute == family => {
                family_scoped = true;
                rest
            }
            [element, address, rest @ ..] if element == "source" || element == "destination" => {
                let scope = address.strip_prefix("address=").and_then(address_scope);
                if element == "source" && unrestricted(scope, ip) {
                    rest
                } else if element == "destination" && matches_destination(scope, ip) {
                    destination = true;
                    rest
                } else {
                    return false;
                }
            }
            [element, first, second, rest @ ..]
                if element == "port"
                    && ((first == &port && second == "protocol=tcp")
                        || (first == "protocol=tcp" && second == &port)) =>
            {
                dport = true;
                rest
            }
            _ => return false,
        };
    }
    // 未显式限定地址族的 port rich rule 可能为另一地址族的服务放行。
    dport && destination && family_scoped
}

fn address_scope(address: &str) -> Option<(IpAddr, u8)> {
    if let Some((ip, prefix)) = address.split_once('/') {
        return Some((ip.parse().ok()?, prefix.parse().ok()?));
    }
    let ip: IpAddr = address.parse().ok()?;
    Some((ip, host_prefix(ip)))
}

fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

fn unrestricted(scope: Option<(IpAddr, u8)>, listener: IpAddr) -> bool {
    scope.is_some_and(|(ip, prefix)| prefix == 0 && ip.is_ipv4() == listener.is_ipv4())
}

fn matches_destination(scope: Option<(IpAddr, u8)>, listener: IpAddr) -> bool {
    if listener.is_unspecified() {
        unrestricted(scope, listener)
    } else {
        scope == Some((listener, host_prefix(listener)))
    }
}

// iptables -S 的引号仅用于分隔参数；绝不交给 shell 执行。
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    for c in line.chars() {
        if escape {
            word.push(c);
            escape = false;
        } else if c == '\\' && quote != Some('\'') {
            escape = true;
        } else if Some(c) == quote {
            quote = None;
        } else if quote.is_some() {
            word.push(c);
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

fn nft_input_port_allow(
    rule: &serde_json::Value,
    items: &[serde_json::Value],
    listener: SocketAddr,
) -> bool {
    let (Some(family), Some(_), Some(_)) = (
        rule["family"].as_str(),
        rule["table"].as_str(),
        rule["chain"].as_str(),
    ) else {
        return false;
    };
    let ip_family = if listener.is_ipv4() { "ip" } else { "ip6" };
    if family != "inet" && family != ip_family {
        return false;
    }
    // 只删除 input hook 上过滤基础链的规则。
    items
        .iter()
        .any(|item| nft_same_chain(&item["chain"], rule))
        && nft_port_allow(rule, listener)
}

fn nft_port_allow(rule: &serde_json::Value, listener: SocketAddr) -> bool {
    if rule.get("comment").is_some() {
        return false;
    }
    let Some(expressions) = rule["expr"].as_array() else {
        return false;
    };
    let ip = listener.ip();
    let ip_family = if ip.is_ipv4() { "ip" } else { "ip6" };
    let nfproto = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    let header_protocol = if ip.is_ipv4() { "protocol" } else { "nexthdr" };
    let mut family_scoped = rule["family"] != "inet";
    let (mut dport, mut accept) = (false, false);
    let mut destination = ip.is_unspecified();
    for expr in expressions {
        if expr.get("accept").is_some() {
            accept = true;
            continue;
        }
        if expr.get("counter").is_some() {
            continue;
        }
        let condition = &expr["match"];
        if condition["op"] != "==" {
            return false;
        }
        let payload = &condition["left"]["payload"];
        let value = &condition["right"];
        if condition["left"]["meta"]["key"] == "nfproto" && value == nfproto {
            family_scoped = true;
            continue;
        }
        let ip_header = payload["protocol"] == ip_family && payload["field"] == header_protocol;
        if (condition["left"]["meta"]["key"] == "l4proto" || ip_header)
            && (value == "tcp" || value.as_u64() == Some(6))
        {
            family_scoped |= ip_header;
            continue;
        }
        match (payload["protocol"].as_str(), payload["field"].as_str()) {
            (Some("tcp"), Some("dport")) if value.as_u64() == Some(u64::from(listener.port())) => {
                dport = true;
            }
            (Some(protocol), Some("saddr"))
                if protocol == ip_family && unrestricted(nft_address_scope(value), ip) =>
            {
                family_scoped = true;
            }
            (Some(protocol), Some("daddr"))
                if protocol == ip_family && matches_destination(nft_address_scope(value), ip) =>
            {
                destination = true;
                family_scoped = true;
            }
            _ => return false,
        }
    }
    dport && accept && destination && family_scoped
}

fn nft_address_scope(value: &serde_json::Value) -> Option<(IpAddr, u8)> {
    if let Some(address) = value.as_str() {
        return address_scope(address);
    }
    let prefix = &value["prefix"];
    let ip = prefix["addr"].as_str()?.parse().ok()?;
    let length = prefix["len"].as_u64()?.try_into().ok()?;
    Some((ip, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_secure_preserves_dual_stack_shared_firewall_rules() {
        for (listener, family) in [("0.0.0.0:1080", "ipv4"), ("[::]:1080", "ipv6")] {
            let listener: SocketAddr = listener.parse().unwrap();
            let mut rule = serde_json::json!({
                "family": "inet", "table": "filter", "chain": "input", "handle": 4,
                "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                    {"accept": null}
                ]
            });
            let chains = [serde_json::json!({"chain": {
                "family": "inet", "table": "filter", "name": "input", "hook": "input", "type": "filter"
            }})];
            assert!(!nft_input_port_allow(&rule, &chains, listener));
            rule["expr"].as_array_mut().unwrap().insert(
                0,
                serde_json::json!({
                    "match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": family}
                }),
            );
            assert!(nft_input_port_allow(&rule, &chains, listener));

            let rules = "1080/tcp\nrule port port=\"1080\" protocol=\"tcp\" accept\n";
            assert!(firewalld_rules(rules, listener, &[]).is_empty());
            let scoped =
                format!(r#"rule family="{family}" port port="1080" protocol="tcp" accept"#);
            assert_eq!(firewalld_rules(&scoped, listener, &[]).len(), 1);
        }
    }

    const SHARED: &str = r#"rule port port="1080" protocol="tcp" accept"#;
    const SCOPED: &str = r#"rule family="ipv4" port port="1080" protocol="tcp" accept"#;

    struct FakeFirewalld {
        rules: [Vec<&'static str>; 2],
        runtime_timeout: Option<u32>,
        fail_permanent_removal: bool,
        fail_permanent_restore: bool,
    }

    impl FirewallExecutor for FakeFirewalld {
        fn available(&self, program: &str) -> bool {
            program == "firewall-cmd"
        }

        async fn execute(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&[u8]>,
        ) -> Result<String> {
            assert!(input.is_none());
            if program == "systemctl" {
                return Ok("active".into());
            }
            assert_eq!(program, "firewall-cmd");
            let permanent = if args[0] == "--permanent" { 1 } else { 0 };
            let option = args.last().unwrap();
            match option.as_str() {
                "--get-zones" => Ok("public".into()),
                "--list-sources" => Ok(String::new()),
                "--list-ports" => Ok("1080/tcp".into()),
                "--list-rich-rules" => Ok(self.rules[permanent].join("\n")),
                _ if option.strip_prefix("--add-rich-rule=") == Some(SCOPED) => {
                    if permanent == 1 && self.fail_permanent_restore {
                        bail!("模拟持久规则恢复失败");
                    }
                    self.rules[permanent].push(SCOPED);
                    if permanent == 0 {
                        self.runtime_timeout = None;
                    }
                    Ok(String::new())
                }
                _ => {
                    assert_eq!(option, &format!("--remove-rich-rule={SCOPED}"));
                    if permanent == 1 && self.fail_permanent_removal {
                        bail!("模拟持久规则删除失败");
                    }
                    assert_eq!(self.rules[permanent].pop(), Some(SCOPED));
                    if permanent == 0 {
                        self.runtime_timeout = None;
                    }
                    Ok(String::new())
                }
            }
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_keeps_shared_runtime_and_permanent_rules() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED], vec![SHARED, SCOPED]],
            runtime_timeout: None,
            fail_permanent_removal: false,
            fail_permanent_restore: false,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);
        let report = plan.closure_report();
        assert!(report.contains("已移除 0 条运行时"));
        assert!(report.contains("已移除 1 条持久"));
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED, SCOPED]]);
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_preflight_keeps_original_runtime_rule() {
        // firewalld 只返回规则文本。没有持久副本的普通及限时规则都不能补偿。
        for runtime_timeout in [None, Some(60)] {
            let rules = [vec![SHARED, SCOPED], vec![SHARED]];
            let mut backend = FakeFirewalld {
                rules: rules.clone(),
                runtime_timeout,
                fail_permanent_removal: false,
                fail_permanent_restore: false,
            };
            let result =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend).await;
            assert!(format!("{:#}", result.err().unwrap()).contains("剩余超时"));
            assert_eq!(backend.rules, rules);
            assert_eq!(backend.runtime_timeout, runtime_timeout);
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_only_restores_permanent_rules_after_runtime_removal() {
        for fail_permanent_removal in [false, true] {
            let original = [vec![SHARED, SCOPED], vec![SHARED, SCOPED]];
            let mut backend = FakeFirewalld {
                rules: original.clone(),
                runtime_timeout: None,
                fail_permanent_removal,
                fail_permanent_restore: false,
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            let close = plan.close_with(&mut backend).await;
            if fail_permanent_removal {
                assert!(format!("{:#}", close.unwrap_err()).contains("持久规则删除失败"));
                assert_eq!(backend.rules, original);
                plan.restore_with(&mut backend).await.unwrap();
                assert_eq!(backend.rules, original);
            } else {
                close.unwrap();
                assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);
                assert!(plan.closure_report().contains("已移除 1 条运行时"));
                let error = plan.restore_with(&mut backend).await.unwrap_err();
                assert!(format!("{error:#}").contains("原剩余超时"));
                assert_eq!(backend.rules, [vec![SHARED], vec![SHARED, SCOPED]]);
            }
            assert_eq!(backend.runtime_timeout, None);
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_rollback_preserves_paired_runtime_timeout() {
        let original = [vec![SHARED, SCOPED], vec![SHARED, SCOPED]];
        let mut backend = FakeFirewalld {
            rules: original.clone(),
            runtime_timeout: Some(60),
            fail_permanent_removal: true,
            fail_permanent_restore: false,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();

        let error = plan.close_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("持久规则删除失败"));
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, original);
        assert_eq!(backend.runtime_timeout, Some(60));
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_does_not_restore_runtime_if_permanent_restore_fails() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED, SCOPED], vec![SHARED, SCOPED]],
            runtime_timeout: Some(60),
            fail_permanent_removal: false,
            fail_permanent_restore: true,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);

        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("持久规则恢复失败"));
        assert!(format!("{error:#}").contains("原剩余超时"));
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_keeps_runtime_rule_when_permanent_backing_disappears() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED, SCOPED], vec![SHARED, SCOPED]],
            runtime_timeout: Some(60),
            fail_permanent_removal: false,
            fail_permanent_restore: false,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        backend.rules[1].pop();
        let error = plan.close_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("无对应持久规则"));
        assert_eq!(backend.rules, [vec![SHARED, SCOPED], vec![SHARED]]);
        assert_eq!(backend.runtime_timeout, Some(60));
    }

    #[test]
    fn socks5_secure_reports_runtime_only_and_persistent_closure_separately() {
        let report = closure_report(1, 0, true, false);
        assert!(report.contains("运行时"));
        assert!(report.contains("/etc/nftables.conf"));
        assert!(report.contains("可能恢复"));
        let report = closure_report(2, 1, false, true);
        assert!(report.contains("已移除 1 条持久"));
        assert!(report.contains("netfilter-persistent"));
        assert!(report.contains("可能恢复"));
        assert!(!closure_report(1, 1, false, false).contains("可能恢复"));
        assert!(closure_report(0, 0, false, false).contains("未移除"));
    }

    #[test]
    fn socks5_secure_iptables_preserves_output_forward_and_unclassified_chains() {
        let listener = "0.0.0.0:443".parse().unwrap();
        for chain in ["OUTPUT", "FORWARD", "CUSTOM"] {
            for protocol in ["tcp", "udp"] {
                assert!(
                    iptables_delete_args(
                        &format!("-A {chain} -p {protocol} --dport 443 -j ACCEPT"),
                        listener,
                    )
                    .is_none(),
                    "must preserve {chain} {protocol}"
                );
            }
        }
        assert!(iptables_delete_args("-A INPUT -p tcp --dport 443 -j ACCEPT", listener).is_some());
    }

    #[test]
    fn socks5_secure_nft_preserves_non_input_hooks_and_unclassified_chains() {
        let listener = "0.0.0.0:443".parse().unwrap();
        let mut rule = serde_json::json!({
            "family": "ip", "table": "filter", "chain": "incoming", "handle": 1,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                {"accept": null}
            ]
        });
        for hook in ["output", "forward", "prerouting", "postrouting", "ingress"] {
            let items = vec![
                serde_json::json!({"chain": {
                    "family": "ip", "table": "filter", "name": "incoming", "hook": hook, "type": "filter"
                }}),
                serde_json::json!({"rule": rule}),
            ];
            assert!(
                !nft_input_port_allow(&rule, &items, listener),
                "must preserve {hook}"
            );
        }
        assert!(!nft_input_port_allow(&rule, &[], listener));
        let items = vec![
            serde_json::json!({"chain": {
                "family": "ip", "table": "filter", "name": "incoming", "hook": "input", "type": "filter"
            }}),
            serde_json::json!({"rule": rule}),
        ];
        assert!(nft_input_port_allow(&rule, &items, listener));
        // 同名链必须同时匹配地址族和表，不能借用另一条链的 input hook。
        for field in ["family", "table", "chain"] {
            let original = rule[field].clone();
            rule[field] = "other".into();
            assert!(
                !nft_input_port_allow(&rule, &items, listener),
                "must match {field}"
            );
            rule[field] = original;
        }
    }

    #[test]
    fn socks5_secure_nft_preserves_nat_input_accept() {
        let listener = "0.0.0.0:443".parse().unwrap();
        let rule = json!({
            "family": "ip", "table": "combined", "chain": "nat_input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                {"accept": null}
            ]
        });
        let items = [
            json!({"chain": {"family": "ip", "table": "combined", "name": "filter_input", "hook": "input", "type": "filter"}}),
            json!({"chain": {"family": "ip", "table": "combined", "name": "nat_input", "hook": "input", "type": "nat"}}),
        ];
        assert!(!nft_input_port_allow(&rule, &items, listener));
        let mut filter_rule = rule;
        filter_rule["chain"] = "filter_input".into();
        assert!(nft_input_port_allow(&filter_rule, &items, listener));
    }

    #[test]
    fn socks5_secure_firewalld_rich_rules_preserve_source_ports_and_other_actions() {
        let listener = "0.0.0.0:1080".parse().unwrap();
        assert!(firewalld_rich_port_allow(
            r#"rule family="ipv4" port port="1080" protocol="tcp" accept"#,
            listener
        ));
        for rule in [
            r#"rule family="ipv6" port protocol="udp" port="1080" log prefix="socks" accept"#,
            r#"rule family="ipv4" port protocol="udp" port="1080" accept"#,
            r#"rule family="ipv6" port port="1080" protocol="tcp" accept"#,
            r#"rule family="ipv4" source address="192.0.2.0/24" port port="1080" protocol="tcp" accept"#,
            r#"rule family="ipv4" source-port port="1080" protocol="tcp" accept"#,
            r#"rule family="ipv6" source-port port="1080" protocol="udp" accept"#,
            r#"rule port port="1081" protocol="tcp" accept"#,
            r#"rule port port="1080-1081" protocol="tcp" accept"#,
            r#"rule source-port port="1080" protocol="tcp" log prefix="port accept" accept"#,
            r#"rule port port="1080" protocol="tcp" log prefix=" accept " drop"#,
            r#"rule port port="1080" protocol="tcp" log prefix="accept" reject"#,
            r#"rule port port="1080" protocol="tcp" audit"#,
        ] {
            assert!(
                !firewalld_rich_port_allow(rule, listener),
                "must preserve {rule}"
            );
        }
        let listener = "[2001:db8::8]:1080".parse().unwrap();
        assert!(firewalld_rich_port_allow(
            r#"rule family="ipv6" destination address="2001:db8::8/128" port protocol="tcp" port="1080" accept"#,
            listener
        ));
        assert!(!firewalld_rich_port_allow(
            r#"rule family="ipv6" destination address="2001:db8::/64" port protocol="tcp" port="1080" accept"#,
            listener
        ));
    }

    const IPV4: &str = "1080/tcp ALLOW IN Anywhere";
    const IPV6: &str = "1080/tcp (v6) ALLOW IN Anywhere (v6)";
    const OTHER: &str = "22/tcp ALLOW IN Anywhere";
    const APP: &str = "Example App ALLOW IN Anywhere";
    const DENY: &str = "1080/tcp DENY IN 192.0.2.0/24";
    const TAIL: &str = "8443/tcp ALLOW IN Anywhere";
    const DENY_V6: &str = "1080/tcp DENY IN 2001:db8::/32";
    const TAIL_V6: &str = "8443/tcp (v6) ALLOW IN Anywhere (v6)";

    #[cfg(target_os = "linux")]
    #[test]
    fn socks5_secure_ufw_preserves_an_admin_write_during_rule_replacement() {
        use rustix::fs::{fcntl_lock, FlockOperation};
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        const ADMIN_DIRECTORY: &str = "PING_RUST_TEST_UFW_ADMIN_DIRECTORY";
        let deny = "-A ufw-user-input -p tcp --dport 8443 -j DROP\n";
        if let Some(directory) = std::env::var_os(ADMIN_DIRECTORY) {
            use std::io::Write;

            let directory = Path::new(&directory);
            let lock = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join("ufw.lock"))
                .unwrap();
            fcntl_lock(&lock, FlockOperation::LockExclusive).unwrap();
            let mut rules = std::fs::OpenOptions::new()
                .append(true)
                .open(directory.join("user.rules"))
                .unwrap();
            eprintln!("ready");
            std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).unwrap();
            rules.write_all(deny.as_bytes()).unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let rules = directory.path().join("user.rules");
        let lock = directory.path().join("ufw.lock");
        let before = "-A ufw-user-input -p tcp --dport 1080 -j ACCEPT\n";
        std::fs::write(&rules, before).unwrap();
        let (_, module) = module_path!().split_once("::").unwrap();
        let test =
            format!("{module}::socks5_secure_ufw_preserves_an_admin_write_during_rule_replacement");
        let mut admin = Command::new(std::env::current_exe().unwrap())
            .args(["--nocapture", "--exact", &test])
            .env(ADMIN_DIRECTORY, directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(admin.stderr.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim_end(), "ready");

        let result = replace_ufw_rules_file(&rules, &lock, before, "");
        drop(admin.stdin.take());
        assert!(admin.wait().unwrap().success());
        assert!(result.unwrap_err().to_string().contains("UFW 写锁"));
        let error = replace_ufw_rules_file(&rules, &lock, before, "").unwrap_err();
        assert!(error.to_string().contains("已并发修改"));
        let current = format!("{before}{deny}");
        assert_eq!(std::fs::read_to_string(&rules).unwrap(), current);
        replace_ufw_rules_file(&rules, &lock, &current, deny).unwrap();
        assert_eq!(std::fs::read_to_string(&rules).unwrap(), deny);
    }

    struct FakeUfw {
        disk: Vec<&'static str>,
        ipv6: bool,
        kernel_has_rule: bool,
        keep_disk_on_delete_failure: bool,
        kernel_reorders_on_insert: bool,
        other_family_runtime_rule: bool,
        delete_succeeds: bool,
    }

    impl FirewallExecutor for FakeUfw {
        fn available(&self, program: &str) -> bool {
            program == "ufw" || program == if self.ipv6 { "ip6tables" } else { "iptables" }
        }

        fn ufw_rules_file(&self, v6: bool) -> Result<String> {
            let mut file = String::new();
            for rule in &self.disk {
                let tuples: &[&str] = match (*rule, v6) {
                    (IPV4, false) => &["allow tcp 1080 0.0.0.0/0 any 0.0.0.0/0 in"],
                    (IPV6, true) => &["allow tcp 1080 ::/0 any ::/0 in"],
                    (OTHER, false) => &["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"],
                    (DENY, false) => &["deny tcp 1080 0.0.0.0/0 any 192.0.2.0/24 in"],
                    (TAIL, false) => &["allow tcp 8443 0.0.0.0/0 any 0.0.0.0/0 in"],
                    (DENY_V6, true) => &["deny tcp 1080 ::/0 any 2001:db8::/32 in"],
                    (TAIL_V6, true) => &["allow tcp 8443 ::/0 any ::/0 in"],
                    (APP, false) => &[
                        "allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Example%20App - in",
                        "allow udp 53 0.0.0.0/0 any 0.0.0.0/0 Example%20App - in",
                    ],
                    _ => &[],
                };
                for tuple in tuples {
                    file.push_str(&format!("### tuple ### {tuple}\n"));
                    if *rule == IPV4 || *rule == IPV6 {
                        let chain = if v6 {
                            "ufw6-user-input"
                        } else {
                            "ufw-user-input"
                        };
                        file.push_str(&format!("-A {chain} -p tcp --dport 1080 -j ACCEPT\n"));
                    }
                }
            }
            file.push_str("### END RULES ###\nCOMMIT\n");
            Ok(file)
        }

        fn replace_ufw_rules_file(&mut self, v6: bool, before: &str, after: &str) -> Result<()> {
            assert_eq!(v6, self.ipv6);
            assert_eq!(before, self.ufw_rules_file(v6)?);
            let allow = if v6 { IPV6 } else { IPV4 };
            if let Some(index) = self.disk.iter().position(|entry| *entry == allow) {
                assert!(!after.contains("-p tcp --dport 1080 -j ACCEPT"));
                if !self.keep_disk_on_delete_failure {
                    self.disk.remove(index);
                }
                if !self.delete_succeeds {
                    self.disk.insert(0, OTHER);
                    bail!("模拟 UFW 持久规则写入失败");
                }
            } else {
                let restored = after
                    .lines()
                    .filter(|line| line.starts_with("### tuple ###"));
                let position = restored
                    .enumerate()
                    .find(|(_, line)| line.starts_with("### tuple ### allow tcp 1080 "))
                    .unwrap()
                    .0;
                let mut offset = 0;
                let mut index = 0;
                while index < self.disk.len() && offset < position {
                    let rule = self.disk[index];
                    if ufw_is_v6(rule) == v6 {
                        offset += if rule == APP { 2 } else { 1 };
                    }
                    index += 1;
                }
                assert_eq!(offset, position);
                if v6 {
                    while index < self.disk.len() && !ufw_is_v6(self.disk[index]) {
                        index += 1;
                    }
                }
                self.disk.insert(index, allow);
                assert_eq!(after, self.ufw_rules_file(v6)?);
            }
            Ok(())
        }

        async fn execute(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&[u8]>,
        ) -> Result<String> {
            assert!(input.is_none());
            if program == "ip6tables" && args == ["-w", "-S", "ufw6-user-input"] && !self.ipv6 {
                let mut output = String::from("-N ufw6-user-input\n");
                if self.other_family_runtime_rule {
                    output.push_str("-A ufw6-user-input -p tcp -m tcp --dport 1080 -j DROP\n");
                }
                if self.disk.contains(&IPV6) {
                    output.push_str("-A ufw6-user-input -p tcp -m tcp --dport 1080 -j ACCEPT\n");
                }
                return Ok(output);
            }
            if self.available(program) && program != "ufw" {
                let kernel_chain = if self.ipv6 {
                    "ufw6-user-input"
                } else {
                    "ufw-user-input"
                };
                return match args {
                    [version] if version == "--version" => Ok("iptables v1.8.9 (legacy)".into()),
                    [_, _, chain] if chain == "INPUT" => Ok("-P INPUT ACCEPT".into()),
                    [_, _, chain] if chain == kernel_chain => {
                        assert_eq!(args, ["-w", "-S", kernel_chain]);
                        let mut rules = format!("-N {kernel_chain}\n");
                        let allow =
                            format!("-A {kernel_chain} -p tcp -m tcp --dport 1080 -j ACCEPT\n");
                        let rule = if self.ipv6 { IPV6 } else { IPV4 };
                        if self.kernel_has_rule && self.kernel_reorders_on_insert {
                            rules.push_str(&allow);
                        }
                        for entry in &self.disk {
                            match *entry {
                                entry if entry == rule && self.kernel_has_rule && !self.kernel_reorders_on_insert => {
                                    rules.push_str(&allow);
                                }
                                APP if !self.ipv6 => rules.push_str(concat!(
                                    "-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT\n",
                                    "-A ufw-user-input -p udp -m udp --dport 53 -j ACCEPT\n",
                                )),
                                DENY if !self.ipv6 => rules.push_str(
                                    "-A ufw-user-input -s 192.0.2.0/24 -p tcp -m tcp --dport 1080 -j DROP\n",
                                ),
                                DENY_V6 if self.ipv6 => rules.push_str(
                                    "-A ufw6-user-input -s 2001:db8::/32 -p tcp -m tcp --dport 1080 -j DROP\n",
                                ),
                                _ => {}
                            }
                        }
                        Ok(rules)
                    }
                    [wait, action, chain, rest @ ..]
                        if matches!(action.as_str(), "-D" | "-A" | "-I") =>
                    {
                        assert_eq!(wait, "-w");
                        assert_eq!(chain, kernel_chain);
                        let rule = if action == "-I" { &rest[1..] } else { rest };
                        assert_eq!(
                            rule,
                            ["-p", "tcp", "-m", "tcp", "--dport", "1080", "-j", "ACCEPT"]
                        );
                        assert_eq!(self.kernel_has_rule, action == "-D");
                        self.kernel_has_rule = action != "-D";
                        Ok(String::new())
                    }
                    _ => panic!("意外 iptables 操作 {args:?}"),
                };
            }
            assert_eq!(program, "ufw");
            let (scope, rule) = if self.ipv6 {
                ("::/0", IPV6)
            } else {
                ("0.0.0.0/0", IPV4)
            };
            let spec = [
                "allow", "proto", "tcp", "from", scope, "to", scope, "port", "1080",
            ];
            match args[0].as_str() {
                "status" => {
                    let mut status = String::from("Status: active\n");
                    for (index, rule) in self.disk.iter().enumerate() {
                        status.push_str(&format!("[{}] {rule}\n", index + 1));
                    }
                    Ok(status)
                }
                "--force" => {
                    assert_eq!(args[1], "delete");
                    assert_eq!(args[2..], spec);
                    self.kernel_has_rule = false;
                    self.other_family_runtime_rule = false;
                    if !self.keep_disk_on_delete_failure {
                        let index = self.disk.iter().position(|entry| *entry == rule).unwrap();
                        assert_eq!(self.disk.remove(index), rule);
                    }
                    if self.delete_succeeds {
                        return Ok(String::new());
                    }
                    self.disk.insert(0, OTHER);
                    bail!("模拟 UFW 删除后失败");
                }
                _ => panic!("意外操作 {args:?}"),
            }
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_preserves_runtime_ipv6_deny_during_ipv4_close_and_rollback() {
        let mut backend = FakeUfw {
            disk: vec![IPV4, IPV6],
            ipv6: false,
            kernel_has_rule: true,
            keep_disk_on_delete_failure: false,
            kernel_reorders_on_insert: false,
            other_family_runtime_rule: true,
            delete_succeeds: true,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        let before = ufw_kernel_rules(&mut backend, "ip6tables", "ufw6-user-input")
            .await
            .unwrap();
        assert_eq!(before.len(), 2);
        assert!(before[0].text.ends_with("-j DROP"));
        assert!(before[1].text.ends_with("-j ACCEPT"));
        plan.close_with(&mut backend).await.unwrap();
        let after_close = ufw_kernel_rules(&mut backend, "ip6tables", "ufw6-user-input")
            .await
            .unwrap();
        assert!(after_close == before);
        assert!(!backend.kernel_has_rule);
        assert_eq!(backend.disk, [IPV6]);
        plan.restore_with(&mut backend).await.unwrap();
        let after_restore = ufw_kernel_rules(&mut backend, "ip6tables", "ufw6-user-input")
            .await
            .unwrap();
        assert!(after_restore == before);
        assert!(backend.kernel_has_rule);
        assert_eq!(backend.disk, [IPV4, IPV6]);
    }

    #[tokio::test]
    async fn socks5_secure_ufw_partial_failure_restores_only_the_removed_family() {
        let mut backend = FakeUfw {
            disk: vec![IPV4, IPV6],
            ipv6: false,
            kernel_has_rule: true,
            keep_disk_on_delete_failure: false,
            kernel_reorders_on_insert: false,
            other_family_runtime_rule: false,
            delete_succeeds: false,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        assert!(plan.close_with(&mut backend).await.is_err());
        assert_eq!(backend.disk, [OTHER, IPV6]);
        assert!(!backend.kernel_has_rule);
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.disk, [OTHER, IPV4, IPV6]);
        assert!(backend.kernel_has_rule);
    }

    #[tokio::test]
    async fn socks5_secure_ufw_rollback_reinstates_kernel_rule_present_only_on_disk() {
        for (address, ipv6) in [("0.0.0.0:1080", false), ("[::]:1080", true)] {
            for keep_disk_on_delete_failure in [false, true] {
                let mut backend = FakeUfw {
                    disk: vec![IPV4, IPV6],
                    ipv6,
                    kernel_has_rule: true,
                    keep_disk_on_delete_failure,
                    kernel_reorders_on_insert: false,
                    other_family_runtime_rule: false,
                    delete_succeeds: false,
                };
                let mut plan = FirewallPlan::capture_with(address.parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
                assert!(plan.close_with(&mut backend).await.is_err());
                assert!(!backend.kernel_has_rule);
                plan.restore_with(&mut backend).await.unwrap();
                assert_eq!(backend.disk, [OTHER, IPV4, IPV6]);
                assert!(backend.kernel_has_rule);
            }
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_rollback_uses_internal_application_rule_positions() {
        for (listener, ipv6, deny, allow, tail) in [
            ("0.0.0.0:1080", false, DENY, IPV4, TAIL),
            ("[::]:1080", true, DENY_V6, IPV6, TAIL_V6),
        ] {
            let mut backend = FakeUfw {
                disk: vec![APP, deny, allow, tail],
                ipv6,
                kernel_has_rule: true,
                keep_disk_on_delete_failure: false,
                kernel_reorders_on_insert: false,
                other_family_runtime_rule: false,
                delete_succeeds: false,
            };
            let mut plan = FirewallPlan::capture_with(listener.parse().unwrap(), &mut backend)
                .await
                .unwrap();
            assert!(plan.close_with(&mut backend).await.is_err());
            assert_eq!(backend.disk, [OTHER, APP, deny, tail]);
            plan.restore_with(&mut backend).await.unwrap();
            assert_eq!(backend.disk, [OTHER, APP, deny, allow, tail]);
            assert!(backend.kernel_has_rule);
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_rollback_checks_persistent_and_kernel_rule_order() {
        for reorder_kernel in [false, true] {
            let mut backend = FakeUfw {
                disk: vec![APP, DENY, IPV4, IPV6],
                ipv6: false,
                kernel_has_rule: true,
                keep_disk_on_delete_failure: false,
                kernel_reorders_on_insert: false,
                other_family_runtime_rule: false,
                delete_succeeds: false,
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            assert!(plan.close_with(&mut backend).await.is_err());
            if reorder_kernel {
                backend.kernel_reorders_on_insert = true;
            } else {
                backend.disk.insert(1, IPV4);
                backend.kernel_has_rule = true;
            }
            let error = plan.restore_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("顺序"));
            assert_eq!(backend.kernel_has_rule, !reorder_kernel);
            let kernel = ufw_kernel_rules(&mut backend, "iptables", "ufw-user-input")
                .await
                .unwrap();
            assert!(kernel.iter().any(rule_denies));
            assert_eq!(
                backend.disk.iter().filter(|entry| **entry == IPV4).count(),
                1
            );
        }
    }

    struct FakeIptables {
        rules: Vec<String>,
        deletions: usize,
        fail_second_deletion: bool,
        drop_before_insert: Option<&'static str>,
        rules_after_insert: Vec<&'static str>,
    }

    impl FirewallExecutor for FakeIptables {
        fn available(&self, program: &str) -> bool {
            program == "iptables"
        }

        async fn execute(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&[u8]>,
        ) -> Result<String> {
            assert_eq!(program, "iptables");
            assert!(input.is_none());
            if args == ["--version"] {
                return Ok("iptables v1.8.9 (legacy)".into());
            }
            if args == ["-w", "-S", "INPUT"] {
                return Ok(self.rules.join("\n"));
            }
            let action = args[1].as_str();
            match action {
                "-D" => {
                    self.deletions += 1;
                    // 第二次删除失败前，另一个工具插入无关规则。
                    if self.deletions == 2 && self.fail_second_deletion {
                        self.rules
                            .insert(0, "-A INPUT -p udp --dport 53 -j ACCEPT".into());
                        bail!("模拟删除失败");
                    }
                    assert_eq!(args[2], "INPUT");
                    let rule = format!("-A INPUT {}", args[3..].join(" "));
                    let position = self.rules.iter().position(|live| live == &rule).unwrap();
                    self.rules.remove(position);
                }
                "-I" => {
                    assert_eq!(args[2], "INPUT");
                    let position = args[3].parse::<usize>().unwrap();
                    if let Some(drop) = self.drop_before_insert.take() {
                        self.rules.insert(0, drop.into());
                    }
                    self.rules
                        .insert(position - 1, format!("-A INPUT {}", args[4..].join(" ")));
                }
                "-A" => {
                    assert_eq!(args[2], "INPUT");
                    self.rules.push(format!("-A INPUT {}", args[3..].join(" ")));
                }
                _ => panic!("意外操作 {args:?}"),
            }
            if matches!(action, "-I" | "-A") {
                drop(
                    self.rules
                        .splice(..0, self.rules_after_insert.drain(..).map(str::to_owned)),
                );
            }
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn socks5_secure_iptables_partial_failure_preserves_concurrent_rules() {
        let rules = [
            "-A INPUT -p tcp --dport 1080 -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 1080 -j ACCEPT",
            "-A INPUT -j DROP",
        ];
        let mut backend = FakeIptables {
            rules: rules.map(str::to_owned).into(),
            deletions: 0,
            fail_second_deletion: true,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        assert!(plan.close_with(&mut backend).await.is_err());
        assert_eq!(backend.rules[1..], rules[1..]);
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules[0], "-A INPUT -p udp --dport 53 -j ACCEPT");
        assert_eq!(backend.rules[1..], rules);
        assert!(plan.attempted.is_empty());
    }

    #[tokio::test]
    async fn socks5_secure_iptables_rollback_preserves_position_before_repeated_drop() {
        let remaining = [
            "-A INPUT -j DROP",
            "-A INPUT -j DROP",
            "-A INPUT -p udp --dport 53 -j ACCEPT",
        ];
        for position in [0, 1] {
            let mut rules = remaining.to_vec();
            rules.insert(position, "-A INPUT -p tcp --dport 1080 -j ACCEPT");
            let mut backend = FakeIptables {
                rules: rules.iter().map(|rule| (*rule).to_owned()).collect(),
                deletions: 0,
                fail_second_deletion: false,
                drop_before_insert: None,
                rules_after_insert: Vec::new(),
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            plan.close_with(&mut backend).await.unwrap();
            assert_eq!(backend.rules, remaining);
            plan.restore_with(&mut backend).await.unwrap();
            assert_eq!(backend.rules, rules);
        }
    }

    #[tokio::test]
    async fn socks5_secure_iptables_rollback_appends_after_new_same_port_drop() {
        let accept = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let drop = "-A INPUT -p tcp --dport 1080 -j DROP";
        let mut backend = FakeIptables {
            rules: vec![accept.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        backend.rules.push(drop.into());
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [drop, accept]);
    }

    #[tokio::test]
    async fn socks5_secure_iptables_removes_accept_inserted_before_a_concurrent_drop() {
        let accept = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let drop = "-A INPUT -p tcp --dport 1080 -j DROP";
        let ssh = "-A INPUT -p tcp --dport 22 -j ACCEPT";
        let mut backend = FakeIptables {
            rules: vec![accept.into(), ssh.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: Some(drop),
            rules_after_insert: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();

        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("相对顺序"));
        assert_eq!(backend.rules, [drop, ssh]);
    }

    #[tokio::test]
    async fn socks5_secure_iptables_preserves_concurrent_identical_accept_before_reject() {
        let accept = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let reject = "-A INPUT -p tcp --dport 1080 -j REJECT";
        let ssh = "-A INPUT -p tcp --dport 22 -j ACCEPT";
        let mut backend = FakeIptables {
            rules: vec![accept.into(), ssh.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: vec![accept, reject],
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();

        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("相对顺序"));
        assert!(format!("{error:#}").contains("多条同文放行规则"));
        assert_eq!(backend.rules, [accept, reject, accept, ssh]);
        assert_eq!(backend.deletions, 1);
    }

    #[tokio::test]
    async fn socks5_secure_iptables_rollback_reports_a_missing_anchor() {
        let mut backend = FakeIptables {
            rules: vec![
                "-A INPUT -p tcp --dport 1080 -j ACCEPT".into(),
                "-A INPUT -p tcp --dport 22 -j ACCEPT".into(),
            ],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        let drop = "-A INPUT -p tcp --dport 1080 -j REJECT";
        backend.rules = vec![drop.into()];
        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("顺序"));
        assert_eq!(backend.rules, [drop]);
    }

    #[tokio::test]
    async fn socks5_secure_iptables_keeps_new_reject_after_original_successor() {
        let allow = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let ssh = "-A INPUT -p tcp --dport 22 -j ACCEPT";
        let reject = "-A INPUT -p tcp --dport 1080 -j REJECT";
        let mut backend = FakeIptables {
            rules: vec![allow.into(), ssh.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        backend.rules.push(reject.into());
        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("顺序"));
        assert_eq!(backend.rules, [ssh, reject]);
    }

    #[test]
    fn socks5_secure_rule_rollback_verifies_order_against_concurrent_rules() {
        let drop = LiveRule::from("-A INPUT -p tcp --dport 1080 -j DROP");
        let accept = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let wrong_order = [LiveRule::from(accept), LiveRule::from(drop.text.as_str())];
        let error = verify_insert_order(&[drop], &wrong_order, 1, accept).unwrap_err();
        assert!(format!("{error:#}").contains("相对顺序"));
    }

    struct FakeNft {
        rules: Vec<serde_json::Value>,
        iptables_nft: bool,
        chain: &'static str,
        next_handle: u64,
        concurrent_insertions: Vec<Value>,
    }

    #[tokio::test]
    async fn socks5_secure_nft_cleans_ipv6_header_rule_in_inet_chain() {
        let rule = json!({
            "family": "inet", "table": "filter", "chain": "input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "nexthdr"}}, "right": 6}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut backend = FakeNft {
            rules: vec![rule.clone()],
            iptables_nft: false,
            chain: "input",
            next_handle: 4,
            concurrent_insertions: Vec::new(),
        };
        let mut ipv4 = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        ipv4.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules.as_slice(), std::slice::from_ref(&rule));

        let listener = "[::]:1080".parse().unwrap();
        let mut ipv6 = FirewallPlan::capture_with(listener, &mut backend)
            .await
            .unwrap();
        let mut concurrent = rule;
        concurrent["handle"] = 3.into();
        backend.rules.push(concurrent.clone());
        assert!(ipv6.close_with(&mut backend).await.is_err());
        assert_eq!(backend.rules, [concurrent]);

        let mut ipv6 = FirewallPlan::capture_with(listener, &mut backend)
            .await
            .unwrap();
        ipv6.close_with(&mut backend).await.unwrap();
        assert!(backend.rules.is_empty());
    }

    impl FirewallExecutor for FakeNft {
        fn available(&self, program: &str) -> bool {
            program == "nft" || (self.iptables_nft && program == "iptables")
        }

        async fn execute(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&[u8]>,
        ) -> Result<String> {
            use serde_json::json;
            if program == "iptables" {
                assert!(self.iptables_nft);
                match args {
                    [version] if version == "--version" => {
                        return Ok("iptables v1.8.9 (nf_tables)".into());
                    }
                    [wait, list, chain] if wait == "-w" && list == "-S" && chain == "INPUT" => {
                        return Ok(if self.rules.iter().any(|rule| rule["handle"] == 2) {
                            "-A INPUT -p tcp -m tcp --dport 1080 -j ACCEPT".into()
                        } else {
                            String::new()
                        });
                    }
                    [_, delete, ..] if delete == "-D" => {
                        self.rules.retain(|rule| rule["handle"] != 2);
                        return Ok(String::new());
                    }
                    _ => panic!("意外 iptables 操作 {args:?}"),
                }
            }
            assert_eq!(program, "nft");
            let echo = args == ["-j", "-s", "-a", "-e", "-f", "-"];
            assert!(echo || args == ["-j", "-s", "-f", "-"]);
            let document: serde_json::Value = serde_json::from_slice(input.unwrap())?;
            let operations = document["nftables"].as_array().unwrap();
            assert_eq!(operations.len(), 1);
            let command = &operations[0];
            if command.get("list").is_some() {
                let mut items = vec![json!({"chain": {
                    "family": self.rules.first().map_or("ip", |rule| rule["family"].as_str().unwrap()),
                    "table": "filter", "name": self.chain, "hook": "input", "type": "filter",
                    "handle": 1
                }})];
                items.extend(self.rules.iter().map(|rule| json!({"rule": rule})));
                return Ok(json!({"nftables": items}).to_string());
            }
            if let Some(rule) = command.get("delete").and_then(|delete| delete.get("rule")) {
                assert!(!echo);
                if !self.iptables_nft {
                    assert_eq!(rule["handle"], self.rules[0]["handle"]);
                }
                let position = self
                    .rules
                    .iter()
                    .position(|live| live["handle"] == rule["handle"]);
                self.rules.remove(position.unwrap());
            } else if let Some(rule) = command.get("add").and_then(|add| add.get("rule")) {
                assert!(rule.get("handle").is_none());
                let mut rule = rule.clone();
                rule["handle"] = self.next_handle.into();
                self.next_handle += 1;
                if echo {
                    self.rules.push(rule.clone());
                    return Ok(json!({"nftables": [{"add": {"rule": rule}}]}).to_string());
                }
                self.rules.push(rule);
            } else {
                self.rules.append(&mut self.concurrent_insertions);
                let mut rule = command["insert"]["rule"].clone();
                if !self.iptables_nft {
                    assert_eq!(rule["handle"], 3);
                }
                let position = self
                    .rules
                    .iter()
                    .position(|live| live["handle"] == rule["handle"]);
                rule["handle"] = self.next_handle.into();
                self.next_handle += 1;
                if echo {
                    self.rules.insert(position.unwrap(), rule.clone());
                    return Ok(json!({"nftables": [{"insert": {"rule": rule}}]}).to_string());
                }
                self.rules.insert(position.unwrap(), rule);
            }
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn socks5_secure_nft_rollback_preserves_concurrently_added_rules() {
        use serde_json::json;
        let original = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let drop = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 3, "expr": [{"drop": null}]
        });
        let mut backend = FakeNft {
            rules: vec![original.clone(), drop.clone()],
            iptables_nft: false,
            chain: "input",
            next_handle: 5,
            concurrent_insertions: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules.as_slice(), std::slice::from_ref(&drop));
        assert!(plan.closure_report().contains("/etc/nftables.conf"));
        let mut concurrent = drop.clone();
        concurrent["handle"] = 4.into();
        concurrent["comment"] = "concurrent".into();
        backend.rules.insert(0, concurrent.clone());
        plan.restore_with(&mut backend).await.unwrap();
        let mut restored = original;
        restored["handle"] = 5.into();
        assert_eq!(backend.rules, [concurrent, restored, drop]);
    }

    #[tokio::test]
    async fn socks5_secure_nft_rollback_appends_after_new_same_port_reject() {
        let original = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut backend = FakeNft {
            rules: vec![original.clone()],
            iptables_nft: false,
            chain: "input",
            next_handle: 4,
            concurrent_insertions: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        let mut reject = original.clone();
        reject["handle"] = 3.into();
        reject["expr"][1] = json!({"reject": null});
        backend.rules.push(reject.clone());
        plan.restore_with(&mut backend).await.unwrap();
        let mut restored = original;
        restored["handle"] = 4.into();
        assert_eq!(backend.rules, [reject, restored]);
    }

    #[tokio::test]
    async fn socks5_secure_nft_removes_only_its_accept_inserted_before_a_concurrent_reject() {
        let allow = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut ssh = allow.clone();
        ssh["handle"] = 3.into();
        ssh["expr"][0]["match"]["right"] = 22.into();
        let mut reject = allow.clone();
        reject["handle"] = 4.into();
        reject["expr"][1] = json!({"reject": null});
        let mut admin_allow = allow.clone();
        admin_allow["handle"] = 5.into();
        let mut backend = FakeNft {
            rules: vec![allow, ssh.clone()],
            iptables_nft: false,
            chain: "input",
            next_handle: 6,
            concurrent_insertions: vec![reject.clone(), admin_allow.clone()],
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules.as_slice(), std::slice::from_ref(&ssh));

        let error = plan.restore_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("相对顺序"));
        assert_eq!(backend.rules, [ssh, reject, admin_allow]);
    }

    #[tokio::test]
    async fn socks5_secure_iptables_nft_rolls_back_compat_and_native_rules_in_same_table() {
        let native = json!({
            "family": "ip", "table": "filter", "chain": "INPUT", "handle": 3,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut compat = native.clone();
        compat["handle"] = 2.into();
        compat["expr"].as_array_mut().unwrap().insert(
            0,
            json!({"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}}),
        );
        compat["expr"]
            .as_array_mut()
            .unwrap()
            .insert(2, json!({"counter": null}));
        let drop = json!({
            "family": "ip", "table": "filter", "chain": "INPUT", "handle": 4,
            "expr": [{"drop": null}]
        });
        let mut backend = FakeNft {
            rules: vec![compat.clone(), native.clone(), drop.clone()],
            iptables_nft: true,
            chain: "INPUT",
            next_handle: 5,
            concurrent_insertions: Vec::new(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules.as_slice(), std::slice::from_ref(&drop));
        plan.restore_with(&mut backend).await.unwrap();
        compat["handle"] = 6.into();
        let mut native = native;
        native["handle"] = 5.into();
        assert_eq!(backend.rules, [compat, native, drop]);
    }

    #[test]
    fn socks5_secure_nft_rules_match_exact_port_and_accept_only() {
        let listener = "0.0.0.0:1080".parse().unwrap();
        let rule = serde_json::json!({"expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
            {"accept": null}
        ]});
        assert!(nft_port_allow(&rule, listener));
        assert!(!nft_port_allow(&rule, "0.0.0.0:1081".parse().unwrap()));
        let mut shared = rule.clone();
        shared["expr"][0]["match"]["right"] = serde_json::json!({"set": [1080, 1081]});
        assert!(!nft_port_allow(&shared, listener));
        let mut drop = rule.clone();
        drop["expr"][1] = serde_json::json!({"drop": null});
        assert!(!nft_port_allow(&drop, listener));
        let mut udp = rule.clone();
        udp["expr"][0]["match"]["left"]["payload"]["protocol"] = "udp".into();
        assert!(!nft_port_allow(&udp, listener));

        let listener = "203.0.113.8:1080".parse().unwrap();
        assert!(!nft_port_allow(&rule, listener));
        let mut scoped = rule;
        let expressions = scoped["expr"].as_array_mut().unwrap();
        expressions.insert(0, serde_json::json!({
            "match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "203.0.113.8"}
        }));
        assert!(nft_port_allow(&scoped, listener));
        scoped["expr"].as_array_mut().unwrap().insert(
            0,
            serde_json::json!({
                "match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                          "right": {"prefix": {"addr": "192.0.2.0", "len": 24}}}
            }),
        );
        assert!(!nft_port_allow(&scoped, listener));
    }
}
