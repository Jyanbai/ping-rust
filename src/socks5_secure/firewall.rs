//! 按原监听地址和 TCP 端口清理专用放行规则。
use super::*;
use serde_json::{json, Value};
use std::{net::IpAddr, ops::Range};

#[cfg(target_os = "linux")]
mod nft_netlink;

trait FirewallExecutor {
    fn available(&self, program: &str) -> bool;
    fn legacy_filter_active(&self, _ipv4: bool) -> Result<bool> {
        Ok(false)
    }
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
    async fn remove_rich_rule(&mut self, _args: &[String]) -> Result<bool> {
        bail!("无法删除 firewalld 持久规则")
    }
    fn nft_generation(&self) -> Result<u32> {
        bail!("无法读取 nftables 规则集代数")
    }
    fn delete_nft_rule(&mut self, _spec: &Value, _handle: u64, _generation: u32) -> Result<bool> {
        bail!("无法执行带代数校验的 nftables 删除")
    }
}

#[cfg(target_os = "linux")]
fn replace_ufw_rules_file(path: &Path, lock_path: &Path, before: &str, after: &str) -> Result<()> {
    use crate::config::FileAccess;
    use rustix::fs::{fcntl_lock, open, FlockOperation, Mode, OFlags};
    use std::{fs, io::Write};

    // ufw 使用 lockf 锁定 /run/ufw.lock。进程级 flock 与这个 POSIX 记录锁互不协调。
    let lock = open(
        lock_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .with_context(|| format!("无法打开 UFW 锁 {}", lock_path.display()))?;
    fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive)
        .context("无法取得 UFW 写锁，请等待其他防火墙操作完成后重试")?;

    let original = fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .with_context(|| format!("无法打开 UFW 持久规则 {}", path.display()))?,
    );
    if !original.metadata()?.is_file() {
        bail!("UFW 持久规则 {} 不是普通文件，请检查防火墙", path.display());
    }
    let access = FileAccess::capture(&original).context("无法读取 UFW 持久规则访问权限")?;
    let mut candidate =
        tempfile::NamedTempFile::new_in(path.parent().context("UFW 规则路径没有父目录")?)
            .context("无法创建 UFW 持久规则候选文件")?;
    candidate
        .write_all(after.as_bytes())
        .context("无法写入 UFW 持久规则候选文件")?;
    access
        .apply(candidate.as_file())
        .context("无法保留 UFW 持久规则访问权限")?;
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

    fn legacy_filter_active(&self, ipv4: bool) -> Result<bool> {
        let path = if ipv4 {
            "/proc/net/ip_tables_names"
        } else {
            "/proc/net/ip6_tables_names"
        };
        match std::fs::read_to_string(path) {
            Ok(tables) => Ok(tables.lines().any(|table| table == "filter")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("无法检查 {path} 中的 legacy 防火墙表"))
            }
        }
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
            .await
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

    async fn remove_rich_rule(&mut self, args: &[String]) -> Result<bool> {
        let output = run_command_output("firewall-cmd", args, None, None, Stdio::piped()).await?;
        firewalld_rich_rule_removed(output.status.code(), &output.stderr)
            .with_context(|| format!("firewall-cmd 持久规则删除失败（{}）", output.status))
    }

    #[cfg(target_os = "linux")]
    fn nft_generation(&self) -> Result<u32> {
        nft_netlink::generation()
    }

    #[cfg(target_os = "linux")]
    fn delete_nft_rule(&mut self, spec: &Value, handle: u64, generation: u32) -> Result<bool> {
        nft_netlink::delete_rule(spec, handle, generation)
    }
}

#[derive(Default)]
pub(super) struct FirewallPlan {
    rules: Vec<Rule>,
    attempted: Vec<Attempt>,
    shared_firewalld_ports: Vec<String>,
    listener: Option<SocketAddr>,
}

enum Rule {
    Ufw {
        text: String,
        scope: UfwScope,
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
    rich_deleted: bool,
}

struct UfwAttempt {
    file: UfwFile,
    entry: Range<usize>,
    kernel: Vec<LiveRule>,
    kernel_position: usize,
    kernel_deleted: bool,
    persistent_deleted: bool,
}

#[derive(Clone, Copy)]
struct UfwScope {
    listener: SocketAddr,
    destination: Option<IpAddr>,
}

impl UfwScope {
    fn matches_destination(self, address: &str) -> bool {
        let Some((ip, prefix)) = address_scope(address) else {
            return false;
        };
        match self.destination {
            Some(destination) => ip == destination && prefix == host_prefix(destination),
            None => prefix == 0 && ip.is_ipv4() == self.listener.is_ipv4(),
        }
    }

    fn tuple_matches(self, tuple: &str) -> bool {
        let mut fields = tuple.split_whitespace().collect::<Vec<_>>();
        if fields
            .last()
            .is_some_and(|field| field.starts_with("comment="))
        {
            fields.pop();
        }
        let ["allow", "tcp", port, destination, "any", source, "in"] = fields.as_slice() else {
            return false;
        };
        port.parse::<u16>().ok() == Some(self.listener.port())
            && self.matches_destination(destination)
            && unrestricted(address_scope(source), self.listener.ip())
    }

    fn kernel_delete_args(self, line: &str, chain: &str) -> Option<Vec<String>> {
        let args = iptables_delete_args_in_chain(line, self.listener, chain)?;
        let (options, _) = args[2..].as_chunks::<2>();
        let destination = options.iter().find(|[option, _]| option == "-d");
        destination
            .map_or(self.destination.is_none(), |[_, address]| {
                self.matches_destination(address)
            })
            .then_some(args)
    }

    fn kernel_count(self, rules: &[LiveRule], chain: &str) -> usize {
        rules
            .iter()
            .filter(|rule| self.kernel_delete_args(&rule.text, chain).is_some())
            .count()
    }
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
                    if let Some((_, text, scope)) = ufw_allow(line, listener) {
                        let rule = Rule::Ufw {
                            text: text.to_owned(),
                            scope,
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
        if managed_firewalld {
            let runtime =
                capture_firewalld(backend, listener, false, &mut plan.shared_firewalld_ports)
                    .await?;
            if let Some(Rule::Rich { base, .. }) = runtime.first() {
                // 同文的持久配置无法证明运行时规则没有独立的超时。
                bail!("firewalld 区域 {} 有匹配 TCP 端口 {} 的运行时 rich rule，无法查询其剩余超时并安全回滚。请先检查并手动处理该规则后重试", base[0], listener.port());
            }
            plan.rules.extend(
                capture_firewalld(backend, listener, true, &mut plan.shared_firewalld_ports)
                    .await?,
            );
        }
        let (program, legacy_program, family) = if listener.is_ipv4() {
            ("iptables", "iptables-legacy", "ip")
        } else {
            ("ip6tables", "ip6tables-legacy", "ip6")
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
            if plan
                .rules
                .iter()
                .any(|rule| matches!(rule, Rule::Nft { .. }))
            {
                backend.nft_generation()?;
            }
        }
        // 切换 alternatives 不会清空内核中的 legacy 表。绑定显式后端，
        // 避免删除、复查或回滚时按当前别名操作另一套表。
        let legacy = if has_iptables && !iptables_nft {
            Some(if backend.available(legacy_program) {
                legacy_program
            } else {
                program
            })
        } else if backend.legacy_filter_active(listener.is_ipv4())? {
            if !backend.available(legacy_program) {
                bail!("检测到 legacy filter 表，请安装提供 {legacy_program} 的 iptables 后重试");
            }
            Some(legacy_program)
        } else {
            None
        };
        if let Some(program) = legacy {
            for rule in iptables_input(backend, program).await?.lines() {
                if iptables_delete_args(rule, listener).is_some() {
                    plan.rules.push(Rule::Iptables {
                        program,
                        text: rule.to_owned(),
                    });
                }
            }
        }
        Ok(plan)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        self.close_with(&mut SystemFirewall::default()).await
    }

    async fn close_with(&mut self, backend: &mut impl FirewallExecutor) -> Result<()> {
        for (index, rule) in self.rules.iter().enumerate() {
            if matches!(rule, Rule::Iptables { .. }) {
                backend
                    .with_xtables_lock(async |backend| {
                        Self::close_rule(backend, rule, &mut self.attempted, index).await
                    })
                    .await?;
            } else {
                Self::close_rule(backend, rule, &mut self.attempted, index).await?;
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

    async fn close_rule(
        backend: &mut impl FirewallExecutor,
        rule: &Rule,
        attempted: &mut Vec<Attempt>,
        index: usize,
    ) -> Result<()> {
        // 确认规则内容之前读取代数。内核在提交删除时同时核对代数和 handle。
        let generation = matches!(rule, Rule::Nft { .. })
            .then(|| backend.nft_generation())
            .transpose()?;
        let before = rule.current(backend).await?;
        let Some(position) = rule.position(&before) else {
            return Ok(());
        };
        let ufw = match rule {
            Rule::Ufw { scope, .. } => {
                Some(UfwAttempt::capture(backend, *scope, &before, position).await?)
            }
            _ => None,
        };
        // 超时或失败也可能已经改动了规则，回滚时先重新查询。
        attempted.push(Attempt {
            rule: index,
            before,
            position,
            ufw,
            rich_deleted: false,
        });
        if let Rule::Nft { spec, .. } = rule {
            let handle = spec["handle"].as_u64().context("nft rule 缺少 handle")?;
            if !backend.delete_nft_rule(spec, handle, generation.unwrap())? {
                // 内核明确拒绝了整笔操作。这个 handle 可能已经属于管理员的新规则。
                attempted.pop();
                bail!("nftables 规则集已并发修改，本次规则未删除，请检查防火墙后重试");
            }
            return Ok(());
        }
        if let Rule::Rich { base, text } = rule {
            let mut args = base.clone();
            args.push(format!("--remove-rich-rule={text}"));
            if backend.remove_rich_rule(&args).await? {
                attempted.last_mut().unwrap().rich_deleted = true;
            } else {
                // firewalld 确认规则已不存在，无需在回滚时补回。
                attempted.pop();
            }
            return Ok(());
        }
        rule.delete(backend, attempted.last_mut().unwrap()).await
    }

    pub(super) async fn restore(&mut self) -> Result<()> {
        self.restore_with(&mut SystemFirewall::default()).await
    }

    async fn restore_with(&mut self, backend: &mut impl FirewallExecutor) -> Result<()> {
        let mut failures = Vec::new();
        for attempt in std::mem::take(&mut self.attempted).into_iter().rev() {
            let port = self.listener.context("缺少原防火墙端口")?.port();
            if let Err(error) = self.rules[attempt.rule]
                .restore(backend, &attempt, port)
                .await
            {
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
                Rule::Rich { .. } => persistent += 1,
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
        let mut report = closure_report(runtime, persistent, nft, iptables);
        for port in &self.shared_firewalld_ports {
            report.push_str(port);
            report.push('\n');
        }
        report
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
            Rule::Ufw { text, scope } => {
                let status = ufw_status(backend).await?;
                if !status.contains("Status: active") {
                    bail!("UFW 已停用，请检查 ufw status");
                }
                let display_scope = ufw_inbound_scope(text).context("无法解析 UFW 规则范围")?;
                let mut displayed = 0;
                for (_, entry) in status.lines().filter_map(ufw_entry) {
                    if entry != text.as_str() && ufw_inbound_scope(entry) == Some(display_scope) {
                        bail!("UFW 存在相同范围的其他规则，请检查 ufw status numbered");
                    }
                    displayed += usize::from(entry == text.as_str());
                }
                let live = UfwFile::load(backend, scope.listener.is_ipv6())?.rules;
                let count = live
                    .iter()
                    .filter(|entry| scope.tuple_matches(&entry.text))
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
            Rule::Ufw { scope, .. } => live.iter().position(|rule| scope.tuple_matches(&rule.text)),
            Rule::Rich { text, .. } | Rule::Iptables { text, .. } => {
                live.iter().position(|rule| rule.text == *text)
            }
            Rule::Nft { spec, .. } => live
                .iter()
                .position(|rule| rule.handle == spec["handle"].as_u64()),
        }
    }

    async fn delete(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &mut Attempt,
    ) -> Result<()> {
        match self {
            Rule::Ufw { scope, .. } => {
                let ufw = attempt.ufw.as_mut().context("缺少 UFW 规则快照")?;
                ufw.delete(backend, *scope).await?;
            }
            Rule::Iptables { program, text } => {
                delete_iptables_rule(backend, program, text).await?;
            }
            Rule::Rich { .. } | Rule::Nft { .. } => unreachable!(),
        }
        Ok(())
    }

    async fn restore(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &Attempt,
        port: u16,
    ) -> Result<()> {
        if matches!(self, Rule::Iptables { .. }) {
            return backend
                .with_xtables_lock(async |backend| self.restore_rule(backend, attempt, port).await)
                .await;
        }
        self.restore_rule(backend, attempt, port).await
    }

    async fn restore_rule(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &Attempt,
        port: u16,
    ) -> Result<()> {
        let current = self.current(backend).await?;
        if let Rule::Ufw { scope, .. } = self {
            return self.restore_ufw(backend, attempt, &current, *scope).await;
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
                .is_some_and(|position| {
                    position < after_new_denials(&attempt.before, &current, port)
                })
            {
                bail!("原放行规则会覆盖新增拒绝规则，无法确认恢复顺序，请检查防火墙");
            }
            return Ok(());
        }
        if let Rule::Rich { base, text } = self {
            if !attempt.rich_deleted {
                bail!("无法确认本次操作删除了 firewalld 持久放行，请检查防火墙");
            }
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
            port,
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
                let generation = backend.nft_generation()?;
                let after = self.current(backend).await?;
                let verified = (|| {
                    verify_insert_order(&current, &after, position, text)?;
                    if after[position].handle != Some(handle) {
                        bail!("无法确认恢复的 nft 放行规则，请检查防火墙");
                    }
                    Ok(())
                })();
                if let Err(error) = verified {
                    if !after
                        .iter()
                        .any(|rule| rule.handle == Some(handle) && rule.text == *text)
                    {
                        return Err(error);
                    }
                    return Err(match backend.delete_nft_rule(spec, handle, generation) {
                        Ok(true) => error,
                        Ok(false) => error.context("规则集已变化，无法撤销 nft 放行规则插入"),
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
        scope: UfwScope,
    ) -> Result<()> {
        let listener = scope.listener;
        let original = attempt.ufw.as_ref().context("缺少 UFW 规则快照")?;
        if self.position(current).is_none() {
            // 内核删除成功不代表持久规则由本次事务删除。
            if !original.persistent_deleted {
                bail!(
                    "无法确认本次操作删除了 UFW 放行，持久规则已变化，请检查 ufw status numbered"
                );
            }
            let position = checked_firewall_restore_position(
                &attempt.before,
                attempt.position,
                current,
                true,
                listener.port(),
            )
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
            || position < after_new_denials(&attempt.before, &persistent, listener.port())
        {
            bail!("UFW 持久规则未恢复原相对顺序，请检查 ufw status numbered");
        }

        let (program, chain) = ufw_kernel_chain(listener);
        let kernel = ufw_kernel_rules(backend, program, chain).await?;
        match scope.kernel_count(&kernel, chain) {
            0 if !original.kernel_deleted => {
                bail!("无法确认本次操作删除了 UFW 内核放行，请检查 {program} -S {chain}");
            }
            0 => {
                // 单独补回目标规则，避免重载整个防火墙。
                let before = &original.kernel;
                let position = checked_firewall_restore_position(
                    before,
                    original.kernel_position,
                    &kernel,
                    true,
                    listener.port(),
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
                            position
                                < after_new_denials(&attempt.before, &persistent, listener.port())
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
                .position(|rule| scope.kernel_delete_args(&rule.text, chain).is_some())
                .is_some_and(|position| {
                    position < after_new_denials(&original.kernel, &kernel, listener.port())
                })
        {
            bail!("UFW 内核规则未恢复原相对顺序，请检查 ufw show raw");
        }
        Ok(())
    }
}

impl UfwAttempt {
    async fn capture(
        backend: &mut impl FirewallExecutor,
        scope: UfwScope,
        before: &[LiveRule],
        position: usize,
    ) -> Result<Self> {
        let listener = scope.listener;
        let file = UfwFile::load(backend, listener.is_ipv6())?;
        if file.rules != before {
            bail!("UFW 持久规则已并发修改，请检查后重试");
        }
        let (program, chain) = ufw_kernel_chain(listener);
        let entry = file.allow_entry(position, scope, chain)?;
        let kernel = ufw_kernel_rules(backend, program, chain).await?;
        if scope.kernel_count(&kernel, chain) != 1 {
            bail!("UFW 内核规则与持久规则无法一一对应，请检查 {program} -S {chain}");
        }
        let kernel_position = kernel
            .iter()
            .position(|rule| scope.kernel_delete_args(&rule.text, chain).is_some())
            .unwrap();
        Ok(Self {
            file,
            entry,
            kernel,
            kernel_position,
            kernel_deleted: false,
            persistent_deleted: false,
        })
    }

    async fn delete(&mut self, backend: &mut impl FirewallExecutor, scope: UfwScope) -> Result<()> {
        let listener = scope.listener;
        // ufw delete 会重载两族用户链。只编辑目标 tuple 及对应内核规则，保留运行时规则。
        let (program, chain) = ufw_kernel_chain(listener);
        let mut args = vec!["-w".into()];
        args.extend(
            scope
                .kernel_delete_args(&self.kernel[self.kernel_position].text, chain)
                .context("无法解析待删除的 UFW 内核规则")?,
        );
        backend.execute(program, &args, None).await?;
        self.kernel_deleted = true;
        backend.replace_ufw_rules_file(
            listener.is_ipv6(),
            &self.file.contents,
            &self.file_without_allow(),
        )?;
        self.persistent_deleted = true;
        let live = ufw_kernel_rules(backend, program, chain).await?;
        if scope.kernel_count(&live, chain) != 0 {
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
    port: u16,
) -> Result<usize> {
    let position = restore_position(before, original, current, use_occurrence)
        .max(after_new_denials(before, current, port));
    verify_restore_position(before, original, current, position)
}

fn after_new_denials(before: &[LiveRule], current: &[LiveRule], port: u16) -> usize {
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
        if is_new && rule_may_deny_port(rule, port) {
            position = index + 1;
        }
    }
    position
}

fn rule_may_deny_port(rule: &LiveRule, port: u16) -> bool {
    if rule.handle.is_some() {
        return serde_json::from_str::<Value>(&rule.text).is_ok_and(|spec| {
            let Some(expressions) = spec["expr"].as_array() else {
                return false;
            };
            // return 在基础链上应用默认策略；跳转和 verdict map 也可能拒绝流量。
            let Some(verdict) = expressions.iter().position(|expr| {
                ["drop", "reject", "return", "jump", "goto", "vmap"]
                    .iter()
                    .any(|action| expr.get(*action).is_some())
            }) else {
                return false;
            };
            !expressions[..verdict].iter().any(|expr| {
                let condition = &expr["match"];
                let payload = &condition["left"]["payload"];
                condition["op"] == "=="
                    && payload["protocol"] == "tcp"
                    && payload["field"] == "dport"
                    && condition["right"]
                        .as_u64()
                        .is_some_and(|value| value != u64::from(port))
            })
        });
    }
    let mut fields = rule.text.split_whitespace();
    if matches!(
        fields.next(),
        Some("deny" | "reject" | "deny_log" | "deny_log-all" | "reject_log" | "reject_log-all")
    ) {
        return !fields
            .nth(1)
            .is_some_and(|value| excludes_destination_port(value, port));
    }
    let words = shell_words(&rule.text);
    words.windows(2).any(|words| {
        // 这里只持有当前链的快照。自定义目标可能进入有拒绝规则的链。
        matches!(words[0].as_str(), "-g" | "--goto")
            || (matches!(words[0].as_str(), "-j" | "--jump")
                && !matches!(words[1].as_str(), "ACCEPT" | "LOG" | "NFLOG"))
    }) && (words.iter().any(|word| word == "!")
        || !words.windows(2).any(|words| {
            matches!(words[0].as_str(), "--dport" | "--destination-port")
                && excludes_destination_port(&words[1], port)
        }))
}

fn excludes_destination_port(value: &str, port: u16) -> bool {
    value.parse::<u16>().is_ok_and(|value| value != port)
        || value.split_once(':').is_some_and(|(start, end)| {
            start
                .parse::<u16>()
                .ok()
                .zip(end.parse::<u16>().ok())
                .is_some_and(|(start, end)| start <= end && !(start..=end).contains(&port))
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

    fn allow_entry(&self, position: usize, scope: UfwScope, chain: &str) -> Result<Range<usize>> {
        let start = self.offsets[position];
        let mut lines = self.contents[start..self.offsets[position + 1]].split_inclusive('\n');
        let tuple = lines.next().context("缺少 UFW tuple")?;
        let rule = lines.next().context("UFW tuple 缺少对应规则")?;
        if scope.kernel_delete_args(rule.trim_end(), chain).is_none()
            || lines.any(|line| !line.trim().is_empty())
        {
            bail!("UFW tuple 与专用放行规则无法一一对应，请检查 user.rules 和 user6.rules");
        }
        Ok(start..start + tuple.len() + rule.len())
    }
}

fn ufw_entry(line: &str) -> Option<(u32, &str)> {
    let (number, text) = line.trim_start().strip_prefix('[')?.split_once(']')?;
    Some((number.trim().parse().ok()?, text.trim()))
}

fn ufw_inbound_scope(text: &str) -> Option<(&str, &str)> {
    let text = ufw_without_comment(text);
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

fn ufw_without_comment(text: &str) -> &str {
    text.split_once(" #").map_or(text, |(rule, _)| rule)
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
    permanent: bool,
    shared_ports: &mut Vec<String>,
) -> Result<Vec<Rule>> {
    let prefix = if permanent {
        vec!["--permanent".into()]
    } else {
        Vec::new()
    };
    let scope = if permanent { "持久" } else { "运行时" };
    let port = format!("{}/tcp", listener.port());
    let mut zones_args = prefix.clone();
    zones_args.push("--get-zones".into());
    let zones = backend.execute("firewall-cmd", &zones_args, None).await?;
    let mut rules = Vec::new();
    for zone in zones.split_whitespace() {
        let mut base = prefix.clone();
        base.push(format!("--zone={zone}"));
        let mut ports = base.clone();
        ports.push("--list-ports".into());
        let output = backend.execute("firewall-cmd", &ports, None).await?;
        if output.split_whitespace().any(|entry| entry == port) {
            // 普通端口放行对双栈有效，不能按单个监听的地址族删除。
            shared_ports.push(format!(
                "firewalld 区域 {zone} 的{scope}端口放行 {port} 适用于 IPv4 和 IPv6，已保留，请手动检查并按需移除。"
            ));
        }
        let mut sources = base.clone();
        sources.push("--list-sources".into());
        if backend
            .execute("firewall-cmd", &sources, None)
            .await?
            .trim()
            .is_empty()
        {
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

fn firewalld_rich_rule_removed(code: Option<i32>, stderr: &[u8]) -> Result<bool> {
    // firewall-cmd 对不存在的规则可能返回 0，并将 NOT_ENABLED 写入 stderr。
    match code {
        Some(12) => Ok(false),
        Some(0) => Ok(!stderr.split(|&byte| byte == b'\n').any(|line| {
            line == b"Warning: NOT_ENABLED" || line.starts_with(b"Warning: NOT_ENABLED:")
        })),
        _ => bail!("无法确认 firewalld 持久规则删除结果，请检查防火墙"),
    }
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

#[cfg(test)]
pub(super) fn ufw_rule_number(line: &str, listener: SocketAddr) -> Option<u32> {
    ufw_allow(line, listener).map(|(number, _, _)| number)
}

fn ufw_allow(line: &str, listener: SocketAddr) -> Option<(u32, &str, UfwScope)> {
    let (number, rule) = ufw_entry(line)?;
    let conditions = ufw_without_comment(rule);
    let (destination, source) = conditions.split_once("ALLOW IN")?;
    let ip = listener.ip();
    let destination = destination.trim();
    let source = source.trim();
    if ufw_is_v6(conditions) != ip.is_ipv6() {
        return None;
    }
    let destination = destination.strip_suffix(" (v6)").unwrap_or(destination);
    let tcp_port = format!("{}/tcp", listener.port());
    let mut fields = destination.split_whitespace();
    let destination = match (fields.next(), fields.next(), fields.next()) {
        (Some(port), None, None) if port == tcp_port && ip.is_unspecified() => None,
        (Some(address), Some(port), None) if port == tcp_port => {
            let scope = address_scope(address)?;
            if !matches_destination(Some(scope), ip) {
                return None;
            }
            (scope.1 != 0).then_some(scope.0)
        }
        _ => return None,
    };
    // 受管节点没有来源范围，保留显式限制来源的规则。
    let anywhere = if ip.is_ipv6() {
        "Anywhere (v6)"
    } else {
        "Anywhere"
    };
    let source_address = source.strip_suffix(" (v6)").unwrap_or(source);
    if source != anywhere && !unrestricted(address_scope(source_address), ip) {
        return None;
    }
    Some((
        number,
        rule,
        UfwScope {
            listener,
            destination,
        },
    ))
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
            ("-m", "tcp" | "comment") | ("--comment", _) => {}
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
        // 回环专用规则仍可供收紧后的监听使用。
        scope.is_some_and(|(ip, prefix)| {
            ip.is_ipv4() == listener.is_ipv4()
                && (prefix == 0 || (prefix == host_prefix(ip) && !ip.is_loopback()))
        })
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
    let mut word_started = false;
    for c in line.chars() {
        if escape {
            word.push(c);
            escape = false;
        } else if c == '\\' && quote != Some('\'') {
            escape = true;
            word_started = true;
        } else if Some(c) == quote {
            quote = None;
        } else if quote.is_some() {
            word.push(c);
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            word_started = true;
        } else if c.is_whitespace() {
            if word_started {
                words.push(std::mem::take(&mut word));
                word_started = false;
            }
        } else {
            word.push(c);
            word_started = true;
        }
    }
    if word_started {
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
    const SCOPED_ALL_SOURCES: &str =
        r#"rule family="ipv4" source address="0.0.0.0/0" port port="1080" protocol="tcp" accept"#;

    #[derive(Default)]
    struct FakeFirewalld {
        rules: [Vec<&'static str>; 2],
        ports: [&'static str; 2],
        runtime_timeout: Option<u32>,
        revoke_before_permanent_removal: bool,
        fail_permanent_removal: Option<&'static str>,
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
                "--list-ports" => Ok(self.ports[permanent].into()),
                "--list-rich-rules" => Ok(self.rules[permanent].join("\n")),
                _ if option.strip_prefix("--add-rich-rule=") == Some(SCOPED) => {
                    assert_eq!(permanent, 1);
                    if self.fail_permanent_restore {
                        bail!("模拟持久规则恢复失败");
                    }
                    self.rules[permanent].push(SCOPED);
                    Ok(String::new())
                }
                _ => panic!("unexpected firewall-cmd arguments: {args:?}"),
            }
        }

        async fn remove_rich_rule(&mut self, args: &[String]) -> Result<bool> {
            assert_eq!(args[0], "--permanent");
            let text = args
                .last()
                .unwrap()
                .strip_prefix("--remove-rich-rule=")
                .unwrap();
            if self.fail_permanent_removal == Some(text) {
                bail!("模拟持久规则删除失败");
            }
            let position = self.rules[1].iter().position(|rule| *rule == text).unwrap();
            self.rules[1].remove(position);
            if std::mem::take(&mut self.revoke_before_permanent_removal) {
                // 管理员先完成删除，firewall-cmd 仍返回成功状态。
                let warning = format!("Warning: NOT_ENABLED: {text}\n");
                return firewalld_rich_rule_removed(Some(0), warning.as_bytes());
            }
            firewalld_rich_rule_removed(Some(0), b"")
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_reports_shared_single_port_allows() {
        for permanent in [false, true] {
            let mut ports = ["1081/tcp 1080/udp", "1079-1081/tcp"];
            ports[usize::from(permanent)] = "1080/tcp";
            let mut backend = FakeFirewalld {
                ports,
                ..Default::default()
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            plan.close_with(&mut backend).await.unwrap();
            let report = plan.closure_report();
            assert_eq!(
                report.contains("firewalld 区域 public 的运行时端口放行 1080/tcp"),
                !permanent
            );
            assert_eq!(
                report.contains("firewalld 区域 public 的持久端口放行 1080/tcp"),
                permanent
            );
            assert!(report.contains("请手动检查"));
            assert!(!report.contains("1081/tcp"));
            assert!(!report.contains("1080/udp"));
            assert!(!report.contains("1079-1081/tcp"));
            plan.restore_with(&mut backend).await.unwrap();
            assert_eq!(backend.ports, ports);
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_keeps_shared_runtime_and_permanent_rules() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED], vec![SHARED, SCOPED]],
            ..Default::default()
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
                ..Default::default()
            };
            let result =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend).await;
            assert!(format!("{:#}", result.err().unwrap()).contains("剩余超时"));
            assert_eq!(backend.rules, rules);
            assert_eq!(backend.runtime_timeout, runtime_timeout);
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_preflight_preserves_paired_runtime_rule_and_timeout() {
        for runtime_timeout in [None, Some(60)] {
            let original = [vec![SHARED, SCOPED], vec![SHARED, SCOPED]];
            let mut backend = FakeFirewalld {
                rules: original.clone(),
                runtime_timeout,
                ..Default::default()
            };
            let error = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                .await
                .err()
                .expect("不能删除无法查询超时的运行时规则");
            assert!(format!("{error:#}").contains("剩余超时"));
            assert_eq!(backend.rules, original);
            assert_eq!(backend.runtime_timeout, runtime_timeout);
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_preserves_concurrent_runtime_rule_and_restores_permanent() {
        for fail_permanent_restore in [false, true] {
            let mut backend = FakeFirewalld {
                rules: [vec![SHARED], vec![SHARED, SCOPED]],
                fail_permanent_restore,
                ..Default::default()
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            backend.rules[0].push(SCOPED);
            backend.runtime_timeout = Some(60);
            let error = plan.close_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("剩余超时"));
            assert_eq!(backend.rules, [vec![SHARED, SCOPED], vec![SHARED]]);
            let restored = plan.restore_with(&mut backend).await;
            if fail_permanent_restore {
                assert!(format!("{:#}", restored.unwrap_err()).contains("持久规则恢复失败"));
                assert_eq!(backend.rules[1], [SHARED]);
            } else {
                restored.unwrap();
                assert_eq!(backend.rules[1], [SHARED, SCOPED]);
            }
            assert_eq!(backend.rules[0], [SHARED, SCOPED]);
            assert_eq!(backend.runtime_timeout, Some(60));
        }
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_does_not_restore_an_allow_revoked_before_removal() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED], vec![SHARED, SCOPED, SCOPED_ALL_SOURCES]],
            revoke_before_permanent_removal: true,
            fail_permanent_removal: Some(SCOPED_ALL_SOURCES),
            ..Default::default()
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        let error = plan.close_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("持久规则删除失败"));
        let remaining = [vec![SHARED], vec![SHARED, SCOPED_ALL_SOURCES]];
        assert_eq!(backend.rules, remaining);
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, remaining);
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_failed_permanent_removal_leaves_rules_unchanged() {
        let original = [vec![SHARED], vec![SHARED, SCOPED]];
        let mut backend = FakeFirewalld {
            rules: original.clone(),
            fail_permanent_removal: Some(SCOPED),
            ..Default::default()
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        let error = plan.close_with(&mut backend).await.unwrap_err();
        assert!(format!("{error:#}").contains("持久规则删除失败"));
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, original);
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

    #[test]
    fn socks5_secure_ufw_matches_commented_persistent_rule() {
        let listener = "0.0.0.0:1080".parse().unwrap();
        let (_, _, scope) =
            ufw_allow("[ 1] 1080/tcp ALLOW IN Anywhere # SOCKS5", listener).unwrap();
        assert!(scope.tuple_matches("allow tcp 1080 0.0.0.0/0 any 0.0.0.0/0 in comment=SOCKS5"));
        assert!(!scope.tuple_matches("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=1080"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socks5_secure_ufw_preserves_an_admin_write_during_rule_replacement() {
        use rustix::fs::{fcntl_lock, getxattr, setxattr, FlockOperation, XattrFlags};
        use std::io::{BufRead, BufReader};
        use std::os::unix::fs::MetadataExt;
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
        let owner = std::fs::metadata(&rules).unwrap().uid();
        let reader = if owner == 65534 { 65533 } else { 65534 };
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, access, id) in [
            (1_u16, 6_u16, u32::MAX),
            (2, 4, reader),
            (4, 0, u32::MAX),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(access.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let attribute = "system.posix_acl_access";
        setxattr(&rules, attribute, &acl, XattrFlags::empty()).unwrap();
        let assert_acl = || {
            let mut value = [0_u8; 44];
            let len = getxattr(&rules, attribute, value.as_mut_slice()).unwrap();
            assert_eq!(&value[..len], acl.as_slice());
        };
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
        assert_acl();
        replace_ufw_rules_file(&rules, &lock, deny, &current).unwrap();
        assert_eq!(std::fs::read_to_string(&rules).unwrap(), current);
        assert_acl();
    }

    struct FakeUfw {
        disk: Vec<&'static str>,
        ipv6: bool,
        kernel_has_rule: bool,
        admin_deletes_before_kernel_delete: bool,
        admin_deletes_before_disk_update: bool,
        keep_disk_on_delete_failure: bool,
        fail_close_check: bool,
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
            let allow = if v6 { IPV6 } else { IPV4 };
            if self.admin_deletes_before_disk_update && before.contains("--dport 1080 -j ACCEPT") {
                assert!(!self.kernel_has_rule);
                self.admin_deletes_before_disk_update = false;
                self.disk.retain(|entry| *entry != allow);
                assert_ne!(before, self.ufw_rules_file(v6)?);
                bail!("UFW 持久规则已并发修改，请检查后重试");
            }
            assert_eq!(before, self.ufw_rules_file(v6)?);
            if let Some(index) = self.disk.iter().position(|entry| *entry == allow) {
                assert!(!after.contains("-p tcp --dport 1080 -j ACCEPT"));
                if !self.delete_succeeds && self.keep_disk_on_delete_failure {
                    self.disk.insert(0, OTHER);
                    bail!("模拟 UFW 持久规则写入失败");
                }
                self.disk.remove(index);
                if !self.delete_succeeds {
                    self.disk.insert(0, OTHER);
                    self.fail_close_check = true;
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
                        if std::mem::take(&mut self.fail_close_check) {
                            bail!("模拟 UFW 持久规则提交后的内核查询失败");
                        }
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
                        if action == "-D" && self.admin_deletes_before_kernel_delete {
                            self.admin_deletes_before_kernel_delete = false;
                            self.kernel_has_rule = false;
                            let allow = if self.ipv6 { IPV6 } else { IPV4 };
                            self.disk.retain(|entry| *entry != allow);
                            bail!("管理员已删除 UFW 放行，内核规则不存在");
                        }
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
    async fn socks5_secure_ufw_does_not_restore_an_allow_deleted_by_the_admin() {
        for (address, ipv6) in [("0.0.0.0:1080", false), ("[::]:1080", true)] {
            let mut backend = FakeUfw {
                disk: vec![IPV4, IPV6],
                ipv6,
                kernel_has_rule: true,
                admin_deletes_before_kernel_delete: true,
                admin_deletes_before_disk_update: false,
                keep_disk_on_delete_failure: false,
                fail_close_check: false,
                kernel_reorders_on_insert: false,
                other_family_runtime_rule: true,
                delete_succeeds: true,
            };
            let mut plan = FirewallPlan::capture_with(address.parse().unwrap(), &mut backend)
                .await
                .unwrap();
            let error = plan.close_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("管理员已删除"));
            let error = plan.restore_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("无法确认"));
            assert_eq!(backend.disk, [if ipv6 { IPV4 } else { IPV6 }]);
            assert!(!backend.kernel_has_rule);
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_does_not_restore_an_allow_revoked_before_disk_commit() {
        for (address, ipv6) in [("0.0.0.0:1080", false), ("[::]:1080", true)] {
            let mut backend = FakeUfw {
                disk: vec![IPV4, IPV6],
                ipv6,
                kernel_has_rule: true,
                admin_deletes_before_kernel_delete: false,
                admin_deletes_before_disk_update: true,
                keep_disk_on_delete_failure: false,
                fail_close_check: false,
                kernel_reorders_on_insert: false,
                other_family_runtime_rule: true,
                delete_succeeds: true,
            };
            let mut plan = FirewallPlan::capture_with(address.parse().unwrap(), &mut backend)
                .await
                .unwrap();
            let error = plan.close_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("UFW 持久规则已并发修改"));
            let error = plan.restore_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("无法确认"));
            assert_eq!(backend.disk, [if ipv6 { IPV4 } else { IPV6 }]);
            assert!(!backend.kernel_has_rule);
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_preserves_runtime_ipv6_deny_during_ipv4_close_and_rollback() {
        let mut backend = FakeUfw {
            disk: vec![IPV4, IPV6],
            ipv6: false,
            kernel_has_rule: true,
            admin_deletes_before_kernel_delete: false,
            admin_deletes_before_disk_update: false,
            keep_disk_on_delete_failure: false,
            fail_close_check: false,
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
    async fn socks5_secure_ufw_closes_and_restores_same_family_destination_scopes() {
        struct ScopedUfw {
            disk: String,
            kernel: Vec<String>,
        }

        impl FirewallExecutor for ScopedUfw {
            fn available(&self, program: &str) -> bool {
                matches!(program, "ufw" | "iptables")
            }

            fn ufw_rules_file(&self, v6: bool) -> Result<String> {
                assert!(!v6);
                Ok(self.disk.clone())
            }

            fn replace_ufw_rules_file(
                &mut self,
                v6: bool,
                before: &str,
                after: &str,
            ) -> Result<()> {
                assert!(!v6);
                assert_eq!(before, self.disk);
                self.disk = after.to_owned();
                Ok(())
            }

            async fn execute(
                &mut self,
                program: &str,
                args: &[String],
                input: Option<&[u8]>,
            ) -> Result<String> {
                assert!(input.is_none());
                if program == "ufw" {
                    assert_eq!(args, ["status", "numbered"]);
                    let mut status = String::from("Status: active\n");
                    for (index, tuple) in self
                        .disk
                        .lines()
                        .filter(|line| line.starts_with("### tuple ###"))
                        .enumerate()
                    {
                        let destination = if tuple.contains("203.0.113.8") {
                            "203.0.113.8 "
                        } else {
                            ""
                        };
                        status.push_str(&format!(
                            "[{}] {destination}1080/tcp ALLOW IN Anywhere\n",
                            index + 1
                        ));
                    }
                    return Ok(status);
                }
                assert_eq!(program, "iptables");
                if args == ["--version"] {
                    return Ok("iptables v1.8.9 (legacy)".into());
                }
                if args == ["-w", "-S", "INPUT"] {
                    return Ok("-P INPUT ACCEPT".into());
                }
                assert_eq!(args[2], "ufw-user-input");
                match args[1].as_str() {
                    "-S" => return Ok(self.kernel.join("\n")),
                    "-D" => {
                        let rule = format!("-A {}", args[2..].join(" "));
                        let index = self.kernel.iter().position(|entry| *entry == rule).unwrap();
                        self.kernel.remove(index);
                    }
                    "-I" => {
                        let index = args[3].parse::<usize>().unwrap() - 1;
                        self.kernel
                            .insert(index, format!("-A {} {}", args[2], args[4..].join(" ")));
                    }
                    "-A" => self.kernel.push(format!("-A {}", args[2..].join(" "))),
                    _ => panic!("意外操作 {args:?}"),
                }
                Ok(String::new())
            }
        }

        let wildcard = "-A ufw-user-input -p tcp --dport 1080 -j ACCEPT";
        let host = "-A ufw-user-input -d 203.0.113.8/32 -p tcp --dport 1080 -j ACCEPT";
        let deny = "-A ufw-user-input -s 192.0.2.2/32 -p tcp --dport 1080 -j DROP";
        let end = "### END RULES ###\nCOMMIT\n";
        let disk = format!(
            "### tuple ### allow tcp 1080 0.0.0.0/0 any 0.0.0.0/0 in\n{wildcard}\n\
             ### tuple ### allow tcp 1080 203.0.113.8 any 0.0.0.0/0 in\n{host}\n{end}"
        );
        let kernel = [wildcard, deny, host].map(str::to_owned).to_vec();
        let mut backend = ScopedUfw {
            disk: disk.clone(),
            kernel: kernel.clone(),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        assert_eq!(plan.rules.len(), 2);
        let current = plan.rules[0].current(&mut backend).await.unwrap();
        assert_eq!(plan.rules[0].position(&current), Some(0));
        assert_eq!(plan.rules[1].position(&current), Some(1));
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.disk, end);
        assert_eq!(backend.kernel, [deny]);
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.disk, disk);
        assert_eq!(backend.kernel, kernel);
    }

    #[tokio::test]
    async fn socks5_secure_ufw_partial_failure_restores_only_the_removed_family() {
        let mut backend = FakeUfw {
            disk: vec![IPV4, IPV6],
            ipv6: false,
            kernel_has_rule: true,
            admin_deletes_before_kernel_delete: false,
            admin_deletes_before_disk_update: false,
            keep_disk_on_delete_failure: false,
            fail_close_check: false,
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
                    admin_deletes_before_kernel_delete: false,
                    admin_deletes_before_disk_update: false,
                    keep_disk_on_delete_failure,
                    fail_close_check: false,
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
                admin_deletes_before_kernel_delete: false,
                admin_deletes_before_disk_update: false,
                keep_disk_on_delete_failure: false,
                fail_close_check: false,
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
                admin_deletes_before_kernel_delete: false,
                admin_deletes_before_disk_update: false,
                keep_disk_on_delete_failure: false,
                fail_close_check: false,
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
            assert!(kernel
                .iter()
                .any(|rule| rule.text.ends_with("--dport 1080 -j DROP")));
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
        locked: bool,
        insert_after_snapshot: Option<&'static str>,
    }

    impl FirewallExecutor for FakeIptables {
        fn available(&self, program: &str) -> bool {
            program == "iptables"
        }

        async fn with_xtables_lock<T>(
            &mut self,
            operation: impl AsyncFnOnce(&mut Self) -> Result<T>,
        ) -> Result<T> {
            assert!(!self.locked);
            self.locked = true;
            let result = operation(self).await;
            self.locked = false;
            result
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
                let snapshot = self.rules.join("\n");
                if !self.locked {
                    if let Some(rule) = self.insert_after_snapshot.take() {
                        self.rules.insert(0, rule.into());
                    }
                }
                return Ok(snapshot);
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
    async fn socks5_secure_iptables_serializes_snapshot_and_deletion() {
        let accept = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let reject = "-A INPUT -p tcp --dport 1080 -j REJECT";
        let mut backend = FakeIptables {
            rules: vec![reject.into(), accept.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
            locked: false,
            insert_after_snapshot: None,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        backend.insert_after_snapshot = Some(accept);

        // 管理员在读取快照后尝试插入同文规则，只有持锁时才会等到删除结束。
        let result = plan.close_with(&mut backend).await;
        assert_eq!(backend.rules, [accept, reject]);
        result.unwrap();
        assert_eq!(backend.deletions, 1);
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
            locked: false,
            insert_after_snapshot: None,
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
                locked: false,
                insert_after_snapshot: None,
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
            locked: false,
            insert_after_snapshot: None,
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
            locked: false,
            insert_after_snapshot: None,
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
            locked: false,
            insert_after_snapshot: None,
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
            locked: false,
            insert_after_snapshot: None,
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
            locked: false,
            insert_after_snapshot: None,
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

    #[tokio::test]
    async fn socks5_secure_iptables_keeps_new_chain_transfers_before_restored_allow() {
        let allow = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let ssh = "-A INPUT -p tcp --dport 22 -j ACCEPT";
        // INPUT 的快照只包含跳转入口，看不到目标链内部的拒绝规则。
        for transfer in [
            "-A INPUT -p tcp --dport 1080 -j admin-deny",
            "-A INPUT -p tcp --dport 1080 -g admin-deny",
        ] {
            let mut backend = FakeIptables {
                rules: vec![allow.into(), ssh.into()],
                deletions: 0,
                fail_second_deletion: false,
                drop_before_insert: None,
                rules_after_insert: Vec::new(),
                locked: false,
                insert_after_snapshot: None,
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            plan.close_with(&mut backend).await.unwrap();
            backend.rules.push(transfer.into());
            let error = plan.restore_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("顺序"));
            assert_eq!(backend.rules, [ssh, transfer]);
        }
    }

    #[tokio::test]
    async fn socks5_secure_iptables_restores_before_ssh_with_new_reject_on_another_port() {
        let allow = "-A INPUT -p tcp --dport 1080 -j ACCEPT";
        let ssh = "-A INPUT -p tcp --dport 22 -j ACCEPT";
        let reject = "-A INPUT -p tcp --dport 8443 -j REJECT";
        let mut backend = FakeIptables {
            rules: vec![allow.into(), ssh.into()],
            deletions: 0,
            fail_second_deletion: false,
            drop_before_insert: None,
            rules_after_insert: Vec::new(),
            locked: false,
            insert_after_snapshot: None,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        backend.rules.push(reject.into());
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [allow, ssh, reject]);
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
        replace_before_delete: Option<Value>,
    }

    #[tokio::test]
    async fn socks5_secure_nft_closes_and_restores_commented_allow() {
        let mut rule = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 2,
            "comment": "SOCKS5",
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut backend = FakeNft {
            rules: vec![rule.clone()],
            iptables_nft: false,
            chain: "input",
            next_handle: 3,
            concurrent_insertions: Vec::new(),
            replace_before_delete: None,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert!(backend.rules.is_empty());
        plan.restore_with(&mut backend).await.unwrap();
        rule["handle"] = 3.into();
        assert_eq!(backend.rules, [rule]);
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
            replace_before_delete: None,
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

    #[tokio::test]
    async fn socks5_secure_nft_preserves_rule_replaced_after_snapshot() {
        let allow = json!({
            "family": "ip", "table": "filter", "chain": "input", "handle": 2,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
                {"accept": null}
            ]
        });
        let mut reject = allow.clone();
        reject["expr"][1] = json!({"reject": null});
        let mut backend = FakeNft {
            rules: vec![allow],
            iptables_nft: false,
            chain: "input",
            next_handle: 3,
            concurrent_insertions: Vec::new(),
            replace_before_delete: Some(reject.clone()),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        assert!(plan.close_with(&mut backend).await.is_err());
        assert_eq!(backend.rules.as_slice(), std::slice::from_ref(&reject));
        plan.restore_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [reject]);
    }

    impl FirewallExecutor for FakeNft {
        fn available(&self, program: &str) -> bool {
            program == "nft" || (self.iptables_nft && program == "iptables")
        }

        fn nft_generation(&self) -> Result<u32> {
            Ok(1)
        }

        fn delete_nft_rule(&mut self, spec: &Value, handle: u64, generation: u32) -> Result<bool> {
            assert_eq!(generation, 1);
            let position = self
                .rules
                .iter()
                .position(|live| {
                    live["handle"].as_u64() == Some(handle)
                        && live["family"] == spec["family"]
                        && live["table"] == spec["table"]
                        && live["chain"] == spec["chain"]
                })
                .unwrap();
            if let Some(replacement) = self.replace_before_delete.take() {
                self.rules[position] = replacement;
                return Ok(false);
            }
            self.rules.remove(position);
            Ok(true)
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
                    "handle": 1, "policy": "drop"
                }})];
                items.extend(self.rules.iter().map(|rule| json!({"rule": rule})));
                return Ok(json!({"nftables": items}).to_string());
            }
            if let Some(rule) = command.get("add").and_then(|add| add.get("rule")) {
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
            replace_before_delete: None,
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
            replace_before_delete: None,
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
    async fn socks5_secure_nft_keeps_new_chain_transfers_before_restored_allow() {
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
        for (verdict, detail) in [
            ("jump", json!({"target": "admin-deny"})),
            ("goto", json!({"target": "admin-deny"})),
            ("return", Value::Null),
        ] {
            let mut backend = FakeNft {
                rules: vec![allow.clone(), ssh.clone()],
                iptables_nft: false,
                chain: "input",
                next_handle: 5,
                concurrent_insertions: Vec::new(),
                replace_before_delete: None,
            };
            let mut plan =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
            plan.close_with(&mut backend).await.unwrap();
            let mut transfer = allow.clone();
            transfer["handle"] = 4.into();
            transfer["expr"][1] = json!({(verdict): detail});
            backend.rules.push(transfer.clone());
            let error = plan.restore_with(&mut backend).await.unwrap_err();
            assert!(format!("{error:#}").contains("顺序"));
            assert_eq!(backend.rules, [ssh.clone(), transfer]);
        }
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
            replace_before_delete: None,
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
            replace_before_delete: None,
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
