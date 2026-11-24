//! 按原监听地址和 TCP 端口清理专用放行规则。
use super::*;
use serde_json::{json, Value};
use std::net::IpAddr;

trait FirewallExecutor {
    fn available(&self, program: &str) -> bool;
    fn ufw_rules_file(&self, v6: bool) -> Result<String> {
        let path = if v6 {
            "/etc/ufw/user6.rules"
        } else {
            "/etc/ufw/user.rules"
        };
        std::fs::read_to_string(path).with_context(|| format!("无法读取 UFW 内部规则 {path}"))
    }
    async fn execute(
        &mut self,
        program: &str,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<String>;
}

struct SystemFirewall;

impl FirewallExecutor for SystemFirewall {
    fn available(&self, program: &str) -> bool {
        utils::command_exists(program)
    }

    async fn execute(
        &mut self,
        program: &str,
        args: &[String],
        input: Option<&[u8]>,
    ) -> Result<String> {
        command(program, args, input).await
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
    ufw_kernel_before: Vec<LiveRule>,
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
        Self::capture_with(listener, &mut SystemFirewall).await
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
        if managed_firewalld {
            for prefix in [vec![], vec!["--permanent".to_owned()]] {
                let mut zones_args = prefix.clone();
                zones_args.push("--get-zones".into());
                for zone in backend
                    .execute("firewall-cmd", &zones_args, None)
                    .await?
                    .split_whitespace()
                {
                    let mut base = prefix.clone();
                    base.push(format!("--zone={zone}"));
                    let mut sources = base.clone();
                    sources.push("--list-sources".into());
                    if !backend
                        .execute("firewall-cmd", &sources, None)
                        .await?
                        .trim()
                        .is_empty()
                    {
                        continue;
                    }
                    // 普通端口放行作用于双栈，只查询能明确限定地址族的 rich rule。
                    let mut args = base.clone();
                    args.push("--list-rich-rules".into());
                    let output = backend.execute("firewall-cmd", &args, None).await?;
                    let rules = firewalld_rules(&output, listener, &base);
                    // firewalld 不公开运行时规则的剩余超时；持久规则也不能证明它没有超时。
                    if prefix.is_empty() && !rules.is_empty() {
                        bail!("firewalld 区域 {zone} 有匹配 TCP 端口 {} 的运行时 rich rule，无法查询其剩余超时并安全回滚。请先检查并手动处理该规则后重试", listener.port());
                    }
                    plan.rules.extend(rules);
                }
            }
        }
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
        // UFW 和 firewalld 仍通过各自接口修改持久配置。
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
        Ok(plan)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        self.close_with(&mut SystemFirewall).await
    }

    async fn close_with(&mut self, backend: &mut impl FirewallExecutor) -> Result<()> {
        for (index, rule) in self.rules.iter().enumerate() {
            let before = rule.current(backend).await?;
            if let Some(position) = rule.position(&before) {
                let count = matching_rule_count(&before, &before[position].text);
                let ufw_kernel_before = rule.verify_ufw_kernel(backend, count).await?;
                // 超时或失败也可能已经改动了规则，回滚时先重新查询。
                self.attempted.push(Attempt {
                    rule: index,
                    before,
                    position,
                    ufw_kernel_before,
                });
                rule.delete(backend).await?;
                rule.verify_ufw_kernel(backend, count - 1).await?;
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
        self.restore_with(&mut SystemFirewall).await
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
                let live = ufw_tuples(backend, listener.is_ipv6())?;
                let count = live
                    .iter()
                    .filter(|entry| ufw_tuple_allow(&entry.text, *listener))
                    .count();
                if count != displayed || count > 1 {
                    bail!("UFW 显示规则与内部规则无法一一对应，请检查 ufw status numbered 和 user.rules");
                }
                Ok(live)
            }
            Rule::Rich { base, .. } => {
                let mut args = base.clone();
                args.push("--list-rich-rules".into());
                Ok(backend
                    .execute("firewall-cmd", &args, None)
                    .await?
                    .lines()
                    .map(str::trim)
                    .map(LiveRule::from)
                    .collect())
            }
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

    async fn delete(&self, backend: &mut impl FirewallExecutor) -> Result<()> {
        match self {
            Rule::Ufw { listener, .. } => {
                let mut args = vec!["--force".into(), "delete".into()];
                args.extend(ufw_allow_args(*listener));
                backend.execute("ufw", &args, None).await?;
            }
            Rule::Rich { base, text } => {
                let mut args = base.clone();
                args.push(format!("--remove-rich-rule={text}"));
                backend.execute("firewall-cmd", &args, None).await?;
            }
            Rule::Iptables { program, text } => {
                let words = shell_words(text);
                let mut args = vec!["-w".into(), "-D".into()];
                args.extend_from_slice(&words[1..]);
                backend.execute(program, &args, None).await?;
            }
            Rule::Nft { spec, .. } => {
                nft_command(
                    backend,
                    json!({"delete": {"rule": {
                        "family": spec["family"], "table": spec["table"],
                        "chain": spec["chain"], "handle": spec["handle"],
                    }}}),
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn restore(&self, backend: &mut impl FirewallExecutor, attempt: &Attempt) -> Result<()> {
        let current = self.current(backend).await?;
        if let Rule::Ufw { listener, .. } = self {
            return self.restore_ufw(backend, attempt, current, *listener).await;
        }
        let text = &attempt.before[attempt.position].text;
        let original_count = matching_rule_count(&attempt.before, text);
        let current_count = matching_rule_count(&current, text);
        if current_count >= original_count {
            if !matches!(self, Rule::Rich { .. }) && !contains_rule_order(&attempt.before, &current)
            {
                bail!("原放行规则的相对顺序已变化，请检查防火墙");
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
        let position = checked_restore_position(
            &attempt.before,
            attempt.position,
            &current,
            matches!(self, Rule::Iptables { .. }),
        )?;
        match self {
            Rule::Ufw { .. } | Rule::Rich { .. } => unreachable!(),
            Rule::Iptables { program, text } => {
                insert_iptables(backend, program, text, position, current.len()).await?;
            }
            Rule::Nft { spec, .. } => {
                let mut rule = spec.clone();
                rule.as_object_mut().unwrap().remove("handle");
                if let Some(next) = current.get(position) {
                    rule["handle"] = next.handle.context("nft 恢复定位缺少 handle")?.into();
                    nft_command(backend, json!({"insert": {"rule": rule}})).await?;
                } else {
                    nft_command(backend, json!({"add": {"rule": rule}})).await?;
                }
            }
        }
        verify_insert_order(&current, &self.current(backend).await?, position, text)
    }

    async fn restore_ufw(
        &self,
        backend: &mut impl FirewallExecutor,
        attempt: &Attempt,
        current: Vec<LiveRule>,
        listener: SocketAddr,
    ) -> Result<()> {
        let result = if self.position(&current).is_some() {
            Ok(())
        } else {
            let position =
                checked_restore_position(&attempt.before, attempt.position, &current, true)
                    .context("无法恢复 UFW 持久规则，请检查 ufw status numbered")?;
            let mut args = vec![];
            if position < current.len() {
                // insert 使用每个内部 tuple 的位置，IPv6 还要加上 IPv4 tuple 总数。
                let offset = if listener.is_ipv6() {
                    ufw_tuples(backend, false)?.len()
                } else {
                    0
                };
                args.extend(["insert".into(), (offset + position + 1).to_string()]);
            }
            args.extend(ufw_allow_args(listener));
            backend.execute("ufw", &args, None).await.map(|_| ())
        };
        let persistent = self.current(backend).await?;
        if self.position(&persistent).is_none() {
            result?;
            bail!("UFW 持久规则未恢复，请检查 ufw status numbered");
        }
        if !contains_rule_order(&attempt.before, &persistent) {
            bail!("UFW 持久规则未恢复原相对顺序，请检查 ufw status numbered");
        }

        let (program, chain) = ufw_kernel_chain(listener);
        let mut kernel = ufw_kernel_rules(backend, program, chain).await?;
        match ufw_kernel_count(&kernel, listener, chain) {
            0 => {
                // ufw 可能先写盘后修改内核。只补回原内核规则，避免重载整个防火墙。
                let before = &attempt.ufw_kernel_before;
                let original = before
                    .iter()
                    .position(|rule| {
                        iptables_delete_args_in_chain(&rule.text, listener, chain).is_some()
                    })
                    .context("缺少原 UFW 内核规则，请检查 ufw show raw")?;
                let position = checked_restore_position(before, original, &kernel, true)
                    .context("无法恢复 UFW 内核规则")?;
                let text = &before[original].text;
                insert_iptables(backend, program, text, position, kernel.len()).await?;
                let restored = self.verify_ufw_kernel(backend, 1).await?;
                verify_insert_order(&kernel, &restored, position, text)?;
                if !contains_rule_order(&attempt.before, &self.current(backend).await?) {
                    bail!("补回内核规则时 UFW 持久规则已变化，请检查 ufw status numbered");
                }
                kernel = restored;
            }
            1 => {}
            count => bail!("UFW 内核规则数量为 {count}，预期为 1，请检查 ufw show raw"),
        }
        if !contains_rule_order(&attempt.ufw_kernel_before, &kernel) {
            bail!("UFW 内核规则未恢复原相对顺序，请检查 ufw show raw");
        }
        Ok(())
    }

    async fn verify_ufw_kernel(
        &self,
        backend: &mut impl FirewallExecutor,
        expected: usize,
    ) -> Result<Vec<LiveRule>> {
        let Rule::Ufw { listener, .. } = self else {
            return Ok(Vec::new());
        };
        let (program, chain) = ufw_kernel_chain(*listener);
        let rules = ufw_kernel_rules(backend, program, chain).await?;
        let count = ufw_kernel_count(&rules, *listener, chain);
        if count != expected {
            bail!("UFW 内核规则数量为 {count}，预期为 {expected}，请检查 {program} -S {chain} 和 ufw status numbered");
        }
        Ok(rules)
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

fn checked_restore_position(
    before: &[LiveRule],
    original: usize,
    current: &[LiveRule],
    use_occurrence: bool,
) -> Result<usize> {
    let position = restore_position(before, original, current, use_occurrence);
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

fn ufw_tuples(backend: &impl FirewallExecutor, v6: bool) -> Result<Vec<LiveRule>> {
    backend
        .ufw_rules_file(v6)?
        .lines()
        .filter_map(|line| line.strip_prefix("### tuple ###"))
        .map(|tuple| {
            let mut fields = tuple.split_whitespace().collect::<Vec<_>>();
            let has_comment = fields
                .last()
                .is_some_and(|field| field.starts_with("comment="));
            let field_count = fields.len() - usize::from(has_comment);
            match field_count {
                // 兼容 UFW 早期省略方向字段的 tuple，UFW 重新写入时会补上 in。
                6 | 8 => fields.insert(field_count, "in"),
                7 | 9 => {}
                _ => bail!("无法解析 UFW 内部规则，请检查 user.rules 和 user6.rules"),
            }
            Ok(LiveRule {
                text: fields.join(" "),
                handle: None,
            })
        })
        .collect()
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

fn ufw_allow_args(listener: SocketAddr) -> Vec<String> {
    // UFW interprets the literal `any` as both families. Explicit /0 fixes the family.
    let source = if listener.is_ipv4() {
        "0.0.0.0/0"
    } else {
        "::/0"
    };
    let destination = if listener.ip().is_unspecified() {
        source.to_owned()
    } else {
        listener.ip().to_string()
    };
    vec![
        "allow".into(),
        "proto".into(),
        "tcp".into(),
        "from".into(),
        source.into(),
        "to".into(),
        destination,
        "port".into(),
        listener.port().to_string(),
    ]
}

async fn iptables_input(backend: &mut impl FirewallExecutor, program: &str) -> Result<String> {
    backend
        .execute(program, &["-w".into(), "-S".into(), "INPUT".into()], None)
        .await
}

async fn nft_list(backend: &mut impl FirewallExecutor, target: Value) -> Result<Vec<Value>> {
    let output = nft_command(backend, json!({"list": target})).await?;
    let mut value: Value = serde_json::from_str(&output).context("解析 nft 规则失败")?;
    let Value::Array(items) = value["nftables"].take() else {
        bail!("nft 输出缺少规则列表");
    };
    Ok(items)
}

async fn nft_command(backend: &mut impl FirewallExecutor, operation: Value) -> Result<String> {
    let input = serde_json::to_vec(&json!({"nftables": [operation]}))?;
    backend
        .execute(
            "nft",
            &["-j".into(), "-s".into(), "-f".into(), "-".into()],
            Some(&input),
        )
        .await
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
        if (condition["left"]["meta"]["key"] == "l4proto"
            || (payload["protocol"] == ip_family && payload["field"] == header_protocol))
            && (value == "tcp" || value.as_u64() == Some(6))
        {
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
                    self.rules[permanent].push(SCOPED);
                    if permanent == 0 {
                        self.runtime_timeout = None;
                    }
                    Ok(String::new())
                }
                _ => {
                    assert_eq!(option, &format!("--remove-rich-rule={SCOPED}"));
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
        for (runtime_timeout, in_permanent) in [(None, false), (Some(60), true)] {
            let rules = [
                vec![SHARED, SCOPED],
                if in_permanent {
                    vec![SHARED, SCOPED]
                } else {
                    vec![SHARED]
                },
            ];
            let mut backend = FakeFirewalld {
                rules: rules.clone(),
                runtime_timeout,
            };
            let result =
                FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend).await;
            assert!(format!("{:#}", result.err().unwrap()).contains("剩余超时"));
            assert_eq!(backend.rules, rules);
            assert_eq!(backend.runtime_timeout, runtime_timeout);
        }
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

    struct FakeUfw {
        disk: Vec<&'static str>,
        ipv6: bool,
        kernel_has_rule: bool,
        apply_to_kernel: bool,
        keep_disk_on_delete_failure: bool,
        kernel_reorders_on_insert: bool,
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
                }
            }
            Ok(file)
        }

        async fn execute(
            &mut self,
            program: &str,
            args: &[String],
            input: Option<&[u8]>,
        ) -> Result<String> {
            assert!(input.is_none());
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
                    [wait, append, chain, rule @ ..] if append == "-A" => {
                        assert_eq!(wait, "-w");
                        assert_eq!(chain, kernel_chain);
                        assert_eq!(
                            rule,
                            ["-p", "tcp", "-m", "tcp", "--dport", "1080", "-j", "ACCEPT"]
                        );
                        assert!(!self.kernel_has_rule);
                        self.kernel_has_rule = true;
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
                    if !self.keep_disk_on_delete_failure {
                        let index = self.disk.iter().position(|entry| *entry == rule).unwrap();
                        assert_eq!(self.disk.remove(index), rule);
                    }
                    self.disk.insert(0, OTHER);
                    bail!("模拟 UFW 删除后失败");
                }
                "allow" | "insert" => {
                    assert!(!self.keep_disk_on_delete_failure);
                    let family_end = if self.ipv6 {
                        self.disk.len()
                    } else {
                        self.disk
                            .iter()
                            .position(|entry| ufw_is_v6(entry))
                            .unwrap_or(self.disk.len())
                    };
                    let position = if args[0] == "insert" {
                        assert_eq!(args[2..], spec);
                        let requested = args[1].parse::<usize>().unwrap();
                        let mut internal = 1;
                        self.disk
                            .iter()
                            .position(|entry| {
                                // UFW 将落进应用分组的插入点推进到分组末尾。
                                let hit = internal >= requested;
                                internal += if *entry == APP { 2 } else { 1 };
                                hit
                            })
                            .unwrap_or(family_end)
                    } else {
                        assert_eq!(args, spec);
                        family_end
                    };
                    self.disk.insert(position, rule);
                    if !self.apply_to_kernel {
                        bail!("模拟 UFW 写入持久规则后追加内核规则失败");
                    }
                    self.kernel_has_rule = true;
                    Ok(String::new())
                }
                _ => panic!("意外操作 {args:?}"),
            }
        }
    }

    #[tokio::test]
    async fn socks5_secure_ufw_partial_failure_restores_only_the_removed_family() {
        let mut backend = FakeUfw {
            disk: vec![IPV4, IPV6],
            ipv6: false,
            kernel_has_rule: true,
            apply_to_kernel: true,
            keep_disk_on_delete_failure: false,
            kernel_reorders_on_insert: false,
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
                    apply_to_kernel: false,
                    keep_disk_on_delete_failure,
                    kernel_reorders_on_insert: false,
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
                apply_to_kernel: true,
                keep_disk_on_delete_failure: false,
                kernel_reorders_on_insert: false,
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
                apply_to_kernel: true,
                keep_disk_on_delete_failure: false,
                kernel_reorders_on_insert: false,
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
            assert!(backend.kernel_has_rule);
            assert_eq!(
                backend.disk.iter().filter(|entry| **entry == IPV4).count(),
                1
            );
        }
    }

    struct FakeIptables {
        rules: Vec<String>,
        deletions: usize,
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
            match args[1].as_str() {
                "-D" => {
                    self.deletions += 1;
                    // 第二次删除失败前，另一个工具插入无关规则。
                    if self.deletions == 2 {
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
                    self.rules
                        .insert(position - 1, format!("-A INPUT {}", args[4..].join(" ")));
                }
                "-A" => {
                    assert_eq!(args[2], "INPUT");
                    self.rules.push(format!("-A INPUT {}", args[3..].join(" ")));
                }
                _ => panic!("意外操作 {args:?}"),
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
    async fn socks5_secure_iptables_rollback_reports_a_missing_anchor() {
        let mut backend = FakeIptables {
            rules: vec![
                "-A INPUT -p tcp --dport 1080 -j ACCEPT".into(),
                "-A INPUT -p tcp --dport 22 -j ACCEPT".into(),
            ],
            deletions: 0,
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
            assert_eq!(args, ["-j", "-s", "-f", "-"]);
            let document: serde_json::Value = serde_json::from_slice(input.unwrap())?;
            let operations = document["nftables"].as_array().unwrap();
            assert_eq!(operations.len(), 1);
            let command = &operations[0];
            if command.get("list").is_some() {
                let mut items = vec![json!({"chain": {
                    "family": "ip", "table": "filter", "name": self.chain, "hook": "input", "type": "filter",
                    "handle": 1
                }})];
                items.extend(self.rules.iter().map(|rule| json!({"rule": rule})));
                return Ok(json!({"nftables": items}).to_string());
            }
            if let Some(rule) = command.get("delete").and_then(|delete| delete.get("rule")) {
                if !self.iptables_nft {
                    assert_eq!(rule["handle"], 2);
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
                self.rules.push(rule);
            } else {
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
