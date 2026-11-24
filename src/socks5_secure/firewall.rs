//! 按原监听地址和 TCP 端口清理专用放行规则。
use super::*;
use serde_json::{json, Value};
use std::net::IpAddr;

trait FirewallExecutor {
    fn available(&self, program: &str) -> bool;
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
}

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
                        plan.rules.push(Rule::Ufw {
                            text: text.to_owned(),
                            listener,
                        });
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
                    plan.rules.extend(firewalld_rules(&output, listener, &base));
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
                rule.verify_ufw_kernel(backend, count).await?;
                // 超时或失败也可能已经改动了规则，回滚时先重新查询。
                self.attempted.push(Attempt {
                    rule: index,
                    before,
                    position,
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
                Rule::Rich { base, .. } if base[0] == "--permanent" => persistent += 1,
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
                Rule::Rich { .. } => runtime += 1,
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
            Rule::Ufw { text, .. } => {
                let status = ufw_status(backend).await?;
                if !status.contains("Status: active") {
                    bail!("UFW 已停用，请检查 ufw status");
                }
                let scope = ufw_inbound_scope(text).context("无法解析 UFW 规则范围")?;
                let mut live = Vec::new();
                for (_, entry) in status.lines().filter_map(ufw_entry) {
                    if entry != text.as_str() && ufw_inbound_scope(entry) == Some(scope) {
                        bail!("UFW 存在相同范围的其他规则，请检查 ufw status numbered");
                    }
                    live.push(entry.into());
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
            Rule::Ufw { text, .. } | Rule::Rich { text, .. } | Rule::Iptables { text, .. } => {
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
        let text = &attempt.before[attempt.position].text;
        let original_count = matching_rule_count(&attempt.before, text);
        let current_count = matching_rule_count(&current, text);
        if current_count >= original_count {
            return self.verify_ufw_kernel(backend, original_count).await;
        }
        let position = restore_position(attempt, &current, matches!(self, Rule::Iptables { .. }));
        match self {
            Rule::Ufw { listener, .. } => {
                let mut args = vec![];
                if current
                    .get(position)
                    .is_some_and(|next| ufw_is_v6(&next.text) == listener.is_ipv6())
                {
                    args.extend(["insert".into(), (position + 1).to_string()]);
                }
                args.extend(ufw_allow_args(*listener));
                let result = backend.execute("ufw", &args, None).await;
                self.verify_ufw_kernel(backend, original_count).await?;
                result?;
            }
            Rule::Rich { base, text } => {
                // --list-rich-rules 无法区分限时和无限时的运行时规则。
                if base.first().is_none_or(|arg| arg != "--permanent") {
                    bail!("firewalld 无法查询运行时 rich rule 的剩余超时。已保留移除状态，请核对原规则和到期时间后按需恢复");
                }
                let mut args = base.clone();
                args.push(format!("--add-rich-rule={text}"));
                backend.execute("firewall-cmd", &args, None).await?;
            }
            Rule::Iptables { program, text } => {
                let words = shell_words(text);
                let mut args = vec![
                    "-w".into(),
                    "-I".into(),
                    "INPUT".into(),
                    (position + 1).to_string(),
                ];
                args.extend_from_slice(&words[2..]);
                backend.execute(program, &args, None).await?;
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
        if matching_rule_count(&self.current(backend).await?, text) <= current_count {
            bail!("原放行规则未恢复，请检查防火墙");
        }
        Ok(())
    }

    async fn verify_ufw_kernel(
        &self,
        backend: &mut impl FirewallExecutor,
        expected: usize,
    ) -> Result<()> {
        let Rule::Ufw { listener, .. } = self else {
            return Ok(());
        };
        let (program, chain) = if listener.is_ipv4() {
            ("iptables", "ufw-user-input")
        } else {
            ("ip6tables", "ufw6-user-input")
        };
        // ufw status numbered 使用持久配置列出用户规则，可能先于内核更新。
        let output = backend
            .execute(program, &["-w".into(), "-S".into(), chain.into()], None)
            .await
            .with_context(|| format!("无法查询 UFW 内核规则，请检查 {program} -S {chain}"))?;
        let count = output
            .lines()
            .filter(|line| iptables_delete_args_in_chain(line, *listener, chain).is_some())
            .count();
        if count != expected {
            bail!("UFW 内核规则数量为 {count}，预期为 {expected}，请检查 {program} -S {chain} 和 ufw status numbered");
        }
        Ok(())
    }
}

fn matching_rule_count(rules: &[LiveRule], text: &str) -> usize {
    rules.iter().filter(|rule| rule.text == text).count()
}

fn restore_position(attempt: &Attempt, current: &[LiveRule], use_occurrence: bool) -> usize {
    // 优先找原后继，其次找原前驱。根据现行顺序插入，保留并发新增规则的位置。
    let locate = |anchor_index: usize| {
        let anchor = &attempt.before[anchor_index];
        if let Some(handle) = anchor.handle {
            if let Some(index) = current
                .iter()
                .position(|rule| rule.handle == Some(handle) && rule.text == anchor.text)
            {
                return Some(index);
            }
        }
        let original_count = attempt
            .before
            .iter()
            .filter(|rule| rule.text == anchor.text)
            .count();
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
        let occurrence = attempt.before[..anchor_index]
            .iter()
            .filter(|rule| rule.text == anchor.text)
            .count();
        matches.nth(occurrence)
    };
    for anchor in attempt.position + 1..attempt.before.len() {
        if let Some(index) = locate(anchor) {
            return index;
        }
    }
    for anchor in (0..attempt.position).rev() {
        if let Some(index) = locate(anchor) {
            return index + 1;
        }
    }
    attempt.position.min(current.len())
}

async fn ufw_status(backend: &mut impl FirewallExecutor) -> Result<String> {
    backend
        .execute("ufw", &["status".into(), "numbered".into()], None)
        .await
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
    // 不依赖链名猜测用途；只删除具有明确 input hook 的基础链中的规则。
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
                "family": "inet", "table": "filter", "name": "input", "hook": "input"
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
            rules: [vec![SHARED, SCOPED], vec![SHARED, SCOPED]],
            runtime_timeout: None,
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);
        let report = plan.closure_report();
        assert!(report.contains("已移除 1 条运行时"));
        assert!(report.contains("已移除 1 条持久"));
    }

    #[tokio::test]
    async fn socks5_secure_firewalld_rollback_does_not_make_timed_rule_indefinite() {
        let mut backend = FakeFirewalld {
            rules: [vec![SHARED, SCOPED], vec![SHARED, SCOPED]],
            runtime_timeout: Some(60),
        };
        let mut plan = FirewallPlan::capture_with("0.0.0.0:1080".parse().unwrap(), &mut backend)
            .await
            .unwrap();
        assert_eq!(backend.runtime_timeout, Some(60));
        plan.close_with(&mut backend).await.unwrap();
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED]]);

        let rollback = plan.restore_with(&mut backend).await;
        assert_eq!(backend.rules, [vec![SHARED], vec![SHARED, SCOPED]]);
        let error = rollback.unwrap_err();
        assert!(format!("{error:#}").contains("剩余超时"));
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
                    "family": "ip", "table": "filter", "name": "incoming", "hook": hook
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
                "family": "ip", "table": "filter", "name": "incoming", "hook": "input"
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

    struct FakeUfw {
        disk: Vec<&'static str>,
        ipv6: bool,
        kernel_has_rule: bool,
        apply_to_kernel: bool,
        keep_disk_on_delete_failure: bool,
    }

    impl FirewallExecutor for FakeUfw {
        fn available(&self, program: &str) -> bool {
            program == "ufw" || program == if self.ipv6 { "ip6tables" } else { "iptables" }
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
                        if self.kernel_has_rule {
                            rules.push_str(&format!(
                                "-A {kernel_chain} -p tcp -m tcp --dport 1080 -j ACCEPT\n"
                            ));
                        }
                        Ok(rules)
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
                        assert_eq!(self.disk.remove(usize::from(self.ipv6)), rule);
                    }
                    self.disk.insert(0, OTHER);
                    bail!("模拟 UFW 删除后失败");
                }
                "allow" => {
                    assert!(!self.keep_disk_on_delete_failure);
                    assert_eq!(args, spec);
                    self.disk.insert(1 + usize::from(self.ipv6), rule);
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
    async fn socks5_secure_ufw_rollback_rejects_rules_present_only_on_disk() {
        for (address, ipv6) in [("0.0.0.0:1080", false), ("[::]:1080", true)] {
            for keep_disk_on_delete_failure in [false, true] {
                let mut backend = FakeUfw {
                    disk: vec![IPV4, IPV6],
                    ipv6,
                    kernel_has_rule: true,
                    apply_to_kernel: false,
                    keep_disk_on_delete_failure,
                };
                let mut plan = FirewallPlan::capture_with(address.parse().unwrap(), &mut backend)
                    .await
                    .unwrap();
                assert!(plan.close_with(&mut backend).await.is_err());
                let rollback = plan.restore_with(&mut backend).await;
                assert_eq!(backend.disk, [OTHER, IPV4, IPV6]);
                assert!(!backend.kernel_has_rule);
                assert!(format!("{:#}", rollback.unwrap_err()).contains("UFW 内核规则"));
            }
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
                    "family": "ip", "table": "filter", "name": self.chain, "hook": "input",
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
