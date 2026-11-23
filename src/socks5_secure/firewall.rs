//! 按原监听地址和 TCP 端口清理专用放行规则。
use super::*;
use std::{fs, net::IpAddr, path::PathBuf};

#[derive(Default)]
pub(super) struct FirewallPlan {
    removals: Vec<(String, Vec<String>)>,
    restores: Vec<(String, Vec<String>, Option<Vec<u8>>)>,
    files: Vec<(PathBuf, Vec<u8>)>,
    touched: bool,
    listener: Option<SocketAddr>,
}

impl FirewallPlan {
    pub(super) async fn capture(listener: SocketAddr) -> Result<Self> {
        let mut plan = Self {
            listener: Some(listener),
            ..Self::default()
        };
        let mut managed_ufw = false;
        let mut managed_firewalld = false;
        if utils::command_exists("ufw") {
            let status = command("ufw", &["status".into(), "numbered".into()], None).await?;
            if status.contains("Status: active") {
                managed_ufw = true;
                for name in ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"] {
                    plan.files.push((
                        name.into(),
                        fs::read(name).with_context(|| format!("备份 {name} 失败"))?,
                    ));
                }
                let mut numbers = status
                    .lines()
                    .filter_map(|line| ufw_rule_number(line, listener))
                    .collect::<Vec<_>>();
                numbers.sort_unstable();
                numbers.dedup();
                for number in numbers.into_iter().rev() {
                    plan.removals.push((
                        "ufw".into(),
                        vec!["--force".into(), "delete".into(), number.to_string()],
                    ));
                }
                plan.restores
                    .push(("ufw".into(), vec!["reload".into()], None));
            }
        }
        if utils::command_exists("firewall-cmd") && service_running("firewalld.service").await? {
            managed_firewalld = true;
            let tcp_port = format!("{}/tcp", listener.port());
            for permanent in [false, true] {
                let prefix = if permanent {
                    vec!["--permanent".to_owned()]
                } else {
                    vec![]
                };
                let mut zones_args = prefix.clone();
                zones_args.push("--get-zones".into());
                for zone in command("firewall-cmd", &zones_args, None)
                    .await?
                    .split_whitespace()
                {
                    let mut base = prefix.clone();
                    base.push(format!("--zone={zone}"));
                    let mut sources = base.clone();
                    sources.push("--list-sources".into());
                    // 来源绑定也会限制区域内的普通端口规则。
                    if !command("firewall-cmd", &sources, None)
                        .await?
                        .trim()
                        .is_empty()
                    {
                        continue;
                    }
                    for (list, remove, add, rich) in [
                        ("--list-ports", "--remove-port=", "--add-port=", false),
                        (
                            "--list-rich-rules",
                            "--remove-rich-rule=",
                            "--add-rich-rule=",
                            true,
                        ),
                    ] {
                        let mut args = base.clone();
                        args.push(list.into());
                        let output = command("firewall-cmd", &args, None).await?;
                        let rules = if rich {
                            output.lines().collect::<Vec<_>>()
                        } else {
                            output.split_whitespace().collect()
                        };
                        for rule in rules {
                            let matches = if rich {
                                firewalld_rich_port_allow(rule, listener)
                            } else {
                                listener.ip().is_unspecified() && rule == tcp_port
                            };
                            if matches {
                                let mut remove_args = base.clone();
                                remove_args.push(format!("{remove}{rule}"));
                                let mut add_args = base.clone();
                                add_args.push(format!("{add}{rule}"));
                                plan.removals.push(("firewall-cmd".into(), remove_args));
                                plan.restores.push(("firewall-cmd".into(), add_args, None));
                            }
                        }
                    }
                }
            }
        }
        // 管理器自己的规则由其接口持久化；仍检查原生规则，避免漏掉并行配置。
        if utils::command_exists("nft") {
            let mut xtables_families = Vec::new();
            for (program, family) in [("iptables", "ip"), ("ip6tables", "ip6")] {
                if utils::command_exists(program)
                    && command(program, &["--version".into()], None)
                        .await?
                        .contains("nf_tables")
                {
                    xtables_families.push(family);
                }
            }
            let json =
                command("nft", &["-j".into(), "list".into(), "ruleset".into()], None).await?;
            let value: serde_json::Value =
                serde_json::from_str(&json).context("解析 nft 规则失败")?;
            if let Some(items) = value["nftables"].as_array() {
                let mut native_removals = Vec::new();
                let mut native_tables = std::collections::BTreeSet::new();
                for item in items {
                    let rule = &item["rule"];
                    let table = rule["table"].as_str().unwrap_or_default();
                    // ufw/firewalld 和 iptables-nft 的表交给各自工具处理。
                    if (managed_firewalld && table == "firewalld")
                        || (managed_ufw && table.starts_with("ufw"))
                        || (xtables_families.contains(&rule["family"].as_str().unwrap_or_default())
                            && matches!(table, "filter" | "nat" | "mangle" | "raw" | "security"))
                    {
                        continue;
                    }
                    if nft_input_port_allow(rule, items, listener) {
                        let family = rule["family"].as_str().context("nft rule 缺少 family")?;
                        let chain = rule["chain"].as_str().context("nft rule 缺少 chain")?;
                        let handle = rule["handle"].as_u64().context("nft rule 缺少 handle")?;
                        native_tables.insert((family.to_owned(), table.to_owned()));
                        native_removals.push((
                            "nft".into(),
                            vec![
                                "delete".into(),
                                "rule".into(),
                                family.into(),
                                table.into(),
                                chain.into(),
                                "handle".into(),
                                handle.to_string(),
                            ],
                        ));
                    }
                }
                if !native_removals.is_empty() {
                    for (family, table) in native_tables {
                        let snapshot = command(
                            "nft",
                            &["list".into(), "table".into(), family.clone(), table.clone()],
                            None,
                        )
                        .await?;
                        let table = serde_json::to_string(&table)?;
                        plan.restores.insert(
                            0,
                            (
                                "nft".into(),
                                vec!["-f".into(), "-".into()],
                                Some(
                                    format!("delete table {family} {table}\n{snapshot}")
                                        .into_bytes(),
                                ),
                            ),
                        );
                    }
                    plan.removals.extend(native_removals);
                }
            }
        }
        let (program, save, restore) = if listener.is_ipv4() {
            ("iptables", "iptables-save", "iptables-restore")
        } else {
            ("ip6tables", "ip6tables-save", "ip6tables-restore")
        };
        if utils::command_exists(program) {
            let rules = command(program, &["-S".into()], None).await?;
            let deletes = rules
                .lines()
                .filter_map(|line| iptables_delete_args(line, listener))
                .map(|args| (program.into(), args))
                .collect::<Vec<_>>();
            if !deletes.is_empty() {
                let snapshot = command(save, &[], None).await?;
                plan.restores
                    .insert(0, (restore.into(), vec![], Some(snapshot.into_bytes())));
                plan.removals.extend(deletes);
            }
        }
        Ok(plan)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        for (program, args) in &self.removals {
            if let Some(listener) = self.listener.filter(|_| program == "ufw") {
                // UFW 通过编号删除。服务重启期间若规则顺序变化，先确认该编号仍然匹配。
                let status = command("ufw", &["status".into(), "numbered".into()], None).await?;
                if !status.lines().any(|line| {
                    ufw_rule_number(line, listener)
                        .is_some_and(|number| number.to_string() == args[2])
                }) {
                    bail!("UFW 规则编号已变化，请检查后重试");
                }
            }
            // 超时也可能已执行了删除，必须从调用前就标记需恢复。
            self.touched = true;
            command(program, args, None).await?;
        }
        if let Some(listener) = self.listener {
            if !Self::capture(listener).await?.removals.is_empty() {
                bail!("防火墙仍有匹配原监听地址和 TCP 端口的放行规则，请检查并重试");
            }
        }
        Ok(())
    }

    pub(super) async fn restore(&mut self) -> Result<()> {
        if !self.touched {
            return Ok(());
        }
        let mut failures = Vec::new();
        for (path, contents) in &self.files {
            if let Err(error) = utils::atomic_write(path, contents, 0o600) {
                failures.push(format!("恢复 {}：{error:#}", path.display()));
            }
        }
        for (program, args, input) in &self.restores {
            if let Err(error) = command(program, args, input.as_deref()).await {
                failures.push(format!("{error:#}"));
            }
        }
        if !failures.is_empty() {
            bail!("防火墙恢复失败：{}", failures.join("；"));
        }
        self.touched = false;
        Ok(())
    }
}

async fn service_running(unit: &str) -> Result<bool> {
    // is-active 的 inactive 返回非零，使用 show 得到可区分查询失败的状态。
    Ok(command(
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

pub(super) fn ufw_rule_number(line: &str, listener: SocketAddr) -> Option<u32> {
    let (number, rule) = line.trim_start().strip_prefix('[')?.split_once(']')?;
    let (destination, source) = rule.split_once("ALLOW IN")?;
    let ip = listener.ip();
    let destination = destination.trim();
    let source = source.trim();
    if !ip.is_ipv6() && (destination.ends_with(" (v6)") || source.ends_with(" (v6)")) {
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
    number.trim().parse().ok()
}

pub(super) fn iptables_delete_args(line: &str, listener: SocketAddr) -> Option<Vec<String>> {
    let mut words = shell_words(line);
    let [append, chain, options @ ..] = words.as_slice() else {
        return None;
    };
    // 自定义链可能同时供 INPUT/OUTPUT/FORWARD 使用。
    if append != "-A" || chain != "INPUT" {
        return None;
    }
    let options = options.chunks_exact(2);
    if !options.remainder().is_empty() {
        return None;
    }
    let ip = listener.ip();
    let port = listener.port().to_string();
    let (mut tcp, mut dport, mut accept) = (false, false, false);
    let mut destination = ip.is_unspecified();
    for option in options {
        match (option[0].as_str(), option[1].as_str()) {
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
    let mut elements = elements;
    while !elements.is_empty() {
        elements = match elements {
            [attribute, rest @ ..] if attribute == family => rest,
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
    dport && destination
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
    let (Some(family), Some(table), Some(name)) = (
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
    items.iter().any(|item| {
        let chain = &item["chain"];
        chain["family"] == family
            && chain["table"] == table
            && chain["name"] == name
            && chain["hook"] == "input"
    }) && nft_port_allow(rule, listener)
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
        match (payload["protocol"].as_str(), payload["field"].as_str()) {
            (Some("tcp"), Some("dport")) if value.as_u64() == Some(u64::from(listener.port())) => {
                dport = true;
            }
            (Some(protocol), Some("saddr"))
                if protocol == ip_family && unrestricted(nft_address_scope(value), ip) => {}
            (Some(protocol), Some("daddr"))
                if protocol == ip_family && matches_destination(nft_address_scope(value), ip) =>
            {
                destination = true;
            }
            _ => return false,
        }
    }
    dport && accept && destination
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
            "family": "inet", "table": "filter", "chain": "incoming", "handle": 1,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                {"accept": null}
            ]
        });
        for hook in ["output", "forward", "prerouting", "postrouting", "ingress"] {
            let items = vec![
                serde_json::json!({"chain": {
                    "family": "inet", "table": "filter", "name": "incoming", "hook": hook
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
                "family": "inet", "table": "filter", "name": "incoming", "hook": "input"
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

    #[tokio::test]
    #[cfg(unix)]
    async fn socks5_secure_firewall_partial_failure_restores_files_and_reloads() {
        let directory = tempfile::tempdir().unwrap();
        let rules = directory.path().join("user.rules");
        let restored = directory.path().join("restored");
        fs::write(&rules, b"original rules\n").unwrap();
        let remove = directory.path().join("remove");
        let reload = directory.path().join("reload");
        utils::atomic_write(
            &remove,
            b"#!/bin/sh\nprintf changed > \"$1\"\nexit 1\n",
            0o700,
        )
        .unwrap();
        utils::atomic_write(&reload, b"#!/bin/sh\nprintf reloaded > \"$1\"\n", 0o700).unwrap();
        let mut plan = FirewallPlan {
            removals: vec![(
                remove.display().to_string(),
                vec![rules.display().to_string()],
            )],
            restores: vec![(
                reload.display().to_string(),
                vec![restored.display().to_string()],
                None,
            )],
            files: vec![(rules.clone(), fs::read(&rules).unwrap())],
            ..Default::default()
        };
        assert!(plan.close().await.is_err());
        assert_eq!(fs::read(&rules).unwrap(), b"changed");
        plan.restore().await.unwrap();
        assert_eq!(fs::read(&rules).unwrap(), b"original rules\n");
        assert_eq!(fs::read(&restored).unwrap(), b"reloaded");
        assert!(!plan.touched);
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
