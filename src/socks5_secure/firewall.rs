//! 只移除该端口的专用放行规则；不触碰共享范围、默认策略或其他端口。
use super::*;
use std::{fs, path::PathBuf};

#[derive(Default)]
pub(super) struct FirewallPlan {
    removals: Vec<(String, Vec<String>)>,
    restores: Vec<(String, Vec<String>, Option<Vec<u8>>)>,
    files: Vec<(PathBuf, Vec<u8>)>,
    touched: bool,
    port: Option<u16>,
}

impl FirewallPlan {
    pub(super) async fn capture(port: u16) -> Result<Self> {
        let mut plan = Self {
            port: Some(port),
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
                    .filter_map(|line| ufw_rule_number(line, port))
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
                                firewalld_rich_port_allow(rule, port)
                            } else {
                                rule == format!("{port}/tcp") || rule == format!("{port}/udp")
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
                    if nft_input_port_allow(rule, items, port) {
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
        for (program, save, restore) in [
            ("iptables", "iptables-save", "iptables-restore"),
            ("ip6tables", "ip6tables-save", "ip6tables-restore"),
        ] {
            if !utils::command_exists(program) {
                continue;
            }
            let rules = command(program, &["-S".into()], None).await?;
            let mut positions = std::collections::BTreeMap::<String, usize>::new();
            let mut deletes = Vec::new();
            for line in rules.lines() {
                let mut words = line.split_whitespace();
                if words.next() != Some("-A") {
                    continue;
                }
                let chain = words.next().context("iptables 规则缺少 chain")?.to_owned();
                let position = positions.entry(chain.clone()).or_default();
                *position += 1;
                // 管理器已记录自身规则的恢复方法，不能重复移除。
                if (managed_ufw && chain.starts_with("ufw-"))
                    || (managed_firewalld && chain.starts_with("IN_"))
                {
                    continue;
                }
                if iptables_port_allow(line, port) {
                    deletes.push((
                        program.into(),
                        vec!["-D".into(), chain, position.to_string()],
                    ));
                }
            }
            if !deletes.is_empty() {
                let snapshot = command(save, &[], None).await?;
                plan.restores
                    .insert(0, (restore.into(), vec![], Some(snapshot.into_bytes())));
                plan.removals.extend(deletes.into_iter().rev());
            }
        }
        Ok(plan)
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        for (program, args) in &self.removals {
            // 超时也可能已执行了删除，必须从调用前就标记需恢复。
            self.touched = true;
            command(program, args, None).await?;
        }
        if let Some(port) = self.port {
            if !Self::capture(port).await?.removals.is_empty() {
                bail!("防火墙仍有该端口的放行规则，请检查并重试");
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

pub(super) fn ufw_rule_number(line: &str, port: u16) -> Option<u32> {
    let (number, rule) = line.strip_prefix('[')?.split_once(']')?;
    let (destination, _) = rule.split_once("ALLOW IN")?;
    if !destination.split_whitespace().any(|word| {
        [
            port.to_string(),
            format!("{port}/tcp"),
            format!("{port}/udp"),
        ]
        .contains(&word.to_owned())
    }) {
        return None;
    }
    number.trim().parse().ok()
}

pub(super) fn iptables_port_allow(line: &str, port: u16) -> bool {
    let words = shell_words(line);
    // 自定义链可能同时供 INPUT/OUTPUT/FORWARD 使用；无法确认用途时保留。
    words.first().is_some_and(|word| word == "-A")
        && words.get(1).is_some_and(|word| word == "INPUT")
        && !words.windows(2).any(|w| w == ["!", "-p"])
        && words
            .windows(2)
            .any(|w| w[0] == "-p" && matches!(w[1].as_str(), "tcp" | "udp"))
        && !words.windows(2).any(|w| w == ["!", "--dport"])
        && words.windows(2).any(|w| w == ["-j", "ACCEPT"])
        && words
            .windows(2)
            .any(|w| w[0] == "--dport" && w[1] == port.to_string())
}

fn firewalld_rich_port_allow(rule: &str, port: u16) -> bool {
    let words = shell_words(rule);
    let target_port = format!("port={port}");
    // 属性中的引号内容保留为一个参数，避免把日志 prefix 当成元素或动作。
    words.first().is_some_and(|word| word == "rule")
        && words.iter().any(|word| word == "accept")
        && words.iter().enumerate().any(|(index, word)| {
            if word != "port" {
                return false;
            }
            let attributes = words[index + 1..]
                .iter()
                .take_while(|word| word.contains('='))
                .collect::<Vec<_>>();
            attributes.iter().any(|word| **word == target_port)
                && attributes
                    .iter()
                    .any(|word| matches!(word.as_str(), "protocol=tcp" | "protocol=udp"))
        })
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

fn nft_input_port_allow(rule: &serde_json::Value, items: &[serde_json::Value], port: u16) -> bool {
    let (Some(family), Some(table), Some(name)) = (
        rule["family"].as_str(),
        rule["table"].as_str(),
        rule["chain"].as_str(),
    ) else {
        return false;
    };
    // 不依赖链名猜测用途；只删除具有明确 input hook 的基础链中的规则。
    items.iter().any(|item| {
        let chain = &item["chain"];
        chain["family"] == family
            && chain["table"] == table
            && chain["name"] == name
            && chain["hook"] == "input"
    }) && nft_port_allow(rule, port)
}

fn nft_port_allow(rule: &serde_json::Value, port: u16) -> bool {
    let Some(expressions) = rule["expr"].as_array() else {
        return false;
    };
    expressions.iter().any(|e| e.get("accept").is_some())
        && expressions.iter().any(|e| {
            let m = &e["match"];
            m["op"] == "=="
                && m["right"].as_u64() == Some(u64::from(port))
                && m["left"]["payload"]["field"] == "dport"
                && matches!(
                    m["left"]["payload"]["protocol"].as_str(),
                    Some("tcp" | "udp")
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_secure_iptables_preserves_output_forward_and_unclassified_chains() {
        for chain in ["OUTPUT", "FORWARD", "CUSTOM"] {
            for protocol in ["tcp", "udp"] {
                assert!(
                    !iptables_port_allow(
                        &format!("-A {chain} -p {protocol} --dport 443 -j ACCEPT"),
                        443,
                    ),
                    "must preserve {chain} {protocol}"
                );
            }
        }
        assert!(iptables_port_allow(
            "-A INPUT -p tcp --dport 443 -j ACCEPT",
            443
        ));
    }

    #[test]
    fn socks5_secure_nft_preserves_non_input_hooks_and_unclassified_chains() {
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
                !nft_input_port_allow(&rule, &items, 443),
                "must preserve {hook}"
            );
        }
        assert!(!nft_input_port_allow(&rule, &[], 443));
        let items = vec![
            serde_json::json!({"chain": {
                "family": "inet", "table": "filter", "name": "incoming", "hook": "input"
            }}),
            serde_json::json!({"rule": rule}),
        ];
        assert!(nft_input_port_allow(&rule, &items, 443));
        // 同名链必须同时匹配地址族和表，不能借用另一条链的 input hook。
        for field in ["family", "table", "chain"] {
            let original = rule[field].clone();
            rule[field] = "other".into();
            assert!(
                !nft_input_port_allow(&rule, &items, 443),
                "must match {field}"
            );
            rule[field] = original;
        }
    }

    #[test]
    fn socks5_secure_firewalld_rich_rules_preserve_source_ports_and_other_actions() {
        assert!(firewalld_rich_port_allow(
            r#"rule family="ipv4" port port="1080" protocol="tcp" accept"#,
            1080
        ));
        assert!(firewalld_rich_port_allow(
            r#"rule family="ipv6" port protocol="udp" port="1080" log prefix="socks" accept"#,
            1080
        ));
        for rule in [
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
                !firewalld_rich_port_allow(rule, 1080),
                "must preserve {rule}"
            );
        }
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
        let rule = serde_json::json!({"expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1080}},
            {"accept": null}
        ]});
        assert!(nft_port_allow(&rule, 1080));
        assert!(!nft_port_allow(&rule, 1081));
        let mut shared = rule.clone();
        shared["expr"][0]["match"]["right"] = serde_json::json!({"set": [1080, 1081]});
        assert!(!nft_port_allow(&shared, 1080));
        let mut drop = rule;
        drop["expr"][1] = serde_json::json!({"drop": null});
        assert!(!nft_port_allow(&drop, 1080));
    }
}
