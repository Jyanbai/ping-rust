use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn socks5_secure_rollback_commands_are_outside_the_foreground_signal_group() {
    let output = command(
        "sh",
        &[
            "-c".into(),
            concat!(
                "read -r stat < \"/proc/$$/stat\" || exit 1; ",
                "set -- ${stat##*) }; printf '%s\\n' \"$3\" \"$$\"",
            )
            .into(),
        ],
        None,
    )
    .await
    .unwrap();
    let ids: Vec<u32> = output
        .split_whitespace()
        .map(|id| id.parse().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    // /proc 的 comm 后依次是 state、ppid、pgrp。PGID 应等于子进程 PID。
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn socks5_secure_listener_verification_ignores_other_processes_on_same_port() {
    for address in ["203.0.113.8:1080", "127.0.0.1:1080", "[::1]:1080"] {
        let output = format!(
            "LISTEN 0 128 {address} *:* users:((\"shoes\",pid=42,fd=7))\n\
             LISTEN 0 128 127.0.0.1:1080 0.0.0.0:* users:((\"shoes\",pid=420,fd=8))\n\
             LISTEN 0 128 [::]:1080 [::]:* users:((\"other\",pid=142,fd=9))\n"
        );
        assert!(check_listeners(&output, address.parse().unwrap(), 42).is_ok());
    }
}

#[test]
fn socks5_secure_listener_verification_requires_shoes_ownership() {
    let expected = "127.0.0.1:1080".parse().unwrap();
    for owner in ["", " users:((\"shoes\",pid=420,fd=7))"] {
        let output = format!("LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*{owner}\n");
        assert!(check_listeners(&output, expected, 42).is_err());
    }
    // 一个 socket 即使被多个进程持有，只要包含 shoes 就必须校验。
    let output = concat!(
        "LISTEN 0 128 127.0.0.1:1080 0.0.0.0:* users:((\"shoes\",pid=42,fd=7))\n",
        "LISTEN 0 128 [::]:1080 [::]:* users:((\"other\",pid=420,fd=8),(\"shoes\",pid=42,fd=9))\n",
    );
    assert!(check_listeners(output, expected, 42).is_err());
}

#[test]
fn socks5_secure_firewall_preserves_non_tcp_udp_protocols() {
    let listener = "0.0.0.0:1080".parse().unwrap();
    for protocol in ["sctp", "dccp"] {
        let rule = format!("-A INPUT -p {protocol} -m {protocol} --dport 1080 -j ACCEPT");
        assert!(
            firewall::iptables_delete_args(&rule, listener).is_none(),
            "must preserve {protocol} rule"
        );
    }
    for rule in [
        "-A INPUT --dport 1080 -j ACCEPT",
        "-A INPUT ! -p tcp --dport 1080 -j ACCEPT",
        "-A INPUT -p sctp --dport 1080 -m comment --comment \"-p tcp\" -j ACCEPT",
    ] {
        assert!(
            firewall::iptables_delete_args(rule, listener).is_none(),
            "must preserve {rule}"
        );
    }
}

#[test]
fn socks5_secure_local_preserves_other_rules_on_the_same_port() {
    let listener = "203.0.113.8:1080".parse().unwrap();
    let rules = [
        "-A INPUT -d 203.0.113.8/32 -p tcp -m tcp --dport 1080 -j ACCEPT",
        "-A INPUT -d 203.0.113.8/32 -p udp -m udp --dport 1080 -j ACCEPT",
        "-A INPUT -d 203.0.113.9/32 -p tcp -m tcp --dport 1080 -j ACCEPT",
        "-A INPUT -p tcp -m tcp --dport 1080 -j ACCEPT",
        "-A INPUT -s 192.0.2.0/24 -d 203.0.113.8/32 -p tcp --dport 1080 -j ACCEPT",
        "-A INPUT -d 203.0.113.8/32 -p tcp --dport 1080 -m comment --comment other-service -j ACCEPT",
    ];
    let remaining = rules
        .into_iter()
        .filter(|rule| firewall::iptables_delete_args(rule, listener).is_none())
        .collect::<Vec<_>>();
    assert_eq!(remaining, rules[1..]);
}

#[test]
fn socks5_secure_listener_verification_rejects_extra_public_binds() {
    // 原有地址断言保留；ss -p 的归属信息由公共测试入口补齐。
    let check_listeners = |output: &str, expected| {
        super::check_listeners(
            &output.replace('\n', " users:((\"shoes\",pid=42,fd=7))\n"),
            expected,
            42,
        )
    };
    let expected = "127.0.0.1:1080".parse().unwrap();
    assert!(check_listeners("LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*\n", expected).is_ok());
    assert!(check_listeners("LISTEN 0 128 0.0.0.0:1080 0.0.0.0:*\n", expected).is_err());
    assert!(check_listeners(
        "LISTEN 0 128 127.0.0.1:1080 0.0.0.0:*\nLISTEN 0 128 [::]:1080 [::]:*\n",
        expected
    )
    .is_err());
    assert!(check_listeners("", expected).is_err());
    assert!(check_listeners(
        "LISTEN 0 128 [::]:1080 [::]:*\n",
        "0.0.0.0:1080".parse().unwrap()
    )
    .is_err());
    assert!(check_listeners("LISTEN 0 128 *:1080 *:*\n", "0.0.0.0:1080".parse().unwrap()).is_err());
}

#[test]
fn socks5_secure_firewall_matches_only_dedicated_port_allow_rules() {
    let listener = "0.0.0.0:1080".parse().unwrap();
    assert_eq!(
        firewall::iptables_delete_args("-A INPUT -p tcp -m tcp --dport 1080 -j ACCEPT", listener)
            .unwrap(),
        ["-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "1080", "-j", "ACCEPT"]
    );
    for rule in [
        "-A INPUT -p udp --dport 1080 -j ACCEPT",
        "-A INPUT -p tcp --dport 10801 -j ACCEPT",
        "-A INPUT -p tcp --dport 1080 -j DROP",
        "-A INPUT -j ACCEPT",
        "-A INPUT -p tcp ! --dport 1080 -j ACCEPT",
        "-A INPUT -p tcp --dport 1080 -j ACCEPT -m",
    ] {
        assert!(
            firewall::iptables_delete_args(rule, listener).is_none(),
            "must preserve {rule}"
        );
    }
    let listener = "[::]:1080".parse().unwrap();
    assert_eq!(
        firewall::ufw_rule_number("[ 3] 1080/tcp (v6) ALLOW IN Anywhere (v6)", listener),
        Some(3)
    );
    for line in [
        "[ 4] 10801/tcp ALLOW IN Anywhere",
        "[ 4] 1080/tcp ALLOW IN Anywhere",
        "[ 4] 1080/udp (v6) ALLOW IN Anywhere (v6)",
        "[ 4] 1080 (v6) ALLOW IN Anywhere (v6)",
    ] {
        assert_eq!(firewall::ufw_rule_number(line, listener), None, "{line}");
    }
}

#[test]
fn socks5_secure_firewall_does_not_parse_comment_text_as_rule_options() {
    let listener = "0.0.0.0:1080".parse().unwrap();
    for rule in [
        r#"-A INPUT -m comment --comment "example --dport 1080 -j ACCEPT text" -j DROP"#,
        r#"-A INPUT -p tcp --dport 10801 -m comment --comment "example --dport 1080 text" -j ACCEPT"#,
    ] {
        assert!(
            firewall::iptables_delete_args(rule, listener).is_none(),
            "must preserve {rule}"
        );
    }
    let listener = "203.0.113.8:1080".parse().unwrap();
    assert_eq!(
        firewall::ufw_rule_number("[ 8] 203.0.113.8 1080/tcp ALLOW IN Anywhere", listener),
        Some(8)
    );
    for line in [
        "[ 9] 1080/tcp ALLOW OUT Anywhere",
        "[ 9] 203.0.113.9 1080/tcp ALLOW IN Anywhere",
        "[ 9] 203.0.113.8 1080/tcp ALLOW IN 192.0.2.0/24",
        "[ 9] 203.0.113.8 1080/tcp ALLOW IN Anywhere # other service",
    ] {
        assert_eq!(firewall::ufw_rule_number(line, listener), None, "{line}");
    }
}
