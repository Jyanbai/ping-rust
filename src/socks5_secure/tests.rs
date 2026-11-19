use super::*;

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
    for protocol in ["sctp", "dccp"] {
        let rule = format!("-A INPUT -p {protocol} -m {protocol} --dport 1080 -j ACCEPT");
        assert!(
            !firewall::iptables_port_allow(&rule, 1080),
            "must preserve {protocol} rule"
        );
    }
    for rule in [
        "-A INPUT --dport 1080 -j ACCEPT",
        "-A INPUT ! -p tcp --dport 1080 -j ACCEPT",
        "-A INPUT -p sctp --dport 1080 -m comment --comment \"-p tcp\" -j ACCEPT",
    ] {
        assert!(
            !firewall::iptables_port_allow(rule, 1080),
            "must preserve {rule}"
        );
    }
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
    assert!(firewall::iptables_port_allow(
        "-A INPUT -p tcp -m tcp --dport 1080 -j ACCEPT",
        1080
    ));
    assert!(firewall::iptables_port_allow(
        "-A INPUT -p udp --dport 1080 -j ACCEPT",
        1080
    ));
    assert!(!firewall::iptables_port_allow(
        "-A INPUT -p tcp --dport 10801 -j ACCEPT",
        1080
    ));
    assert!(!firewall::iptables_port_allow(
        "-A INPUT -p tcp --dport 1080 -j DROP",
        1080
    ));
    assert!(!firewall::iptables_port_allow("-A INPUT -j ACCEPT", 1080));
    assert!(!firewall::iptables_port_allow(
        "-A INPUT -p tcp ! --dport 1080 -j ACCEPT",
        1080
    ));
    assert_eq!(
        firewall::ufw_rule_number("[ 3] 1080/tcp (v6) ALLOW IN Anywhere (v6)", 1080),
        Some(3)
    );
    assert_eq!(
        firewall::ufw_rule_number("[ 4] 10801/tcp ALLOW IN Anywhere", 1080),
        None
    );
}

#[test]
fn socks5_secure_firewall_does_not_parse_comment_text_as_rule_options() {
    assert!(!firewall::iptables_port_allow(
        "-A INPUT -m comment --comment \"example --dport 1080 -j ACCEPT text\" -j DROP",
        1080
    ));
    assert!(!firewall::iptables_port_allow("-A INPUT -p tcp --dport 10801 -m comment --comment \"example --dport 1080 text\" -j ACCEPT", 1080));
    assert_eq!(
        firewall::ufw_rule_number("[ 8] 203.0.113.8 1080/tcp ALLOW IN Anywhere", 1080),
        Some(8)
    );
    assert_eq!(
        firewall::ufw_rule_number("[ 9] 1080/tcp ALLOW OUT Anywhere", 1080),
        None
    );
}
