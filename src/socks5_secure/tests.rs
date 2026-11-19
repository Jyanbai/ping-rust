use super::*;

#[test]
fn socks5_secure_listener_verification_rejects_extra_public_binds() {
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
