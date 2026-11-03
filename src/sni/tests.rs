use super::*;

#[test]
fn scanner_csv_handles_quoted_issuer_and_escaped_quotes() {
    let rows = parse_csv("IP,CERT,ISSUER,ORIGIN\r\n203.0.113.8,*.example.com,\"Example, \"\"CA\"\"\",www.example.com\r\n203.0.113.9,*.example.com,CA,\r\n", "203.0.113.0/24".parse().unwrap(), Mode::Reality, false).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].domain, "www.example.com");
    assert!(rows[0].skip.is_none());
    assert!(rows[1].skip.as_deref().unwrap().contains("通配符"));
    assert!(parse_csv(
        "IP,CERT\n203.0.113.1,\"unfinished",
        "203.0.113.0/24".parse().unwrap(),
        Mode::Reality,
        false
    )
    .is_err());
}

#[test]
fn scanner_filters_wildcards_and_requires_resolved_address_in_subnet() {
    assert_eq!(
        scan_domain("*.example.com", "www.example.com").unwrap(),
        "www.example.com"
    );
    assert!(scan_domain("*.example.com", "*.example.com").is_err());
    assert!(scan_domain("*.example.com", "203.0.113.2").is_err());
    assert_eq!(
        scan_domain("www.example.com", "").unwrap(),
        "www.example.com"
    );
    let subnet: Subnet = "203.0.113.42/24".parse().unwrap();
    assert!(subnet.contains("203.0.113.99".parse().unwrap()));
    assert!(!subnet.contains("203.0.114.1".parse().unwrap()));
    assert!(!subnet.contains("::1".parse().unwrap()));
    assert!("203.0.113.0/16".parse::<Subnet>().is_err());
}

#[test]
fn results_put_passed_first_then_sort_by_handshake_time() {
    let mut rows = vec![
        Report::test("failed.example.com", Some(1), false),
        Report::test("slow.example.com", Some(30), true),
        Report::test("fast.example.com", Some(10), true),
        Report::test("unavailable.example.com", None, false),
    ];
    sort_reports(&mut rows);
    assert_eq!(
        rows.iter()
            .map(|r| r.candidate.domain.as_str())
            .collect::<Vec<_>>(),
        [
            "fast.example.com",
            "slow.example.com",
            "failed.example.com",
            "unavailable.example.com"
        ]
    );
}

#[test]
fn scanner_rejects_bad_digest_before_executing_anything() {
    assert!(scan::verify_digest(b"wrong binary", scan::AMD64_SHA256).is_err());
    assert!(scan::verify_digest(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    .is_ok());
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("RealiTLScanner");
    assert!(scan::write_verified_binary(&binary, b"wrong binary", scan::AMD64_SHA256).is_err());
    assert!(!binary.exists(), "摘要不符的下载不能成为可执行文件");
}

#[test]
fn cli_parses_read_only_check_csv_and_explicit_scan_consent() {
    use crate::cli::{Cli, Command as CliCommand};
    use clap::Parser;
    let parsed = Cli::try_parse_from([
        "prs",
        "sni",
        "check",
        "www.example.com",
        "other.example.com",
    ])
    .unwrap();
    let Some(CliCommand::Sni {
        command: Command::Check {
            domains, protocol, ..
        },
    }) = parsed.command
    else {
        panic!("应解析为 sni check");
    };
    assert_eq!(domains, ["www.example.com", "other.example.com"]);
    assert!(protocol.is_none());
    let parsed = Cli::try_parse_from([
        "prs",
        "sni",
        "check",
        "--csv",
        "out.csv",
        "--subnet",
        "203.0.113.0/24",
        "--protocol",
        "shadow-tls",
    ])
    .unwrap();
    assert!(matches!(
        parsed.command,
        Some(CliCommand::Sni {
            command: Command::Check {
                csv: Some(_),
                subnet: Some(_),
                protocol: Some(Mode::ShadowTls),
                ..
            }
        })
    ));
    assert!(Cli::try_parse_from(["prs", "sni", "check", "--csv", "out.csv"]).is_err());
    assert!(matches!(
        Cli::try_parse_from(["prs", "sni", "scan", "--yes"])
            .unwrap()
            .command,
        Some(CliCommand::Sni {
            command: Command::Scan { yes: true, .. }
        })
    ));
}

#[test]
fn selection_only_accepts_passed_rows_and_never_substitutes_a_failure() {
    let reports = [
        Report::test("failed.example.com", Some(1), false),
        Report::test("www.example.com", Some(20), true),
    ];
    assert!(selected(&reports, 0).is_err());
    assert!(selected(&reports, 2).is_err());
    assert_eq!(selected(&reports, 1).unwrap(), "www.example.com");
}

#[tokio::test]
async fn invalid_scanner_candidate_skips_all_network_stages() {
    let candidates = parse_csv(
        "IP,CERT,ORIGIN\n203.0.113.2,*.example.com,\n",
        "203.0.113.0/24".parse().unwrap(),
        Mode::Reality,
        false,
    )
    .unwrap();
    let reports = check(candidates).await;
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].passed);
    assert_eq!(reports[0].tls, "未检测");
    assert_eq!(reports[0].redirect, "未检测");
    assert_eq!(reports[0].shoes, "未检测");
    assert!(reports[0].detail.contains("通配符"));
    assert!(reports[0].candidate.subnet.is_some());
}

#[test]
fn nonterminal_scan_requires_yes_and_never_calls_confirmation() {
    let error = scan::authorize(false, false, || panic!("不得读取 stdin")).unwrap_err();
    assert!(error.to_string().contains("--yes"));
    assert!(scan::authorize(false, true, || panic!("不得读取 stdin")).unwrap());
    assert!(!scan::authorize(true, false, || Ok(false)).unwrap());
}

#[test]
fn https_rejects_cross_host_redirect_and_cloudflare_headers() {
    use reqwest::{header::HeaderMap, StatusCode};
    let mut headers = HeaderMap::new();
    headers.insert("location", "https://other.example.com/".parse().unwrap());
    assert!(inspect_https("example.com", StatusCode::FOUND, &headers)
        .0
        .contains("跨主机"));
    headers.insert("location", "/path".parse().unwrap());
    assert_eq!(
        inspect_https("example.com", StatusCode::FOUND, &headers).0,
        "同主机"
    );
    headers.insert("server", "CloudFlare".parse().unwrap());
    assert!(inspect_https("example.com", StatusCode::OK, &headers).1);
    headers.remove("server");
    headers.insert("cf-ray", "example".parse().unwrap());
    assert!(inspect_https("example.com", StatusCode::OK, &headers).1);
}
