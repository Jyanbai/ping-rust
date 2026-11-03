//! Reality / ShadowTLS 目标检测：只做经根证书验证的 TLS 1.3 + h2 握手。

use std::{
    fmt,
    future::Future,
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use futures_util::future::join_all;
use rand::Rng;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{lookup_host, TcpStream},
};
use tokio_rustls::TlsConnector;

use crate::config;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Dns,
    Tcp,
    TlsVersion,
    Alpn,
    Certificate,
    Timeout,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dns => "DNS：系统域名解析失败或没有可用地址",
            Self::Tcp => "TCP：无法连接目标 443 端口",
            Self::TlsVersion => "TLS 版本：无法完成 TLS 1.3 握手",
            Self::Alpn => "ALPN：未协商 h2",
            Self::Certificate => "证书：证书链、有效期或域名校验失败",
            Self::Timeout => "超时：候选整体检测超过 3 秒",
        })
    }
}

#[derive(Debug)]
pub(crate) struct ProbeResult {
    pub domain: String,
    pub outcome: std::result::Result<Duration, Failure>,
}

fn tls_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring 支持 TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn public_tls_config() -> Arc<ClientConfig> {
    tls_config(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

fn tls_failure(error: &io::Error) -> Failure {
    match error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented) => {
            Failure::Certificate
        }
        Some(
            rustls::Error::NoApplicationProtocol
            | rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol),
        ) => Failure::Alpn,
        // 包括旧版本协议、握手警报、无效握手包或 TLS 阶段连接中断。
        _ => Failure::TlsVersion,
    }
}

async fn bounded<T>(
    future: impl Future<Output = std::result::Result<T, Failure>>,
) -> std::result::Result<T, Failure> {
    tokio::time::timeout(PROBE_TIMEOUT, future)
        .await
        .unwrap_or(Err(Failure::Timeout))
}

async fn probe_addresses(
    domain: &str,
    addresses: &[SocketAddr],
    config: Arc<ClientConfig>,
) -> std::result::Result<Duration, Failure> {
    let stream = TcpStream::connect(addresses)
        .await
        .map_err(|_| Failure::Tcp)?;
    tls_handshake(domain, stream, config).await
}

async fn tls_handshake(
    domain: &str,
    stream: impl AsyncRead + AsyncWrite + Unpin,
    config: Arc<ClientConfig>,
) -> std::result::Result<Duration, Failure> {
    let name = ServerName::try_from(domain.to_owned()).map_err(|_| Failure::Certificate)?;
    let start = Instant::now();
    let tls = TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|e| tls_failure(&e))?;
    let session = tls.get_ref().1;
    if session.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(Failure::TlsVersion);
    }
    if session.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(Failure::Alpn);
    }
    Ok(start.elapsed())
}

async fn probe(domain: &str, config: Arc<ClientConfig>) -> ProbeResult {
    let outcome = bounded(async {
        let addresses: Vec<_> = lookup_host((domain, 443))
            .await
            .map_err(|_| Failure::Dns)?
            .collect();
        if addresses.is_empty() {
            return Err(Failure::Dns);
        }
        probe_addresses(domain, &addresses, config).await
    })
    .await;
    ProbeResult {
        domain: domain.to_owned(),
        outcome,
    }
}

/// 纯选择函数：稳定排序后在最快的至多三个成功结果中等概率抽取。
pub(crate) fn select<'a>(
    results: &'a [ProbeResult],
    rng: &mut impl Rng,
) -> Option<&'a ProbeResult> {
    let mut passed: Vec<_> = results.iter().filter(|r| r.outcome.is_ok()).collect();
    passed.sort_by_key(|r| r.outcome.as_ref().ok().copied());
    let count = passed.len().min(3);
    (count > 0).then(|| passed[rng.random_range(0..count)])
}

fn write_results(results: &[ProbeResult], output: &mut impl Write) -> Result<()> {
    for result in results {
        match result.outcome {
            Ok(elapsed) => writeln!(output, "{}：握手 {} ms", result.domain, elapsed.as_millis())?,
            Err(reason) => writeln!(output, "{}：失败（{reason}）", result.domain)?,
        }
    }
    Ok(())
}

// 检测与终端 I/O 分开，使失败路径可注入验证，尤其确保非终端不会调用输入函数。
fn finish(
    results: &[ProbeResult],
    interactive: bool,
    rng: &mut impl Rng,
    output: &mut impl Write,
    manual: impl FnOnce() -> Result<String>,
) -> Result<String> {
    if interactive {
        write_results(results, output)?;
    }
    if let Some(chosen) = select(results, rng) {
        let elapsed = chosen.outcome.as_ref().expect("只选择成功结果");
        let available = results.iter().filter(|r| r.outcome.is_ok()).count();
        writeln!(
            output,
            "SNI：{}（握手 {} ms，{available}/{} 个候选可用）",
            chosen.domain,
            elapsed.as_millis(),
            results.len()
        )?;
        return Ok(chosen.domain.clone());
    }
    if !interactive {
        let failures = results
            .iter()
            .map(|r| format!("{}：{}", r.domain, r.outcome.unwrap_err()))
            .collect::<Vec<_>>()
            .join("；");
        bail!(
            "全部 SNI 候选检测失败（{failures}）；请用 prs add reality --server-name <域名> 重试"
        );
    }
    writeln!(
        output,
        "全部 SNI 候选检测失败。输入 SNI 域名，或输入 0 取消"
    )?;
    output.flush()?;
    manual()
}

fn manual_warning(domain: &str, outcome: std::result::Result<Duration, Failure>) -> Option<String> {
    outcome.err().map(|reason| {
        format!("警告：SNI {domain} 检测失败（{reason}），仍使用手动指定值；请检查域名或网络连通性")
    })
}

/// 显式输入只检测一次，失败警告不拦截；所有诊断只写 stderr。
pub(crate) async fn check_manual(domain: &str) {
    if let Some(warning) = manual_warning(domain, probe(domain, public_tls_config()).await.outcome)
    {
        eprintln!("{warning}");
    }
}

pub(crate) async fn check(domain: &str) -> ProbeResult {
    probe(domain, public_tls_config()).await
}

pub(crate) async fn resolve(explicit: Option<String>, interactive: bool) -> Result<String> {
    if let Some(domain) = explicit {
        config::validate_server_name(&domain)?;
        check_manual(&domain).await;
        return Ok(domain);
    }
    let config = public_tls_config();
    let results = join_all(
        config::reality_server_names()
            .into_iter()
            .map(|domain| probe(domain, config.clone())),
    )
    .await;
    let interactive = interactive && io::stdin().is_terminal();
    let chosen = finish(
        &results,
        interactive,
        &mut rand::rng(),
        &mut io::stderr(),
        || {
            crate::menu::input::read_text(
                &mut io::stdin().lock(),
                &mut io::stderr(),
                "SNI 域名",
                None,
                false,
                |value| {
                    config::validate_server_name(value)?;
                    Ok(value.to_owned())
                },
            )
        },
    )?;
    if !results.iter().any(|r| r.outcome.is_ok()) {
        check_manual(&chosen).await;
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn passed(name: &str, millis: u64) -> ProbeResult {
        ProbeResult {
            domain: name.to_owned(),
            outcome: Ok(Duration::from_millis(millis)),
        }
    }

    fn test_tls_configs(
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&[u8]],
        certificate_name: &str,
        public_roots: bool,
    ) -> (Arc<rustls::ServerConfig>, Arc<ClientConfig>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![certificate_name.to_owned()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )
        .unwrap();
        server.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let client = if public_roots {
            public_tls_config()
        } else {
            tls_config(roots)
        };
        (Arc::new(server), client)
    }

    // TLS 核心握手通过内存流验证，不需要沙箱的网络/端口权限。
    #[tokio::test]
    async fn memory_tls_enforces_version_alpn_certificate_and_hostname() {
        for (tls12, alpn, name, public_roots, expected) in [
            (false, Some(b"h2".as_slice()), "example.com", false, None),
            (false, None, "example.com", false, Some(Failure::Alpn)),
            (
                false,
                Some(b"http/1.1".as_slice()),
                "example.com",
                false,
                Some(Failure::Alpn),
            ),
            (
                true,
                Some(b"h2".as_slice()),
                "example.com",
                false,
                Some(Failure::TlsVersion),
            ),
            (
                false,
                Some(b"h2".as_slice()),
                "other.example.com",
                false,
                Some(Failure::Certificate),
            ),
            (
                false,
                Some(b"h2".as_slice()),
                "example.com",
                true,
                Some(Failure::Certificate),
            ),
        ] {
            let version = if tls12 {
                &rustls::version::TLS12
            } else {
                &rustls::version::TLS13
            };
            let alpn: Vec<_> = alpn.into_iter().collect();
            let (server, client) = test_tls_configs(&[version], &alpn, name, public_roots);
            let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
            let task = tokio::spawn(async move {
                let _ = tokio_rustls::TlsAcceptor::from(server)
                    .accept(server_stream)
                    .await;
            });
            let outcome = bounded(tls_handshake("example.com", client_stream, client)).await;
            assert_eq!(
                outcome.err(),
                expected,
                "TLS12={tls12}, ALPN={alpn:?}, 名称={name}, 公共根={public_roots}"
            );
            task.abort();
        }
    }

    // 本地 TCP 测试沙箱通过 --skip local_tls_ 跳过，CI 正常运行。
    async fn local_tls_case(
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&[u8]],
        certificate_name: &str,
        public_roots: bool,
    ) -> std::result::Result<Duration, Failure> {
        let (server, client) = test_tls_configs(versions, alpn, certificate_name, public_roots);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(server).accept(stream).await;
        });
        let result = bounded(probe_addresses("example.com", &[address], client)).await;
        task.abort();
        result
    }

    #[tokio::test]
    async fn local_tls_accepts_verified_tls13_h2() {
        assert!(
            local_tls_case(&[&rustls::version::TLS13], &[b"h2"], "example.com", false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn local_tls_rejects_missing_or_wrong_alpn() {
        for alpn in [vec![], vec![b"http/1.1".as_slice()]] {
            assert_eq!(
                local_tls_case(&[&rustls::version::TLS13], &alpn, "example.com", false).await,
                Err(Failure::Alpn)
            );
        }
    }

    #[tokio::test]
    async fn local_tls_rejects_tls12() {
        assert_eq!(
            local_tls_case(&[&rustls::version::TLS12], &[b"h2"], "example.com", false).await,
            Err(Failure::TlsVersion)
        );
    }

    #[tokio::test]
    async fn local_tls_rejects_certificate_name_mismatch() {
        assert_eq!(
            local_tls_case(
                &[&rustls::version::TLS13],
                &[b"h2"],
                "other.example.com",
                false
            )
            .await,
            Err(Failure::Certificate)
        );
    }

    #[tokio::test]
    async fn local_tls_rejects_untrusted_certificate() {
        assert_eq!(
            local_tls_case(&[&rustls::version::TLS13], &[b"h2"], "example.com", true).await,
            Err(Failure::Certificate)
        );
    }

    #[tokio::test]
    async fn local_tls_times_out_entire_candidate() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let start = Instant::now();
        assert_eq!(
            bounded(probe_addresses(
                "example.com",
                &[address],
                public_tls_config()
            ))
            .await,
            Err(Failure::Timeout)
        );
        assert!(start.elapsed() < Duration::from_secs(4));
        task.abort();
    }

    #[test]
    fn tls_configuration_and_failure_stages() {
        assert_eq!(public_tls_config().alpn_protocols, vec![b"h2".to_vec()]);
        for (error, expected) in [
            (
                rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
                Failure::Certificate,
            ),
            (
                rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol),
                Failure::Alpn,
            ),
            (
                rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion),
                Failure::TlsVersion,
            ),
        ] {
            assert_eq!(
                tls_failure(&io::Error::new(io::ErrorKind::InvalidData, error)),
                expected
            );
        }
        for stage in [
            Failure::Dns,
            Failure::Tcp,
            Failure::TlsVersion,
            Failure::Alpn,
            Failure::Certificate,
            Failure::Timeout,
        ] {
            assert!(!stage.to_string().is_empty());
        }
    }

    #[test]
    fn manual_failures_warn_and_success_is_silent() {
        assert!(manual_warning("example.com", Ok(Duration::from_millis(24))).is_none());
        for stage in [
            Failure::Dns,
            Failure::Tcp,
            Failure::TlsVersion,
            Failure::Alpn,
            Failure::Certificate,
            Failure::Timeout,
        ] {
            let warning = manual_warning("example.com", Err(stage)).unwrap();
            assert!(warning.contains("example.com"));
            assert!(warning.contains(&stage.to_string()));
            assert!(warning.contains("仍使用手动指定值"));
        }
    }

    #[tokio::test]
    async fn timeout_also_bounds_pending_resolution() {
        let start = Instant::now();
        let result: std::result::Result<(), Failure> = bounded(std::future::pending()).await;
        assert_eq!(result, Err(Failure::Timeout));
        assert!(start.elapsed() >= PROBE_TIMEOUT);
    }

    #[test]
    fn all_failed_manual_input_validates_retries_and_cancels() {
        use std::io::Cursor;
        let failed = vec![ProbeResult {
            domain: "example.com".to_owned(),
            outcome: Err(Failure::Dns),
        }];
        for (input, expected) in [
            (
                "invalid host\nmanual.example.com\n",
                Some("manual.example.com"),
            ),
            ("0\n", None),
        ] {
            let result = finish(
                &failed,
                true,
                &mut StdRng::seed_from_u64(63),
                &mut Vec::new(),
                || {
                    crate::menu::input::read_text(
                        &mut Cursor::new(input),
                        &mut Vec::new(),
                        "SNI 域名",
                        None,
                        false,
                        |value| {
                            config::validate_server_name(value)?;
                            Ok(value.to_owned())
                        },
                    )
                },
            );
            match expected {
                Some(name) => assert_eq!(result.unwrap(), name),
                None => assert!(crate::menu::input::is_back(&result.unwrap_err())),
            }
        }
    }

    #[test]
    fn chooses_only_fastest_three_and_handles_small_or_empty_sets() {
        let mut rng = StdRng::seed_from_u64(63);
        let results = vec![
            passed("slow.example.com", 90),
            passed("c.example.com", 30),
            ProbeResult {
                domain: "failed.example.com".to_owned(),
                outcome: Err(Failure::Dns),
            },
            passed("a.example.com", 10),
            passed("b.example.com", 20),
        ];
        let mut selected = std::collections::BTreeSet::new();
        for _ in 0..128 {
            selected.insert(select(&results, &mut rng).unwrap().domain.as_str());
        }
        assert_eq!(
            selected,
            ["a.example.com", "b.example.com", "c.example.com"]
                .into_iter()
                .collect()
        );
        assert!(select(&[], &mut rng).is_none());
        assert!(select(&results[2..3], &mut rng).is_none());
        assert_eq!(
            select(&results[..1], &mut rng).unwrap().domain,
            "slow.example.com"
        );
        for _ in 0..32 {
            let chosen = select(&results[..2], &mut rng).unwrap();
            assert!(results[..2].iter().any(|r| r.domain == chosen.domain));
        }
    }

    #[test]
    fn reports_results_and_never_reads_nonterminal_input() {
        let results = vec![
            passed("example.com", 24),
            ProbeResult {
                domain: "unavailable.example.com".to_owned(),
                outcome: Err(Failure::Timeout),
            },
        ];
        let mut rng = StdRng::seed_from_u64(63);
        let mut output = Vec::new();
        let selected = finish(&results, true, &mut rng, &mut output, || {
            panic!("unexpected input")
        })
        .unwrap();
        assert_eq!(selected, "example.com");
        let interactive = String::from_utf8(output).unwrap();
        assert!(interactive.contains("example.com：握手 24 ms"));
        assert!(
            interactive.contains("unavailable.example.com：失败（超时：候选整体检测超过 3 秒）")
        );
        println!("正常选择（交互，注入结果）：\n{interactive}");
        let mut output = Vec::new();
        finish(&results, false, &mut rng, &mut output, || {
            panic!("must not read stdin")
        })
        .unwrap();
        let nonterminal = String::from_utf8(output).unwrap();
        assert_eq!(
            nonterminal,
            "SNI：example.com（握手 24 ms，1/2 个候选可用）\n"
        );
        println!("正常选择（非交互 stderr，注入结果）：\n{nonterminal}");
        let failed = &results[1..];
        let mut output = Vec::new();
        let error = finish(failed, false, &mut rng, &mut output, || {
            panic!("must not read stdin")
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("prs add reality --server-name <域名>"));
        assert!(error.to_string().contains("unavailable.example.com"));
        assert!(output.is_empty());
        println!("全部失败（非交互，注入结果）：\n{error}");
        let mut output = Vec::new();
        assert_eq!(
            finish(failed, true, &mut rng, &mut output, || Ok(
                "manual.example.com".to_owned()
            ))
            .unwrap(),
            "manual.example.com"
        );
        println!(
            "全部失败（交互，注入结果）：\n{}",
            String::from_utf8(output).unwrap()
        );
    }
}
