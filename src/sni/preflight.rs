use super::{temporary::Temporary, Mode};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

fn configuration(
    domain: &str,
    target: &str,
    mode: Mode,
    server_port: u16,
    socks_port: u16,
) -> Result<String> {
    let (server, client) = match mode {
        Mode::Reality => {
            let key = crate::config::generate_reality_keypair();
            let user = uuid::Uuid::new_v4().to_string();
            let sid = hex::encode(rand::random::<[u8; 8]>());
            (
                json!({"type":"tls", "reality_targets":{(domain):{
                    "private_key":key.private_key, "short_ids":[sid], "dest":target,
                    "max_time_diff":crate::config::GenerationOptions::default().reality_max_time_diff,
                    "vision":true,
                    "protocol":{"type":"vless", "user_id":user, "udp_enabled":false}
                }}}),
                json!({"type":"reality", "public_key":key.public_key,
                    "short_id":sid, "sni_hostname":domain, "vision":true,
                    "protocol":{"type":"vless", "user_id":user, "udp_enabled":false}
                }),
            )
        }
        Mode::ShadowTls => {
            let password = crate::config::generated_password();
            let ss_password = crate::config::generate_shadowsocks_password(
                crate::config::ShadowsocksCipher::Aes128Gcm2022,
            );
            let inner = json!({"type":"shadowsocks", "cipher":"2022-blake3-aes-128-gcm", "password":ss_password, "udp_enabled":false});
            (
                json!({"type":"tls", "shadowtls_targets":{(domain):{
                    "password":password, "handshake":{"address":target}, "protocol":inner
                }}}),
                json!({"type":"shadowtls", "password":password, "sni_hostname":domain, "protocol":inner}),
            )
        }
    };
    let rules = json!([{"masks":["0.0.0.0/0", "::/0"], "action":"allow"}]);
    let config: Value = json!([
        {"address":format!("127.0.0.1:{server_port}"), "protocol":server, "rules":rules},
        {"address":format!("127.0.0.1:{socks_port}"), "protocol":{"type":"socks", "udp_enabled":false},
         "rules":[{"masks":["0.0.0.0/0", "::/0"], "action":"allow", "client_chains":[{"address":format!("127.0.0.1:{server_port}"), "protocol":client}]}]}
    ]);
    crate::yaml::to_string(&config).context("生成 SNI 本机预检配置失败")
}

pub(super) async fn run(domain: &str, mode: Mode) -> Result<()> {
    let binary = std::env::var_os("PING_RUST_TEST_SHOES")
        .or_else(|| std::env::var_os("PING_RUST_SHOES_E2E_BIN"))
        .unwrap_or_else(|| crate::utils::SHOES_BIN.into());
    let url = std::env::var("PING_RUST_SNI_TEST_URL")
        .or_else(|_| std::env::var("PING_RUST_CHAIN_TEST_URL"))
        .unwrap_or_else(|_| "https://www.gstatic.com/generate_204".to_owned());
    run_with(
        domain,
        &format!("{domain}:443"),
        mode,
        Path::new(&binary),
        &url,
        TIMEOUT,
    )
    .await
}

async fn run_with(
    domain: &str,
    target: &str,
    mode: Mode,
    binary: &Path,
    url: &str,
    timeout: Duration,
) -> Result<()> {
    // 与 Chain 测试一样：私有目录、dry-run、kill_on_drop、等待 SOCKS 入口、经代理请求。
    // 外层 deadline 包括 dry-run、启动和 HTTP，取消 future 也会析构 Temporary。
    let temporary = Temporary::new()?;
    tokio::time::timeout(timeout, async {
        if !binary.is_file() {
            bail!("未找到 shoes，请先运行 prs install 后重新检测");
        }
        // 同时保留两个端口，避免内核连续分配同一个空闲端口。
        let server = std::net::TcpListener::bind(("127.0.0.1", 0))
            .context("无法绑定本机预检端口，请检查系统权限")?;
        let socks =
            std::net::TcpListener::bind(("127.0.0.1", 0)).context("无法绑定本机 SOCKS 测试端口")?;
        let server_port = server.local_addr()?.port();
        let socks_port = socks.local_addr()?.port();
        let path = temporary.path().join("probe.yaml");
        crate::utils::atomic_write(
            &path,
            configuration(domain, target, mode, server_port, socks_port)?.as_bytes(),
            0o600,
        )?;
        temporary.spawn(binary, &["--dry-run".as_ref(), path.as_os_str()])?;
        if !temporary.wait().await?.success() {
            bail!(
                "shoes 拒绝本机预检配置，请确认已安装项目固定版本的 shoes；{}",
                temporary.log_notice()
            );
        }
        drop((server, socks));
        temporary.spawn(binary, &[path.as_os_str()])?;
        loop {
            if let Some(status) = temporary.status()? {
                bail!(
                    "临时 shoes 提前退出（{status}），请检查内核版本和端口权限；{}",
                    temporary.log_notice()
                );
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!(
                "socks5h://127.0.0.1:{socks_port}"
            ))?)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let response = client.get(url).send().await.with_context(|| {
            format!(
                "经 shoes 的请求失败，请更换候选或检查 VPS 出站网络；{}",
                temporary.log_notice()
            )
        })?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            bail!(
                "shoes 请求返回 {}，预期 204，请检查探测地址或更换候选；{}",
                response.status(),
                temporary.log_notice()
            );
        }
        Ok(())
    })
    .await
    .with_context(|| {
        format!(
            "shoes 本机预检整体超时（10 秒），请检查网络或更换候选；{}",
            temporary.log_notice()
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, path::PathBuf, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    struct Target {
        address: SocketAddr,
        task: JoinHandle<()>,
    }
    impl Drop for Target {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn shoes() -> Option<PathBuf> {
        let binary = std::env::var_os("PING_RUST_TEST_SHOES")
            .or_else(|| std::env::var_os("PING_RUST_SHOES_E2E_BIN"));
        if binary.is_none() {
            eprintln!("未运行，待 CI：本机 SNI 预检需要 PING_RUST_TEST_SHOES 和绑定端口权限");
        }
        binary.map(PathBuf::from)
    }

    #[test]
    fn reality_preflight_uses_production_time_tolerance() {
        let yaml = configuration(
            "example.com",
            "example.com:443",
            Mode::Reality,
            20001,
            20002,
        )
        .unwrap();
        let value: Value = crate::yaml::from_str(&yaml).unwrap();
        let tolerance = value[0]["protocol"]["reality_targets"]["example.com"]["max_time_diff"]
            .as_u64()
            .unwrap();
        assert_eq!(
            tolerance,
            crate::config::GenerationOptions::default().reality_max_time_diff
        );
        assert!(tolerance > 0);
    }

    #[test]
    fn shadowtls_preflight_matches_server_and_client_credentials() {
        let yaml = configuration(
            "example.com",
            "127.0.0.1:20003",
            Mode::ShadowTls,
            20001,
            20002,
        )
        .unwrap();
        let value: Value = crate::yaml::from_str(&yaml).unwrap();
        let server = &value[0]["protocol"]["shadowtls_targets"]["example.com"];
        let client = &value[1]["rules"][0]["client_chains"][0]["protocol"];
        assert_eq!(server["handshake"]["address"], "127.0.0.1:20003");
        assert_eq!(client["type"], "shadowtls");
        assert_eq!(client["sni_hostname"], "example.com");
        assert!(!server["password"].as_str().unwrap().is_empty());
        assert!(server["password"] == client["password"]);
        assert!(server["protocol"] == client["protocol"]);
        assert_eq!(client["protocol"]["type"], "shadowsocks");
        assert_eq!(client["protocol"]["udp_enabled"], false);
        assert_eq!(client["protocol"]["cipher"], "2022-blake3-aes-128-gcm");
        use base64::Engine;
        let password = base64::engine::general_purpose::STANDARD
            .decode(client["protocol"]["password"].as_str().unwrap())
            .unwrap();
        assert_eq!(password.len(), 16);
    }

    fn tls_config(version: &'static rustls::SupportedProtocolVersion) -> rustls::ServerConfig {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["example.com".to_owned()]).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config
    }

    #[test]
    fn local_tls13_target_flight_matches_shoes_requirements() {
        // 在内存中检查实际 TLS 记录，不依赖 shoes 或监听端口。
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            "example.com".try_into().unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut server =
            rustls::ServerConnection::new(Arc::new(tls_config(&rustls::version::TLS13))).unwrap();
        server.read_tls(&mut hello.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut flight = Vec::new();
        server.write_tls(&mut flight).unwrap();
        let mut records = Vec::new();
        let mut remaining = flight.as_slice();
        while !remaining.is_empty() {
            assert!(remaining.len() >= 5);
            let length = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
            records.push((remaining[0], length));
            remaining = &remaining[5 + length..];
        }
        assert_eq!(records.len(), 3, "shoes v0.3.6 要求三条记录：{records:?}");
        assert_eq!(records[0].0, 22);
        assert_eq!(records[1], (20, 1));
        assert_eq!(records[2].0, 23);
        assert!(
            records[2].1 > 512,
            "shoes v0.3.6 要求合并加密记录大于 512 字节：{records:?}"
        );
    }

    async fn tls_target(version: &'static rustls::SupportedProtocolVersion) -> Target {
        let config = Arc::new(tls_config(version));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result.unwrap();
                        let config = config.clone();
                        connections.spawn(async move {
                            if let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await {
                                let mut buffer = [0u8; 4096];
                                while tls.read(&mut buffer).await.is_ok_and(|n| n > 0) {}
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Target { address, task }
    }

    async fn origin() -> Target {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        Target { address, task }
    }

    #[tokio::test]
    async fn local_sni_preflight_accepts_local_tls13_target() {
        let Some(binary) = shoes() else {
            return;
        };
        let target = tls_target(&rustls::version::TLS13).await;
        for mode in [Mode::Reality, Mode::ShadowTls] {
            let origin = origin().await;
            run_with(
                "example.com",
                &target.address.to_string(),
                mode,
                &binary,
                &format!("http://{}/generate_204", origin.address),
                TIMEOUT,
            )
            .await
            .expect("本地 TLS1.3 目标的 shoes 预检应返回 204");
        }
    }

    #[tokio::test]
    async fn local_sni_preflight_rejects_tls12_target() {
        let Some(binary) = shoes() else {
            return;
        };
        let target = tls_target(&rustls::version::TLS12).await;
        let origin = origin().await;
        let error = run_with(
            "example.com",
            &target.address.to_string(),
            Mode::Reality,
            &binary,
            &format!("http://{}/generate_204", origin.address),
            TIMEOUT,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("经 shoes") || error.to_string().contains("超时"),
            "必须在握手/请求阶段失败：{error:#}"
        );
    }

    #[tokio::test]
    async fn local_sni_preflight_timeout_cleans_process_and_private_files() {
        let Some(binary) = shoes() else {
            return;
        };
        // 直接观察预检使用的相同 RAII 资源；目标不响应时外层 deadline 取消操作。
        let temporary = Temporary::new().unwrap();
        let directory = temporary.path();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let path = directory.join("probe.yaml");
        crate::utils::atomic_write(&path, format!("- address: 127.0.0.1:{port}\n  protocol:\n    type: socks\n    udp_enabled: false\n").as_bytes(), 0o600).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        temporary
            .spawn(&binary, &["--dry-run".as_ref(), path.as_os_str()])
            .unwrap();
        assert!(temporary.wait().await.unwrap().success());
        drop(listener);
        temporary.spawn(&binary, &[path.as_os_str()]).unwrap();
        let pid = temporary.child_id().unwrap();
        let result = tokio::time::timeout(Duration::from_millis(200), temporary.wait()).await;
        assert!(result.is_err(), "测试进程应一直运行到 deadline");
        drop(temporary);
        assert!(!directory.exists());
        #[cfg(target_os = "linux")]
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "超时后不应遗留 shoes 进程"
        );
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(),
            "超时后端口必须释放"
        );
    }

    #[test]
    fn configurations_only_listen_on_loopback_and_use_one_sni() {
        for mode in [Mode::Reality, Mode::ShadowTls] {
            let yaml = configuration("example.com", "example.com:443", mode, 20001, 20002).unwrap();
            let value: Value = crate::yaml::from_str(&yaml).unwrap();
            assert_eq!(value[0]["address"], "127.0.0.1:20001");
            assert_eq!(value[1]["address"], "127.0.0.1:20002");
            let targets = if mode == Mode::Reality {
                "reality_targets"
            } else {
                "shadowtls_targets"
            };
            assert_eq!(value[0]["protocol"][targets].as_object().unwrap().len(), 1);
            assert!(value[0]["protocol"][targets].get("example.com").is_some());
            assert!(value[1]["rules"][0]["client_chains"].is_array());
        }
    }
}
