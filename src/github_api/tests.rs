use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

fn fixture(replies: Vec<Option<String>>) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let url = format!("http://{}/fixture", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let worker = thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read(&mut byte).unwrap() == 0 { break; }
                request.extend(byte);
            }
            captured.lock().unwrap().push(String::from_utf8(request).unwrap());
            if let Some(reply) = reply { stream.write_all(reply.as_bytes()).unwrap(); }
        }
    });
    (url, requests, worker)
}

fn reply(status: u16, body: &str, headers: &str) -> Option<String> {
    Some(format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}\r\n{body}", body.len()))
}

fn policy() -> RetryPolicy {
    RetryPolicy { attempts: 3, base_delay: Duration::ZERO, max_delay: Duration::ZERO }
}

fn client() -> Client {
    Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

#[test]
fn github_api_token_precedence_and_origin_validation() {
    assert_eq!(select_token(Some(" first ".into()), Some("second".into())).as_deref(), Some("first"));
    assert_eq!(select_token(Some(" ".into()), Some(" second ".into())).as_deref(), Some("second"));
    assert!(select_token(None, None).is_none());
    assert!(validate_api_url("https://api.github.com/repos/cfal/shoes/releases/latest").is_ok());
    for url in ["http://api.github.com/repos/x", "https://github.com/asset", "https://api.github.com.evil.test/", "https://user:secret@api.github.com/", "https://api.github.com:444/"] {
        assert!(validate_api_url(url).is_err());
    }
}

#[tokio::test]
async fn github_api_optional_auth_and_status_recovery() {
    let token = uuid::Uuid::new_v4().simple().to_string();
    for status in [403, 429, 500, 502, 503, 504] {
        let (url, requests, worker) = fixture(vec![reply(status, "{}", ""), reply(200, "{\"ok\":true}", "")]);
        let value: serde_json::Value = get_with_policy(&client(), &url, Some(&token), policy()).await.unwrap();
        assert_eq!(value["ok"], true);
        worker.join().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.to_lowercase().contains(&format!("authorization: bearer {token}"))));
    }
    let (url, requests, worker) = fixture(vec![reply(200, "{}", "")]);
    get_with_policy::<serde_json::Value>(&client(), &url, None, policy()).await.unwrap();
    worker.join().unwrap();
    assert!(!requests.lock().unwrap()[0].to_lowercase().contains("authorization:"));
}

#[tokio::test]
async fn github_api_exhaustion_and_nonretry_errors_do_not_leak_secrets() {
    let token = uuid::Uuid::new_v4().simple().to_string();
    for status in [403, 429, 500, 404, 401, 302] {
        let count = if [403, 429, 500].contains(&status) { 3 } else { 1 };
        let (url, requests, worker) = fixture((0..count).map(|_| reply(status, &token, "Location: https://example.invalid/\r\n")).collect());
        let error = get_with_policy::<serde_json::Value>(&client(), &url, Some(&token), policy()).await.unwrap_err().to_string();
        worker.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), count);
        assert!(error.contains(&format!("HTTP {status}")));
        assert!(error.contains("GITHUB_TOKEN / GH_TOKEN"));
        assert!(!error.contains(&token));
    }
    let (url, _, worker) = fixture(vec![reply(200, &token, "")]);
    let error = get_with_policy::<serde_json::Value>(&client(), &url, None, policy()).await.unwrap_err().to_string();
    worker.join().unwrap();
    assert!(!error.contains(&token));
}

#[tokio::test]
async fn github_api_transient_disconnect_retries() {
    let (url, requests, worker) = fixture(vec![None, reply(200, "{}", "")]);
    get_with_policy::<serde_json::Value>(&client(), &url, None, policy()).await.unwrap();
    worker.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[test]
fn github_api_backoff_respects_server_wait_without_unbounded_sleep() {
    let policy = RetryPolicy { attempts: 3, base_delay: Duration::from_secs(1), max_delay: Duration::from_secs(10) };
    let mut headers = reqwest::header::HeaderMap::new();
    assert_eq!(retry_delay(&headers, 0, policy), Some(Duration::from_secs(1)));
    assert_eq!(retry_delay(&headers, 1, policy), Some(Duration::from_secs(2)));
    headers.insert("retry-after", "7".parse().unwrap());
    assert_eq!(retry_delay(&headers, 0, policy), Some(Duration::from_secs(7)));
    headers.insert("retry-after", "60".parse().unwrap());
    assert!(retry_delay(&headers, 0, policy).is_none());
    headers.remove("retry-after");
    headers.insert("x-ratelimit-remaining", "0".parse().unwrap());
    headers.insert("x-ratelimit-reset", "9999999999".parse().unwrap());
    assert!(retry_delay(&headers, 0, policy).is_none());
}
