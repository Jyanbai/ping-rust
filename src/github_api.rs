//! GitHub API credentials stay on the API origin; release asset clients stay unauthenticated.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use reqwest::{header::HeaderMap, Client};
use serde::de::DeserializeOwned;

const TOKEN_HINT: &str =
    "可设置 GITHUB_TOKEN / GH_TOKEN（sudo 时需显式保留该环境变量）；已停止有限重试";

#[derive(Clone, Copy)]
struct RetryPolicy {
    attempts: usize,
    base_delay: Duration,
    max_delay: Duration,
}

fn select_token(primary: Option<String>, fallback: Option<String>) -> Option<String> {
    [primary, fallback]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

fn validate_api_url(url: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(url).context("GitHub API URL 无效")?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("拒绝向非 GitHub API HTTPS 地址发送请求");
    }
    Ok(url)
}

pub async fn get<T: DeserializeOwned>(url: &str) -> Result<T> {
    validate_api_url(url)?;
    let client = Client::builder()
        .user_agent(concat!("ping-rust/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || validate_api_url(attempt.url().as_str()).is_err() {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .context("创建 GitHub API 客户端失败")?;
    let token = select_token(
        std::env::var("GITHUB_TOKEN").ok(),
        std::env::var("GH_TOKEN").ok(),
    );
    get_with_policy(
        &client,
        url,
        token.as_deref(),
        RetryPolicy {
            attempts: 3,
            base_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(120),
        },
    )
    .await
}

fn retry_delay(headers: &HeaderMap, index: usize, policy: RetryPolicy) -> Option<Duration> {
    let backoff = policy.base_delay.saturating_mul(1u32 << index.min(16));
    let server_wait = if let Some(value) = headers.get("retry-after") {
        // Unknown date-form Retry-After: stop rather than retry before the server permits it.
        Duration::from_secs(value.to_str().ok()?.parse().ok()?)
    } else if headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        == Some("0")
    {
        let reset: u64 = headers
            .get("x-ratelimit-reset")?
            .to_str()
            .ok()?
            .parse()
            .ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Duration::from_secs(reset.saturating_sub(now))
    } else {
        Duration::ZERO
    };
    let delay = backoff.max(server_wait);
    (delay <= policy.max_delay).then_some(delay)
}

async fn get_with_policy<T: DeserializeOwned>(
    client: &Client,
    url: &str,
    token: Option<&str>,
    policy: RetryPolicy,
) -> Result<T> {
    for index in 0..policy.attempts {
        let mut request = client
            .get(url)
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = token {
            let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| anyhow::anyhow!("GitHub API token 格式无效；{TOKEN_HINT}"))?;
            auth.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) if index + 1 < policy.attempts => {
                tokio::time::sleep(
                    policy
                        .base_delay
                        .saturating_mul(1u32 << index.min(16))
                        .min(policy.max_delay),
                )
                .await;
                continue;
            }
            Err(_) => bail!(
                "GitHub API 网络请求失败（连接 / TLS / 超时）；尝试 {} 次；{TOKEN_HINT}",
                index + 1
            ),
        };
        let status = response.status();
        if status.is_success() {
            match response.bytes().await {
                Ok(bytes) => {
                    return serde_json::from_slice(&bytes)
                        .map_err(|_| anyhow::anyhow!("GitHub API JSON 响应无效；{TOKEN_HINT}"))
                }
                Err(_) if index + 1 < policy.attempts => {
                    tokio::time::sleep(
                        policy
                            .base_delay
                            .saturating_mul(1u32 << index.min(16))
                            .min(policy.max_delay),
                    )
                    .await;
                    continue;
                }
                Err(_) => bail!(
                    "GitHub API 响应读取失败；尝试 {} 次；{TOKEN_HINT}",
                    index + 1
                ),
            }
        }
        let retry = status.as_u16() == 403 || status.as_u16() == 429 || status.is_server_error();
        if retry && index + 1 < policy.attempts {
            if let Some(delay) = retry_delay(response.headers(), index, policy) {
                drop(response);
                tokio::time::sleep(delay).await;
                continue;
            }
            bail!(
                "GitHub API HTTP {}；服务端要求等待超过重试上限或等待时间无法解析；{TOKEN_HINT}",
                status.as_u16()
            );
        }
        bail!(
            "GitHub API HTTP {}；尝试 {} 次；{TOKEN_HINT}",
            status.as_u16(),
            index + 1
        );
    }
    bail!("GitHub API 未发出请求；{TOKEN_HINT}")
}

#[cfg(test)]
mod tests;
