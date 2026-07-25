//! Pure input validators for generation/update request fields.
//! Types and password rules stay in the parent config module.

use super::{AnyTlsUser, ShadowsocksCipher};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

pub(super) fn validate_websocket_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > 256
        || path.contains(['?', '#'])
        || path.chars().any(char::is_control)
    {
        bail!("WebSocket 路径必须以 / 开头、长度不超过 256，且不能包含 ?、# 或控制字符");
    }
    Ok(())
}

pub(super) fn validate_server_name(value: &str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > 253
        || value.contains(char::is_whitespace)
        || value.contains('/')
        || value.contains([':', '\\'])
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        bail!("SNI/服务器名称无效");
    }
    Ok(())
}

pub(super) fn validate_reality_short_id(value: &str) -> Result<()> {
    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.chars().all(|c| c.is_ascii_hexdigit())
    {
        bail!("Reality short ID 必须是 0..=16 个偶数长度十六进制字符");
    }
    Ok(())
}

pub(crate) fn validate_shadowsocks_password(
    cipher: ShadowsocksCipher,
    password: &str,
) -> Result<()> {
    if password.is_empty() || password.contains(char::is_control) {
        bail!("Shadowsocks 密码不能为空或包含控制字符");
    }
    if let Some(expected) = cipher.key_len() {
        let decoded = STANDARD
            .decode(password)
            .context("Shadowsocks 2022 密码必须使用标准 Base64 编码")?;
        if decoded.len() != expected {
            bail!(
                "{} 密码解码后必须为 {} 字节，当前为 {} 字节",
                cipher.as_str(),
                expected,
                decoded.len()
            );
        }
    }
    Ok(())
}

pub(super) fn validate_anytls_users(users: &[AnyTlsUser]) -> Result<()> {
    if users.is_empty() {
        bail!("AnyTLS 至少需要一个用户");
    }
    for user in users {
        if user.name.len() > 64 || user.name.chars().any(char::is_control) {
            bail!("AnyTLS 用户名不能超过 64 字符或包含控制字符");
        }
        if user.password.is_empty() || user.password.chars().any(char::is_control) {
            bail!("AnyTLS 用户密码不能为空或包含控制字符");
        }
    }
    Ok(())
}

pub(super) fn validate_padding_scheme(scheme: &[String]) -> Result<()> {
    if scheme.is_empty() {
        bail!("AnyTLS padding_scheme 不能为空");
    }
    let mut stop_count = 0;
    for entry in scheme {
        let (key, value) = entry
            .split_once('=')
            .context("AnyTLS padding 条目必须采用 key=value 格式")?;
        if key == "stop" {
            stop_count += 1;
            let stop = value
                .parse::<u32>()
                .context("AnyTLS padding 的 stop 必须是正整数")?;
            if stop == 0 {
                bail!("AnyTLS padding 的 stop 必须大于 0");
            }
            continue;
        }
        key.parse::<u32>()
            .context("AnyTLS padding 的包序号必须是非负整数")?;
        if value.is_empty() {
            bail!("AnyTLS padding 范围不能为空");
        }
        for range in value.split(',') {
            let (min, max) = match range.split_once('-') {
                Some((min, max)) => (
                    min.parse::<u32>().context("AnyTLS padding 下限无效")?,
                    max.parse::<u32>().context("AnyTLS padding 上限无效")?,
                ),
                None => {
                    let size = range.parse::<u32>().context("AnyTLS padding 长度无效")?;
                    (size, size)
                }
            };
            if min > max || max > 65_535 {
                bail!("AnyTLS padding 范围必须满足 0 <= min <= max <= 65535");
            }
        }
    }
    if stop_count != 1 {
        bail!("AnyTLS padding_scheme 必须且只能包含一个 stop=N 条目");
    }
    Ok(())
}

pub(super) fn validate_host_port(value: &str) -> Result<()> {
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .context("IPv6 Reality fallback 必须采用 [address]:port 格式")?;
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .context("Reality fallback 必须采用 host:port 格式")?;
        if host.contains(':') {
            bail!("IPv6 Reality fallback 必须使用方括号，例如 [2001:db8::1]:443");
        }
        (host, port)
    };
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains(['/', '\\', '[', ']'])
    {
        bail!("Reality fallback 主机名或地址无效");
    }
    let port = port
        .parse::<u16>()
        .context("Reality fallback 端口必须是 1..=65535 的整数")?;
    if port == 0 {
        bail!("Reality fallback 端口必须在 1..=65535 范围内");
    }
    Ok(())
}
