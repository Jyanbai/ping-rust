//! Adapter for shoes' credential generator. Never include its output in errors.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VlessEncMode {
    #[default]
    Native,
    Xorpub,
    Random,
}

impl VlessEncMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xorpub => "xorpub",
            Self::Random => "random",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VlessEncAuth {
    #[default]
    X25519,
    Mlkem768,
}

#[derive(Clone, Debug, Default, clap::Args)]
pub struct Options {
    /// VLESS Encryption 外观；random 关闭 TCP splice
    #[arg(long = "encryption-mode", value_enum, default_value = "native")]
    pub mode: VlessEncMode,
    /// mlkem768 链接约 1.6 KB，二维码可能无法扫描
    #[arg(long = "encryption-auth", value_enum, default_value = "x25519")]
    pub auth: VlessEncAuth,
    /// VLESS-ENC 开启 Vision（默认关闭）
    #[arg(long)]
    pub vision: bool,
}

impl Options {
    pub fn warn(&self) {
        if self.mode == VlessEncMode::Random {
            eprintln!("提示：random 外观会关闭 TCP splice。");
        }
        if self.auth == VlessEncAuth::Mlkem768 {
            eprintln!("提示：mlkem768 分享链接约 1.6 KB，二维码可能无法扫描。");
        }
    }
}

impl VlessEncAuth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::Mlkem768 => "mlkem768",
        }
    }
}

pub(crate) struct CredentialPair {
    pub encryption: String,
    pub decryption: String,
}

pub(crate) fn generate(mode: VlessEncMode, auth: VlessEncAuth) -> Result<CredentialPair> {
    #[cfg(test)]
    let binary = std::env::var_os("PING_RUST_TEST_SHOES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::utils::SHOES_BIN.into());
    #[cfg(not(test))]
    let binary = std::path::PathBuf::from(crate::utils::SHOES_BIN);
    generate_with_binary(&binary, mode.as_str(), auth.as_str())
}

pub(crate) fn generate_with_binary(
    binary: &std::path::Path,
    mode: &str,
    auth: &str,
) -> Result<CredentialPair> {
    if !matches!(mode, "native" | "xorpub" | "random") || !matches!(auth, "x25519" | "mlkem768") {
        anyhow::bail!("VLESS Encryption 模式或认证方式无效");
    }
    let output = std::process::Command::new(binary)
        .args([
            "generate-vless-encryption",
            "--auth",
            auth,
            "--mode",
            mode,
            "--rtt",
            "0rtt",
            "--lifetime",
            "600s",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|_| anyhow!("无法启动 shoes VLESS Encryption 密钥生成器"))?;
    if !output.status.success() {
        anyhow::bail!("shoes VLESS Encryption 密钥生成失败");
    }
    if !output.stderr.is_empty() {
        anyhow::bail!("shoes VLESS Encryption 输出格式无效");
    }
    parse_output(&output.stdout, mode, auth)
}

pub(crate) fn parse_output(output: &[u8], mode: &str, auth: &str) -> Result<CredentialPair> {
    let invalid = || anyhow!("shoes VLESS Encryption 输出格式无效");
    if !matches!(mode, "native" | "xorpub" | "random") {
        return Err(invalid());
    }
    let (public_len, secret_len) = match auth {
        "x25519" => (32, 32),
        "mlkem768" => (1184, 64),
        _ => return Err(invalid()),
    };
    let text = std::str::from_utf8(output).map_err(|_| invalid())?;
    let mut lines = text.lines();
    let encryption = lines
        .next()
        .and_then(|line| line.strip_prefix("encryption: "))
        .ok_or_else(invalid)?;
    let decryption = lines
        .next()
        .and_then(|line| line.strip_prefix("decryption: "))
        .ok_or_else(invalid)?;
    if lines.next().is_some() {
        return Err(invalid());
    }
    for (value, phase, length) in [
        (encryption, "0rtt", public_len),
        (decryption, "600s", secret_len),
    ] {
        let prefix = format!("mlkem768x25519plus.{mode}.{phase}.");
        let key = value.strip_prefix(&prefix).ok_or_else(invalid)?;
        let decoded = URL_SAFE_NO_PAD.decode(key).map_err(|_| invalid())?;
        if decoded.len() != length || URL_SAFE_NO_PAD.encode(&decoded) != key {
            return Err(invalid());
        }
    }
    Ok(CredentialPair {
        encryption: encryption.to_owned(),
        decryption: decryption.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::*;

    fn output(mode: &str, auth: &str) -> String {
        let (public_len, secret_len) = if auth == "x25519" {
            (32, 32)
        } else {
            (1184, 64)
        };
        format!(
            "encryption: mlkem768x25519plus.{mode}.0rtt.{}\ndecryption: mlkem768x25519plus.{mode}.600s.{}\n",
            URL_SAFE_NO_PAD.encode(vec![7; public_len]),
            URL_SAFE_NO_PAD.encode(vec![9; secret_len]),
        )
    }

    #[test]
    fn vless_encryption_parser_accepts_each_supported_mode_and_auth() {
        for mode in ["native", "xorpub", "random"] {
            for auth in ["x25519", "mlkem768"] {
                let text = output(mode, auth);
                let pair = parse_output(text.as_bytes(), mode, auth).unwrap();
                assert!(pair
                    .encryption
                    .starts_with(&format!("mlkem768x25519plus.{mode}.0rtt.")));
                assert!(pair
                    .decryption
                    .starts_with(&format!("mlkem768x25519plus.{mode}.600s.")));
                assert!(parse_output(text.replace('\n', "\r\n").as_bytes(), mode, auth).is_ok());
            }
        }
    }

    #[test]
    fn vless_encryption_parser_rejects_missing_extra_and_malformed_lines_without_leaks() {
        let valid = output("native", "x25519");
        let lines: Vec<_> = valid.lines().collect();
        for text in [
            String::new(),
            format!("{}\n", lines[0]),
            format!("{}\n", lines[1]),
            format!("{valid}\n"),
            format!("{valid}unexpected\n"),
            format!("{}\n{}\n", lines[1], lines[0]),
            format!("{}\n{}\n", lines[0], lines[0]),
            valid.replace("encryption: ", "encryption="),
            valid.replace("decryption: ", "decryption="),
            valid.replace(".0rtt.", ".1rtt."),
            valid.replace(".600s.", ".0s."),
            valid.replace("native", "sudoku"),
            valid.replace(".0rtt.", ".0rtt. "),
            valid.replace("plus", "unknown"),
            valid.replace(&URL_SAFE_NO_PAD.encode(vec![9; 32]), "secret-sentinel"),
        ] {
            let error = parse_output(text.as_bytes(), "native", "x25519")
                .err()
                .expect("must reject malformed output");
            assert_eq!(error.to_string(), "shoes VLESS Encryption 输出格式无效");
            assert!(!format!("{error:#}").contains("secret-sentinel"));
            assert!(!format!("{error:#}").contains(&URL_SAFE_NO_PAD.encode(vec![9; 32])));
        }
        assert!(parse_output(b"\xff\xfe", "native", "x25519").is_err());
    }

    #[test]
    fn vless_encryption_parser_requires_requested_mode_auth_and_key_sizes() {
        let valid = output("native", "x25519");
        assert!(parse_output(valid.as_bytes(), "random", "x25519").is_err());
        assert!(parse_output(valid.as_bytes(), "native", "mlkem768").is_err());
        assert!(parse_output(valid.as_bytes(), "native", "unknown").is_err());
        let wrong_size = valid.replace(
            &URL_SAFE_NO_PAD.encode(vec![7; 32]),
            &URL_SAFE_NO_PAD.encode(vec![7; 31]),
        );
        assert!(parse_output(wrong_size.as_bytes(), "native", "x25519").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn vless_encryption_generator_passes_explicit_defaults_and_hides_failed_output() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("shoes");
        let script = format!(
            "#!/bin/sh\n[ \"$*\" = 'generate-vless-encryption --auth x25519 --mode native --rtt 0rtt --lifetime 600s' ] || exit 2\ncat <<'OUTPUT'\n{}OUTPUT\n",
            output("native", "x25519"),
        );
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(generate_with_binary(&binary, "native", "x25519").is_ok());
        fs::write(
            &binary,
            "#!/bin/sh\necho secret-sentinel\necho secret-sentinel >&2\nexit 1\n",
        )
        .unwrap();
        let error = generate_with_binary(&binary, "native", "x25519")
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "shoes VLESS Encryption 密钥生成失败");
        assert!(!format!("{error:#}").contains("secret-sentinel"));
        assert!(generate_with_binary(&binary, "sudoku", "x25519").is_err());
    }

    #[test]
    #[ignore = "requires the checksum-verified shoes v0.3.6 binary"]
    fn vless_encryption_real_shoes_generator() {
        let binary = std::env::var_os("PING_RUST_TEST_SHOES").expect("set binary path");
        for mode in ["native", "xorpub", "random"] {
            for auth in ["x25519", "mlkem768"] {
                assert!(generate_with_binary(std::path::Path::new(&binary), mode, auth).is_ok());
            }
        }
    }
}
