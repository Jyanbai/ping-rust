//! Probe the executable used by configuration validation, never a PATH alias or
//! an unverified version/provenance string.
use std::{io::Write, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use crate::{config::Credentials, installer, utils};

const SUDOKU_PROBE: &str = "- address: 127.0.0.1:24444\n  protocol:\n    type: sudoku_mask\n    password: compatibilityProbeOnly123\n    ascii: prefer_entropy\n    padding_min: 0\n    padding_max: 10\n    protocol:\n      type: vless\n      user_id: 00000000-0000-4000-8000-000000000096\n      udp_enabled: true\n  rules:\n    - masks: 0.0.0.0/0\n      action: allow\n";

fn unsupported_sudoku(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.contains("unknown variant `sudoku_mask`")
}

pub(crate) async fn supports_sudoku(binary: &Path) -> Result<bool> {
    let mut candidate = tempfile::NamedTempFile::new().context("创建 shoes 能力检测配置失败")?;
    candidate.write_all(SUDOKU_PROBE.as_bytes())?;
    let mut command = Command::new(binary);
    command
        .kill_on_drop(true)
        .arg("--dry-run")
        .arg(candidate.path());
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .context("shoes 能力检测超时")?
        .with_context(|| format!("无法检测 shoes：{}", binary.display()))?;
    if output.status.success() {
        return Ok(true);
    }
    if unsupported_sudoku(&output.stderr) {
        return Ok(false);
    }
    // Do not treat arbitrary execution/config errors as permission to upgrade.
    bail!("shoes 能力检测失败：{}；现有配置未修改", binary.display())
}

pub(crate) fn credentials_need_sudoku(credentials: &Credentials) -> bool {
    matches!(
        credentials,
        Credentials::VlessSudoku { .. }
            | Credentials::VlessEnc {
                sudoku: Some(_),
                ..
            }
    )
}

pub(crate) fn managed_state_needs_sudoku(exclude: Option<uuid::Uuid>) -> Result<bool> {
    if !Path::new(utils::STATE_FILE).exists() {
        return Ok(false);
    }
    Ok(state_needs_sudoku(&crate::config::load_state()?, exclude))
}

fn state_needs_sudoku(state: &crate::config::ManagedState, exclude: Option<uuid::Uuid>) -> bool {
    state.profiles.iter().any(|profile| {
        Some(profile.id) != exclude && credentials_need_sudoku(&profile.credentials)
    })
}

pub(crate) async fn ensure_sudoku(required: bool) -> Result<()> {
    if !required || supports_sudoku(Path::new(utils::SHOES_BIN)).await? {
        return Ok(());
    }
    eprintln!(
        "当前 shoes 不支持 Sudoku，正在自动升级至 {}…",
        installer::SHOES_RELEASE_TAG
    );
    // Reuse the existing locked migration, digest verification and rollback.
    // No cargo build on the user's machine and no implicit downgrade.
    crate::cli::update_shoes(installer::InstallMethod::Release).await?;
    if !supports_sudoku(Path::new(utils::SHOES_BIN)).await? {
        bail!("升级后的 shoes 不支持 Sudoku，已取消节点操作");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_missing_sudoku_schema_requests_upgrade() {
        assert!(unsupported_sudoku(
            b"invalid protocol: unknown variant `sudoku_mask`, expected vless"
        ));
        assert!(!unsupported_sudoku(b"permission denied"));
        assert!(!unsupported_sudoku(b"unknown variant `other`"));
        assert!(!unsupported_sudoku(b"invalid sudoku_mask password"));
    }

    #[test]
    fn removing_last_sudoku_does_not_require_upgrade() {
        let state: crate::config::ManagedState = serde_json::from_str(include_str!(
            "../tests/fixtures/yaml/vless-enc-sudoku/state.json"
        ))
        .unwrap();
        assert!(state_needs_sudoku(&state, None));
        assert!(!state_needs_sudoku(&state, Some(state.profiles[0].id)));
        let mut two = state.clone();
        let mut second = two.profiles[0].clone();
        second.id = uuid::Uuid::new_v4();
        two.profiles.push(second);
        assert!(state_needs_sudoku(&two, Some(two.profiles[0].id)));
    }

    #[cfg(unix)]
    async fn probe_script(script: &str) -> Result<bool> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("shoes");
        std::fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        supports_sudoku(&binary).await
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn actual_binary_probe_distinguishes_old_new_and_broken() {
        assert!(probe_script("test \"$1\" = --dry-run && test -f \"$2\"")
            .await
            .unwrap());
        assert!(!probe_script("echo 'unknown variant `sudoku_mask`' >&2; exit 1")
            .await
            .unwrap());
        assert!(probe_script("echo 'permission denied' >&2; exit 1")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn pinned_shoes_accepts_capability_probe() {
        let Some(binary) = crate::shoes_e2e::shoes_binary(
            "shoes_compat::tests::pinned_shoes_accepts_capability_probe",
            &[crate::shoes_e2e::SHOES_E2E_BIN, crate::shoes_e2e::TEST_SHOES],
        ) else {
            return;
        };
        assert!(supports_sudoku(Path::new(&binary)).await.unwrap());
    }
}
