use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};

use super::{
    ensure_servers_match_state, save_state_to,
    schema::ServerConfig,
    transaction::{read_optional, restore_snapshot, ProfileDirectorySnapshot},
    ManagedProfile, ManagedState,
};
use crate::{performance, utils};

pub(super) fn commit_managed(
    config_path: &Path,
    state_path: &Path,
    servers: &[ServerConfig],
    state: &ManagedState,
) -> Result<()> {
    commit_managed_with_state_writer(
        config_path,
        state_path,
        Path::new(utils::PROFILES_DIR),
        servers,
        state,
        save_state_to,
    )
}

pub(super) fn commit_managed_with_state_writer<F>(
    config_path: &Path,
    state_path: &Path,
    profiles_path: &Path,
    servers: &[ServerConfig],
    state: &ManagedState,
    write_state: F,
) -> Result<()>
where
    F: FnOnce(&Path, &ManagedState) -> Result<()>,
{
    let _timer = performance::stage("config_commit");
    let old_config = read_optional(config_path)?;
    let old_state = read_optional(state_path)?;
    let old_profiles = ProfileDirectorySnapshot::capture(profiles_path)?;
    let documents = profile_documents(servers, &state.profiles)?;
    let aggregate_yaml = aggregate_profile_documents(&documents, &state.profiles)?;
    let commit = (|| {
        write_profile_documents(profiles_path, &documents)?;
        utils::atomic_write(config_path, aggregate_yaml.as_bytes(), 0o600)?;
        write_state(state_path, state)
    })();
    if let Err(error) = commit {
        let state_rollback = restore_snapshot(state_path, old_state.as_deref(), 0o600);
        let config_rollback = restore_snapshot(config_path, old_config.as_deref(), 0o600);
        let profiles_rollback = old_profiles.restore(profiles_path);
        let mut rollback_failures = Vec::new();
        if let Err(error) = state_rollback {
            rollback_failures.push(format!("状态={error:#}"));
        }
        if let Err(error) = config_rollback {
            rollback_failures.push(format!("聚合配置={error:#}"));
        }
        if let Err(error) = profiles_rollback {
            rollback_failures.push(format!("节点目录={error:#}"));
        }
        if rollback_failures.is_empty() {
            return Err(error.context("受管配置提交失败，聚合配置、状态和节点文件已回滚"));
        }
        return Err(error.context(format!(
            "受管配置提交失败且回滚不完整：{}",
            rollback_failures.join("；")
        )));
    }
    Ok(())
}

pub(super) fn profile_documents(
    servers: &[ServerConfig],
    profiles: &[ManagedProfile],
) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure_servers_match_state(servers, profiles)?;
    let mut documents = BTreeMap::new();
    for (server, profile) in servers.iter().zip(profiles) {
        let name = profile.config_file_name();
        let yaml =
            serde_yaml::to_string(server).with_context(|| format!("序列化节点文件 {name} 失败"))?;
        if documents.insert(name.clone(), yaml.into_bytes()).is_some() {
            bail!("节点文件名冲突：{name}");
        }
    }
    Ok(documents)
}

pub(super) fn aggregate_profile_documents(
    documents: &BTreeMap<String, Vec<u8>>,
    profiles: &[ManagedProfile],
) -> Result<String> {
    let mut servers = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let name = profile.config_file_name();
        let contents = documents
            .get(&name)
            .with_context(|| format!("缺少节点文件 {name}"))?;
        let server: ServerConfig = serde_yaml::from_slice(contents)
            .with_context(|| format!("解析节点文件 {name} 失败"))?;
        servers.push(server);
    }
    ensure_servers_match_state(&servers, profiles)?;
    serde_yaml::to_string(&servers).context("聚合节点配置失败")
}

pub(super) fn write_profile_documents(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    utils::ensure_directory(path, 0o700)?;
    let mut existing = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            bail!(
                "节点目录包含链接、目录或特殊文件：{}",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("节点文件名不是 UTF-8：{}", entry.path().display()))?;
        if !is_managed_profile_file_name(&name) {
            bail!("节点目录包含非 ping-rust 文件 {name}，已拒绝覆盖");
        }
        existing.push(name);
    }
    for (name, contents) in documents {
        utils::atomic_write(&path.join(name), contents, 0o600)?;
    }
    for name in existing {
        if !documents.contains_key(&name) {
            fs::remove_file(path.join(&name))
                .with_context(|| format!("删除旧节点文件 {name} 失败"))?;
        }
    }
    Ok(())
}

pub(super) fn profile_documents_are_current(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
) -> Result<bool> {
    let snapshot = ProfileDirectorySnapshot::capture(path)?;
    if !snapshot.existed {
        return Ok(documents.is_empty());
    }
    Ok(snapshot.files == *documents)
}

pub(super) fn is_managed_profile_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".yaml") else {
        return false;
    };
    let prefixes = [
        "VLESS-REALITY-",
        "HYSTERIA2-",
        "TUIC-",
        "SHADOWSOCKS-",
        "ANYTLS-",
        "VLESS-TLS-VISION-",
        "VLESS-WS-TLS-",
        "TROJAN-TLS-",
        "TROJAN-REALITY-",
        "VMESS-WS-TLS-",
        "SOCKS5-",
    ];
    prefixes.iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|value| {
            value
                .parse::<u16>()
                .is_ok_and(|port| port > 0 && port.to_string() == value)
        })
    })
}
