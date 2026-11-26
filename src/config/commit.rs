use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};

use super::{
    ensure_servers_match_state, save_state_to,
    schema::ServerConfig,
    transaction::{read_optional, restore_snapshot, FileAccess, ProfileDirectorySnapshot},
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
    let documents = profile_documents(servers, &state.profiles)?;
    let aggregate_yaml = aggregate_profile_documents(&documents, &state.profiles)?;
    commit_managed_with_writers(
        config_path,
        state_path,
        profiles_path,
        &documents,
        &aggregate_yaml,
        |path| write_state(path, state),
        |path, write| match write {
            ManagedWrite::Profiles(documents) => write_profile_documents(path, documents),
            ManagedWrite::Config(contents)
            | ManagedWrite::RestoreConfig(contents)
            | ManagedWrite::RestoreState(contents) => utils::atomic_write(path, contents, 0o600),
        },
    )
}

pub(super) enum ManagedWrite<'a> {
    Profiles(&'a BTreeMap<String, Vec<u8>>),
    Config(&'a [u8]),
    RestoreConfig(&'a [u8]),
    RestoreState(&'a [u8]),
}

pub(super) fn commit_managed_with_writers(
    config_path: &Path,
    state_path: &Path,
    profiles_path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
    aggregate_yaml: &str,
    write_state: impl FnOnce(&Path) -> Result<()>,
    write_snapshot: impl Fn(&Path, ManagedWrite<'_>) -> Result<()>,
) -> Result<()> {
    let _timer = performance::stage("config_commit");
    let old_config = read_optional(config_path)?;
    let old_state = read_optional(state_path)?;
    let old_profiles = ProfileDirectorySnapshot::capture(profiles_path)?;
    let runtime_unchanged = old_config.as_deref() == Some(aggregate_yaml.as_bytes());
    let commit = (|| {
        write_snapshot(profiles_path, ManagedWrite::Profiles(documents))?;
        write_state(state_path)?;
        if !runtime_unchanged {
            write_snapshot(config_path, ManagedWrite::Config(aggregate_yaml.as_bytes()))?;
        }
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = commit {
        let state_rollback = match old_state {
            Some(bytes) => write_snapshot(state_path, ManagedWrite::RestoreState(&bytes)),
            None => restore_snapshot(state_path, None, 0o600),
        };
        let config_rollback = match old_config {
            Some(bytes) => write_snapshot(config_path, ManagedWrite::RestoreConfig(&bytes)),
            None => restore_snapshot(config_path, None, 0o600),
        };
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
    serialize_profile_documents(servers, profiles)
}

pub(super) fn serialize_profile_documents(
    servers: &[impl serde::Serialize],
    profiles: &[ManagedProfile],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut documents = BTreeMap::new();
    for (server, profile) in servers.iter().zip(profiles) {
        let name = profile.config_file_name();
        let yaml = crate::yaml::to_string(server)
            .with_context(|| format!("序列化节点文件 {name} 失败"))?;
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
        let server: ServerConfig = crate::yaml::from_slice(contents)
            .with_context(|| format!("解析节点文件 {name} 失败"))?;
        servers.push(server);
    }
    ensure_servers_match_state(&servers, profiles)?;
    crate::yaml::to_string(&servers).context("聚合节点配置失败")
}

pub(super) fn write_profile_documents(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    write_profile_documents_inner(path, documents, false, |name, contents| {
        utils::atomic_write(&path.join(name), contents, 0o600)
    })
}

pub(super) fn write_profile_documents_with_access(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
    snapshot: &ProfileDirectorySnapshot,
    changed_profile: &str,
    protect_credentials: bool,
) -> Result<()> {
    write_profile_documents_inner(path, documents, snapshot.existed(), |name, contents| {
        let changed = name == changed_profile;
        // 加固只更新目标节点，缺失文件从聚合配置补齐。
        if changed || !snapshot.has_profile(name) {
            let access = if changed && protect_credentials {
                FileAccess::apply_private
            } else {
                FileAccess::apply
            };
            snapshot.write_profile(path, name, contents, access)?;
        }
        Ok(())
    })
}

pub(super) fn repair_profile_documents(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
    snapshot: ProfileDirectorySnapshot,
) -> Result<()> {
    let repair =
        write_profile_documents_inner(path, documents, snapshot.existed(), |name, contents| {
            if !snapshot.profile_yaml_is_current(name, contents) {
                snapshot.write_profile(
                    path,
                    name,
                    contents,
                    FileAccess::apply_without_public_access,
                )?;
            }
            Ok(())
        });
    if let Err(error) = repair {
        if !ProfileDirectorySnapshot::capture(path).is_ok_and(|current| current == snapshot) {
            if let Err(rollback) = snapshot.restore(path) {
                return Err(error.context(format!("恢复节点文件失败：{rollback:#}")));
            }
        }
        return Err(error);
    }
    Ok(())
}

fn write_profile_documents_inner(
    path: &Path,
    documents: &BTreeMap<String, Vec<u8>>,
    directory_exists: bool,
    write_profile: impl Fn(&str, &[u8]) -> Result<()>,
) -> Result<()> {
    if !directory_exists {
        utils::ensure_directory(path, 0o700)?;
    }
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
        write_profile(name, contents)?;
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
    Ok(ProfileDirectorySnapshot::capture(path)?.matches_documents(documents))
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
        "SNELL-",
        "NAIVEPROXY-",
        "VLESS-ENC-",
        "VLESS-XHTTP-REALITY-",
        "VLESS-SUDOKU-",
    ];
    prefixes.iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|value| {
            value
                .parse::<u16>()
                .is_ok_and(|port| port > 0 && port.to_string() == value)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::is_managed_profile_file_name;

    #[test]
    fn naiveproxy_profile_files_are_managed_without_accepting_lookalikes() {
        assert!(is_managed_profile_file_name("NAIVEPROXY-443.yaml"));
        assert!(!is_managed_profile_file_name("NAIVEPROXY-0.yaml"));
        assert!(!is_managed_profile_file_name("NAIVEPROXY-0443.yaml"));
        assert!(!is_managed_profile_file_name("NAIVEPROXY-443.yaml.bak"));
    }
}
