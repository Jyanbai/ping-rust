use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{anyhow, bail, Context, Result};

#[cfg(test)]
use super::{ensure_servers_match_state, schema::ServerConfig, ManagedProfile};
use super::{
    managed_yaml::PreparedYaml,
    save_state_to,
    transaction::{read_optional, restore_snapshot, ManagedRollback, ProfileDirectorySnapshot},
    ManagedState,
};
use crate::{performance, utils};

#[cfg(test)]
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
    let profiles = profile_documents(servers, &state.profiles)?;
    let aggregate = aggregate_profile_documents(&profiles, &state.profiles)?;
    commit_yaml_with_state_writer(
        config_path,
        state_path,
        profiles_path,
        &PreparedYaml {
            aggregate,
            profiles,
        },
        state,
        None,
        write_state,
    )
}

pub(super) fn commit_prepared(
    directory: &Path,
    yaml: &PreparedYaml,
    state: &ManagedState,
    original: &ManagedRollback,
) -> Result<()> {
    commit_prepared_with_state_writer(directory, yaml, state, original, save_state_to)
}

pub(super) fn commit_prepared_with_state_writer(
    directory: &Path,
    yaml: &PreparedYaml,
    state: &ManagedState,
    original: &ManagedRollback,
    write_state: impl FnOnce(&Path, &ManagedState) -> Result<()>,
) -> Result<()> {
    commit_yaml_with_state_writer(
        &directory.join("config.yaml"),
        &directory.join("ping-rust-state.json"),
        &directory.join("profiles"),
        yaml,
        state,
        Some(original),
        write_state,
    )
}

fn commit_yaml_with_state_writer(
    config_path: &Path,
    state_path: &Path,
    profiles_path: &Path,
    yaml: &PreparedYaml,
    state: &ManagedState,
    original: Option<&ManagedRollback>,
    write_state: impl FnOnce(&Path, &ManagedState) -> Result<()>,
) -> Result<()> {
    let _timer = performance::stage("config_commit");
    let old_config = read_optional(config_path)?;
    let old_state = read_optional(state_path)?;
    let old_profiles = ProfileDirectorySnapshot::capture(profiles_path)?;
    if original.is_some_and(|original| {
        old_config != original.config
            || old_state != original.state
            || old_profiles != original.profiles
    }) {
        bail!("受管配置在校验期间已变更，请重试");
    }
    let runtime_unchanged = old_config.as_deref() == Some(yaml.aggregate.as_bytes());
    let commit = (|| {
        write_profile_documents(profiles_path, &yaml.profiles)?;
        write_state(state_path, state)?;
        if !runtime_unchanged {
            utils::atomic_write(config_path, yaml.aggregate.as_bytes(), 0o600)?;
        }
        Ok::<(), anyhow::Error>(())
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

#[cfg(test)]
std::thread_local! {
    pub(super) static AFTER_PROFILE_REPLACE: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
}

pub(super) fn commit_profile_with_activation(
    directory: &Path,
    yaml: &PreparedYaml,
    target: &str,
    state: &ManagedState,
    original: &ManagedRollback,
    mut activate: impl FnMut(bool) -> Result<()>,
) -> Result<()> {
    let profiles = directory.join("profiles");
    let state_path = directory.join("ping-rust-state.json");
    let config_path = directory.join("config.yaml");
    if read_managed_file(&config_path)? != original.config
        || read_managed_file(&state_path)? != original.state
        || ProfileDirectorySnapshot::capture(&profiles)? != original.profiles
    {
        bail!("受管配置在校验期间已变更，请重试");
    }
    let state_json = serde_json::to_vec_pretty(state).context("序列化管理状态失败")?;
    let mut files = Vec::new();
    for (name, bytes) in &yaml.profiles {
        let previous = original.profiles.files.get(name).map(Vec::as_slice);
        if name == target || previous.is_none() {
            files.push((profiles.join(name), bytes.as_slice(), previous));
        }
    }
    files.push((
        config_path,
        yaml.aggregate.as_bytes(),
        original.config.as_deref(),
    ));

    let mut committed = 0;
    let mut created_profiles = false;
    let update = (|| {
        if !original.profiles.existed {
            fs::create_dir(&profiles).context("创建节点配置目录失败")?;
            created_profiles = true;
            utils::set_mode(&profiles, 0o700).context("设置节点配置目录权限失败")?;
        }
        let staged = files
            .iter()
            .map(|(path, bytes, _)| utils::stage_atomic_write(path, bytes, 0o600))
            .collect::<Result<Vec<_>>>()?;
        for ((path, _, _), temp) in files.iter().zip(staged) {
            utils::persist_replace(temp, path)?;
            committed += 1;
            #[cfg(test)]
            if let Some(after_replace) = AFTER_PROFILE_REPLACE.take() {
                after_replace();
            }
        }
        activate(false)?;
        utils::atomic_write(&state_path, &state_json, 0o600)
    })();
    let Err(error) = update else {
        return Ok(());
    };

    let mut recovery_errors = Vec::new();
    for (path, _, original) in files.iter().take(committed).rev() {
        if let Err(error) = restore_snapshot(path, *original, 0o600) {
            recovery_errors.push(format!("恢复 {} 失败：{error:#}", path.display()));
        }
    }
    if created_profiles {
        if let Err(error) = fs::remove_dir(&profiles) {
            recovery_errors.push(format!("恢复节点目录失败：{error}"));
        }
    }
    if committed != 0 {
        if let Err(error) = activate(true) {
            recovery_errors.push(format!("重启或验证原服务失败：{error:#}"));
        }
    }
    if !recovery_errors.is_empty() {
        return Err(error.context(format!(
            "SOCKS5 加固失败，回滚不完整：{}",
            recovery_errors.join("；")
        )));
    }
    if committed == 0 {
        return Err(error.context("SOCKS5 加固失败，配置未提交"));
    }
    Err(error.context("SOCKS5 加固失败；原配置已恢复，服务已重启并验证"))
}

pub(super) fn read_managed_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => read_optional(path),
        Ok(_) => bail!("受管文件不是普通文件：{}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取文件 {} 失败", path.display())),
    }
}

#[cfg(test)]
pub(super) fn profile_documents(
    servers: &[ServerConfig],
    profiles: &[ManagedProfile],
) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure_servers_match_state(servers, profiles)?;
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

#[cfg(test)]
pub(super) fn aggregate_profile_documents(
    documents: &BTreeMap<String, Vec<u8>>,
    profiles: &[ManagedProfile],
) -> Result<String> {
    let mut servers = Vec::with_capacity(profiles.len());
    let mut entries = Vec::with_capacity(profiles.len());
    for profile in profiles {
        let name = profile.config_file_name();
        let contents = documents
            .get(&name)
            .with_context(|| format!("缺少节点文件 {name}"))?;
        let invalid = || anyhow!("解析节点文件 {name} 失败");
        servers.push(crate::yaml::from_slice(contents).map_err(|_| invalid())?);
        entries
            .push(crate::yaml::from_slice::<serde_json::Value>(contents).map_err(|_| invalid())?);
    }
    ensure_servers_match_state(&servers, profiles)?;
    crate::yaml::to_string(&entries).context("聚合节点配置失败")
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
