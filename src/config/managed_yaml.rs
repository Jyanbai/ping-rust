use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use super::{
    commit::{is_managed_profile_file_name, read_managed_file},
    ensure_servers_match_state, finish_state_load, parse_state, socks5,
    transaction::{ManagedRollback, ProfileDirectorySnapshot},
    ManagedProfile, ManagedState, ServerConfig,
};
use crate::yaml;

const LOSSY_WRITE: &str = "该操作暂不支持保留手工添加的字段，请先备份 /etc/shoes 并移除字段后重试";

pub(super) struct ManagedYaml {
    pub(super) servers: Vec<ServerConfig>,
    entries: Vec<Value>,
    changed: bool,
    original: ManagedRollback,
}

pub(super) struct PreparedYaml {
    pub(super) aggregate: String,
    pub(super) profiles: BTreeMap<String, Vec<u8>>,
}

impl ManagedYaml {
    pub(super) fn load(directory: &Path) -> Result<Self> {
        let config = read_managed_file(&directory.join("config.yaml"))?;
        let (servers, entries) = match &config {
            Some(bytes) => (
                yaml::from_slice(bytes).map_err(|_| anyhow!("config.yaml 不是可管理的配置"))?,
                yaml::from_slice(bytes).map_err(|_| anyhow!("config.yaml 无法解析节点条目"))?,
            ),
            None => (Vec::new(), Vec::new()),
        };
        Ok(Self {
            servers,
            entries,
            changed: false,
            original: ManagedRollback {
                config,
                state: read_managed_file(&directory.join("ping-rust-state.json"))?,
                profiles: ProfileDirectorySnapshot::capture(&directory.join("profiles"))?,
                generated_certificate: None,
                generated_certificate_key: None,
            },
        })
    }

    pub(super) fn state(&self, required: bool) -> Result<ManagedState> {
        if required && self.original.config.is_none() {
            bail!("未找到聚合配置 config.yaml");
        }
        match self.original.state.as_deref() {
            Some(bytes) => finish_state_load(parse_state(bytes)?, |state| {
                socks5::migrate_listen(state, &self.servers)
            }),
            None if self.original.config.is_some() => {
                bail!("检测到非 ping-rust 管理的 config.yaml；为避免覆盖，请先备份或改用 --output")
            }
            None if required => bail!("未找到管理状态 ping-rust-state.json"),
            None => Ok(ManagedState::default()),
        }
    }

    pub(super) fn rollback_mut(&mut self) -> &mut ManagedRollback {
        &mut self.original
    }

    pub(super) fn into_legacy(
        self,
        required: bool,
    ) -> Result<(Vec<ServerConfig>, ManagedState, ManagedRollback, bool)> {
        let state = self.state(required)?;
        let complete = self.guard_legacy(&state.profiles)?;
        ensure_servers_match_state(&self.servers, &state.profiles)?;
        Ok((self.servers, state, self.original, complete))
    }

    pub(super) fn check_copies(&self, profiles: &[ManagedProfile]) -> Result<bool> {
        let mut matched = BTreeSet::new();
        for (index, (entry, profile)) in self.entries.iter().zip(profiles).enumerate() {
            let name = profile.config_file_name();
            if let Some(bytes) = self.original.profiles.files.get(&name) {
                let ordinal = index + 1;
                let copy = yaml::from_slice(bytes)
                    .map_err(|_| anyhow!("{name} 无法解析（config.yaml 第 {ordinal} 项）"))?;
                if entry != &copy {
                    let field = differing_path(entry, &copy);
                    bail!("config.yaml 第 {ordinal} 项与 {name} 不一致（字段路径：${field}）");
                }
                matched.insert(name);
            }
        }
        for name in self.original.profiles.files.keys() {
            if is_managed_profile_file_name(name) && !matched.contains(name) {
                bail!("节点文件 {name} 缺少对应的 config.yaml 条目，请先备份并恢复一致后重试");
            }
        }
        Ok(matched.len() == profiles.len() && matched.len() == self.original.profiles.files.len())
    }

    pub(super) fn guard_legacy(&self, profiles: &[ManagedProfile]) -> Result<bool> {
        let complete = self.check_copies(profiles)?;
        self.ensure_lossless_legacy_write()?;
        Ok(complete)
    }

    pub(super) fn ensure_lossless_legacy_write(&self) -> Result<()> {
        if self.entries.len() != self.servers.len() {
            bail!("{LOSSY_WRITE}");
        }
        for (entry, server) in self.entries.iter().zip(&self.servers) {
            let modeled = yaml::to_value(server)?;
            if entry == &modeled {
                continue;
            }
            let mut normalized = entry.clone();
            if let Some(rules) = normalized.get_mut("rules") {
                normalize_rule_aliases(rules);
            }
            if normalized != modeled {
                bail!("{LOSSY_WRITE}");
            }
        }
        Ok(())
    }

    pub(super) fn append(&mut self, server: ServerConfig, rerender_rules: bool) -> Result<()> {
        let entry = yaml::to_value(&server)?;
        if rerender_rules {
            for (existing, previous) in self.entries.iter_mut().zip(&mut self.servers) {
                let before = yaml::to_value(&previous.rules)?;
                let rules = &mut existing["rules"];
                normalize_rule_aliases(rules);
                patch(rules, &before, &entry["rules"], "rules")?;
                previous.rules.clone_from(&server.rules);
            }
        }
        self.entries.push(entry);
        self.servers.push(server);
        self.changed = true;
        Ok(())
    }

    pub(super) fn edit(&mut self, index: usize, server: ServerConfig) -> Result<()> {
        let before = yaml::to_value(&self.servers[index])?;
        let after = yaml::to_value(&server)?;
        if before != after {
            patch(&mut self.entries[index], &before, &after, "")?;
            self.changed = true;
        }
        self.servers[index] = server;
        Ok(())
    }

    pub(super) fn remove(&mut self, index: usize) {
        self.entries.remove(index);
        self.servers.remove(index);
        self.changed = true;
    }

    pub(super) fn prepare(
        self,
        profiles: &[ManagedProfile],
    ) -> Result<(PreparedYaml, ManagedRollback)> {
        ensure_servers_match_state(&self.servers, profiles)?;
        let mut documents = BTreeMap::new();
        for (entry, profile) in self.entries.iter().zip(profiles) {
            let name = profile.config_file_name();
            let bytes = yaml::to_string(entry)?.into_bytes();
            if yaml::from_slice::<Value>(&bytes).ok().as_ref() != Some(entry) {
                bail!("生成的节点文件 {name} 无法无损往返，已拒绝提交");
            }
            if documents.insert(name.clone(), bytes).is_some() {
                bail!("节点文件名冲突：{name}");
            }
        }
        let aggregate = match (&self.original.config, self.changed) {
            (Some(bytes), false) => std::str::from_utf8(bytes)?.to_owned(),
            _ => yaml::to_string(&self.entries)?,
        };
        if yaml::from_str::<Vec<Value>>(&aggregate).ok().as_ref() != Some(&self.entries) {
            bail!("生成的 config.yaml 无法无损往返，已拒绝提交");
        }
        let servers: Vec<ServerConfig> = yaml::from_str(&aggregate)
            .map_err(|_| anyhow!("生成的 config.yaml 不是可管理的配置，已拒绝提交"))?;
        if yaml::to_value(servers)? != yaml::to_value(&self.servers)? {
            bail!("{LOSSY_WRITE}");
        }
        Ok((
            PreparedYaml {
                aggregate,
                profiles: documents,
            },
            self.original,
        ))
    }
}

fn normalize_rule_aliases(rules: &mut Value) {
    if let Some(rules) = rules.as_array_mut() {
        for rule in rules.iter_mut().filter_map(Value::as_object_mut) {
            if !rule.contains_key("client_chains") {
                if let Some(client) = rule.remove("client_chain") {
                    rule.insert("client_chains".to_owned(), client);
                }
            }
        }
    }
}

fn patch(raw: &mut Value, before: &Value, after: &Value, field: &str) -> Result<()> {
    if before == after {
        return Ok(());
    }
    if field == "protocol" && before["type"] == "vless" && after["type"] == "sudoku_mask" {
        let mut inner = raw.take();
        patch(&mut inner, before, &after["protocol"], "")?;
        *raw = after.clone();
        raw["protocol"] = inner;
        return Ok(());
    }
    if field == "protocol" && before["type"] == "sudoku_mask" && after["type"] == "vless" {
        let wrapper = raw.as_object_mut().context(LOSSY_WRITE)?;
        if wrapper.keys().any(|key| before.get(key).is_none()) {
            bail!("{LOSSY_WRITE}");
        }
        let mut inner = wrapper.remove("protocol").context(LOSSY_WRITE)?;
        patch(&mut inner, &before["protocol"], after, "")?;
        *raw = inner;
        return Ok(());
    }
    match (raw, before, after) {
        (Value::Object(raw), Value::Object(before), Value::Object(after)) => {
            if matches!(
                field,
                "tls_targets" | "reality_targets" | "shadowtls_targets"
            ) {
                let removed = before.iter().find(|(key, _)| !after.contains_key(*key));
                let added = after.iter().find(|(key, _)| !before.contains_key(*key));
                if let (Some((old_key, old)), Some((new_key, new))) = (removed, added) {
                    if raw.contains_key(new_key) {
                        bail!("{LOSSY_WRITE}");
                    }
                    let mut renamed = raw.remove(old_key).context(LOSSY_WRITE)?;
                    patch(&mut renamed, old, new, "")?;
                    raw.insert(new_key.clone(), renamed);
                    return Ok(());
                }
            }
            for (key, old) in before {
                if !after.contains_key(key) {
                    if raw
                        .get(key)
                        .is_some_and(|value| compound(value) && value != old)
                    {
                        bail!("{LOSSY_WRITE}");
                    }
                    raw.remove(key);
                }
            }
            for (key, new) in after {
                let old = before.get(key);
                if old == Some(new) {
                    continue;
                }
                match (raw.get_mut(key), old) {
                    (Some(value), Some(old)) => patch(value, old, new, key)?,
                    (Some(value), None) if compound(value) && value != new => {
                        bail!("{LOSSY_WRITE}")
                    }
                    _ => {
                        raw.insert(key.clone(), new.clone());
                    }
                }
            }
        }
        (Value::Array(raw), Value::Array(before), Value::Array(after))
            if raw.len() == before.len() && before.len() == after.len() =>
        {
            for ((value, old), new) in raw.iter_mut().zip(before).zip(after) {
                patch(value, old, new, "")?;
            }
        }
        (value, old, new) if !compound(value) || value == old => *value = new.clone(),
        _ => bail!("{LOSSY_WRITE}"),
    }
    Ok(())
}

fn compound(value: &Value) -> bool {
    value.is_object() || value.is_array()
}

fn differing_path(left: &Value, right: &Value) -> String {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let key = left
                .keys()
                .chain(right.keys())
                .find(|key| left.get(*key) != right.get(*key))
                .expect("Values differ");
            let segment = match key.as_str() {
                "address" | "transport" | "protocol" | "rules" | "quic_settings"
                | "tls_targets" | "reality_targets" | "shadowtls_targets" | "encryption_limits" => {
                    key.as_str()
                }
                _ => "<字段>",
            };
            let tail = match (left.get(key), right.get(key)) {
                (Some(lhs), Some(rhs)) => differing_path(lhs, rhs),
                _ => String::new(),
            };
            format!(".{segment}{tail}")
        }
        (Value::Array(left), Value::Array(right)) => {
            if let Some(index) = left.iter().zip(right).position(|(lhs, rhs)| lhs != rhs) {
                return format!("[{index}]{}", differing_path(&left[index], &right[index]));
            }
            format!("[{}]", left.len().min(right.len()))
        }
        _ => String::new(),
    }
}
