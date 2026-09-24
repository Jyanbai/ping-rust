use std::{collections::BTreeSet, error::Error, fmt, path::Path};

use anyhow::{bail, Result};

use crate::{
    chain_proxy::ChainProxyChange,
    config::{self, GenerationRequest, GenerationResult, ProfileChange},
    performance, service, utils,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyOperation {
    AddOrEdit,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplyStrategy {
    NoServiceAction,
    Activate,
    Stop,
    HotReload,
}

fn plan_apply(
    operation: ApplyOperation,
    runtime_changed: bool,
    was_active: bool,
    remaining_profiles: usize,
    hot_reload_ready: bool,
) -> ApplyStrategy {
    if !runtime_changed || (operation == ApplyOperation::Delete && !was_active) {
        ApplyStrategy::NoServiceAction
    } else if operation == ApplyOperation::Delete && remaining_profiles == 0 {
        ApplyStrategy::Stop
    } else if was_active && hot_reload_ready {
        ApplyStrategy::HotReload
    } else {
        ApplyStrategy::Activate
    }
}

#[derive(Debug)]
pub(crate) struct ActivationFailure {
    message: String,
    source: anyhow::Error,
}

impl ActivationFailure {
    pub(crate) fn new(message: impl Into<String>, source: anyhow::Error) -> Self {
        Self {
            message: message.into(),
            source,
        }
    }
}

impl fmt::Display for ActivationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ActivationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub async fn generate_and_activate(request: GenerationRequest) -> Result<GenerationResult> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let hot_reload_snapshot = match service::capture_hot_reload_snapshot(&service_snapshot) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            service::hot_reload_trace(&format!("capture failed: {error:#}"));
            None
        }
    }
    .filter(|snapshot| {
        let observed = config::load_state().is_ok_and(|state| {
            state
                .profiles
                .iter()
                .all(|profile| snapshot.listening_ports.contains(&profile.port))
        });
        if !observed {
            service::hot_reload_trace("existing managed ports not observed");
        }
        observed
    });
    let mut result = config::generate_locked(request, lock).await?;
    let strategy = plan_apply(
        ApplyOperation::AddOrEdit,
        true,
        service_snapshot.was_active(),
        1,
        hot_reload_snapshot.is_some(),
    );
    let activation = if strategy == ApplyStrategy::HotReload {
        let snapshot = hot_reload_snapshot.expect("hot reload strategy requires a snapshot");
        let mut expected = snapshot.listening_ports.clone();
        expected.insert(result.profile.port);
        service::hot_reload_and_verify(snapshot, &expected, &BTreeSet::new())
    } else {
        service::activate_and_verify()
    };
    if let Err(activation) = activation {
        let _rollback_timer = performance::stage("rollback_restore");
        let config_rollback = result.rollback_managed();
        let service_rollback = service::restore_snapshot(service_snapshot);
        let message = match (config_rollback, service_rollback) {
            (Ok(()), Ok(())) => "shoes 激活失败，配置和服务状态已回滚".to_owned(),
            (Err(config), Ok(())) => {
                format!("shoes 激活失败，服务状态已恢复，但配置回滚失败：配置={config:#}")
            }
            (Ok(()), Err(service)) => {
                format!("shoes 激活失败，配置已回滚，但服务状态恢复失败：服务={service:#}")
            }
            (Err(config), Err(service)) => format!(
                "shoes 激活失败，配置与服务状态回滚均失败：配置={config:#}；服务={service:#}"
            ),
        };
        return Err(anyhow::Error::new(ActivationFailure::new(
            message, activation,
        )));
    }
    Ok(result)
}

pub async fn update_and_activate(id: Uuid, change: ProfileChange) -> Result<GenerationResult> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let observable_port_change = matches!(&change, ProfileChange::Port(_));
    let previous_port = if observable_port_change {
        config::load_state()?
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.port)
    } else {
        None
    };
    let hot_reload_snapshot = observable_port_change
        .then(|| {
            service::capture_hot_reload_snapshot(&service_snapshot)
                .ok()
                .flatten()
        })
        .flatten()
        .filter(|snapshot| {
            previous_port.is_some_and(|port| snapshot.listening_ports.contains(&port))
        });
    let mut result = config::update_profile_locked(id, change, lock).await?;
    let strategy = plan_apply(
        ApplyOperation::AddOrEdit,
        result.runtime_config_changed,
        service_snapshot.was_active(),
        1,
        hot_reload_snapshot.is_some() && observable_port_change,
    );
    if strategy == ApplyStrategy::NoServiceAction {
        result.finish_update();
        return Ok(result);
    }
    let activation = if strategy == ApplyStrategy::HotReload {
        let snapshot = hot_reload_snapshot.expect("hot reload strategy requires a snapshot");
        let mut expected = snapshot.listening_ports.clone();
        if let Some(previous_port) = previous_port {
            expected.remove(&previous_port);
        }
        expected.insert(result.profile.port);
        let mut removed = BTreeSet::new();
        if let Some(previous_port) = previous_port.filter(|port| *port != result.profile.port) {
            removed.insert(previous_port);
        }
        service::hot_reload_and_verify(snapshot, &expected, &removed)
    } else {
        service::activate_and_verify()
    };
    if let Err(activation) = activation {
        let _rollback_timer = performance::stage("rollback_restore");
        let config_rollback = result.rollback_managed();
        let service_rollback = service::restore_snapshot(service_snapshot);
        return match (config_rollback, service_rollback) {
            (Ok(()), Ok(())) => {
                Err(activation.context("shoes 激活失败，配置修改和服务状态已回滚"))
            }
            (Err(config), Ok(())) => bail!(
                "shoes 激活失败，服务状态已恢复，但配置修改回滚失败：激活={activation:#}；配置={config:#}"
            ),
            (Ok(()), Err(service)) => bail!(
                "shoes 激活失败，配置修改已回滚，但服务状态恢复失败：激活={activation:#}；服务={service:#}"
            ),
            (Err(config), Err(service)) => bail!(
                "shoes 激活失败，配置修改与服务状态回滚均失败：激活={activation:#}；配置={config:#}；服务={service:#}"
            ),
        };
    }
    result.finish_update();
    Ok(result)
}

pub async fn delete_and_activate(id: Uuid) -> Result<config::ManagedProfile> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let was_active = Path::new(utils::SERVICE_FILE).exists() && service::is_active()?;
    let hot_reload_snapshot = if was_active {
        service::capture_hot_reload_snapshot(&service_snapshot)
            .ok()
            .flatten()
    } else {
        None
    }
    .filter(|snapshot| {
        config::load_state().is_ok_and(|state| {
            state
                .profiles
                .iter()
                .all(|profile| snapshot.listening_ports.contains(&profile.port))
        })
    });
    let mut result = config::delete_profile_locked(id, lock).await?;
    let strategy = plan_apply(
        ApplyOperation::Delete,
        true,
        was_active,
        result.remaining_profiles,
        hot_reload_snapshot.is_some(),
    );
    let activation = match strategy {
        ApplyStrategy::NoServiceAction => Ok(()),
        ApplyStrategy::Stop => service::execute(service::ServiceAction::Stop),
        ApplyStrategy::HotReload => {
            let snapshot = hot_reload_snapshot.expect("hot reload strategy requires a snapshot");
            let mut expected = snapshot.listening_ports.clone();
            expected.remove(&result.profile.port);
            let removed = BTreeSet::from([result.profile.port]);
            service::hot_reload_and_verify(snapshot, &expected, &removed)
        }
        ApplyStrategy::Activate => service::activate_and_verify(),
    };
    if let Err(activation) = activation {
        let _rollback_timer = performance::stage("rollback_restore");
        let config_rollback = result.rollback_managed();
        let service_rollback = service::restore_snapshot(service_snapshot);
        return match (config_rollback, service_rollback) {
            (Ok(()), Ok(())) => {
                Err(activation.context("shoes 切换失败，配置删除和服务状态已回滚"))
            }
            (Err(config), Ok(())) => bail!(
                "shoes 切换失败，服务状态已恢复，但配置删除回滚失败：切换={activation:#}；配置={config:#}"
            ),
            (Ok(()), Err(service)) => bail!(
                "shoes 切换失败，配置删除已回滚，但服务状态恢复失败：切换={activation:#}；服务={service:#}"
            ),
            (Err(config), Err(service)) => bail!(
                "shoes 切换失败，配置删除与服务状态回滚均失败：切换={activation:#}；配置={config:#}；服务={service:#}"
            ),
        };
    }
    Ok(result.finish())
}

pub async fn update_chain_proxy(change: ChainProxyChange) -> Result<config::ManagedState> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let mut result = config::update_chain_proxy_locked(change, lock).await?;
    if result.configuration_changed && result.profiles_count > 0 {
        if let Err(activation) = service::activate_and_verify() {
            let _rollback_timer = performance::stage("rollback_restore");
            let config_rollback = result.rollback_managed();
            let service_rollback = service::restore_snapshot(service_snapshot);
            return match (config_rollback, service_rollback) {
                (Ok(()), Ok(())) => {
                    Err(activation.context("链式代理切换失败，配置和服务状态已回滚"))
                }
                (Err(config), Ok(())) => bail!(
                    "链式代理切换失败，服务状态已恢复，但配置回滚失败：切换={activation:#}；配置={config:#}"
                ),
                (Ok(()), Err(service)) => bail!(
                    "链式代理切换失败，配置已回滚，但服务状态恢复失败：切换={activation:#}；服务={service:#}"
                ),
                (Err(config), Err(service)) => bail!(
                    "链式代理切换失败，配置与服务状态回滚均失败：切换={activation:#}；配置={config:#}；服务={service:#}"
                ),
            };
        }
    }
    Ok(result.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_planner_preserves_start_stop_and_verified_reload_boundaries() {
        let plan = |operation, changed, active, remaining, observable| {
            plan_apply(operation, changed, active, remaining, observable)
        };
        assert_eq!(
            plan(ApplyOperation::AddOrEdit, false, true, 1, true),
            ApplyStrategy::NoServiceAction
        );
        assert_eq!(
            plan(ApplyOperation::AddOrEdit, true, true, 2, true),
            ApplyStrategy::HotReload
        );
        assert_eq!(
            plan(ApplyOperation::AddOrEdit, true, true, 2, false),
            ApplyStrategy::Activate
        );
        assert_eq!(
            plan(ApplyOperation::AddOrEdit, true, false, 1, false),
            ApplyStrategy::Activate
        );
        assert_eq!(
            plan(ApplyOperation::Delete, true, true, 0, true),
            ApplyStrategy::Stop
        );
        assert_eq!(
            plan(ApplyOperation::Delete, true, false, 1, false),
            ApplyStrategy::NoServiceAction
        );
    }
}
