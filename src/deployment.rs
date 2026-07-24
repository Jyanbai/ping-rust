use std::{error::Error, fmt, path::Path};

use anyhow::{bail, Result};

use crate::{
    chain_proxy::ChainProxyChange,
    config::{self, GenerationRequest, GenerationResult, ProfileChange},
    service, utils,
};
use uuid::Uuid;

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
    let mut result = config::generate_locked(request, lock).await?;
    if let Err(activation) = service::activate_and_verify() {
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
    let mut result = config::update_profile_locked(id, change, lock).await?;
    if let Err(activation) = service::activate_and_verify() {
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
    Ok(result)
}

pub async fn delete_and_activate(id: Uuid) -> Result<config::ManagedProfile> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let was_active = Path::new(utils::SERVICE_FILE).exists() && service::is_active()?;
    let mut result = config::delete_profile_locked(id, lock).await?;
    let activation = if !was_active {
        Ok(())
    } else if result.remaining_profiles == 0 {
        service::execute(service::ServiceAction::Stop)
    } else {
        service::activate_and_verify()
    };
    if let Err(activation) = activation {
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
