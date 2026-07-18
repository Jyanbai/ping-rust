use std::path::Path;

use anyhow::{bail, Result};

use crate::{
    config::{self, GenerationRequest, GenerationResult, ProfileChange},
    service, utils,
};
use uuid::Uuid;

pub async fn generate_and_activate(request: GenerationRequest) -> Result<GenerationResult> {
    utils::require_linux_root()?;
    let lock = utils::exclusive_lock(Path::new(utils::LOCK_FILE))?;
    let service_snapshot = service::capture_snapshot()?;
    let mut result = config::generate_locked(request, lock).await?;
    if let Err(activation) = service::activate_and_verify() {
        let config_rollback = result.rollback_managed();
        let service_rollback = service::restore_snapshot(service_snapshot);
        return match (config_rollback, service_rollback) {
            (Ok(()), Ok(())) => {
                Err(activation.context("shoes 激活失败，配置和服务状态已回滚"))
            }
            (Err(config), Ok(())) => bail!(
                "shoes 激活失败，服务状态已恢复，但配置回滚失败：激活={activation:#}；配置={config:#}"
            ),
            (Ok(()), Err(service)) => bail!(
                "shoes 激活失败，配置已回滚，但服务状态恢复失败：激活={activation:#}；服务={service:#}"
            ),
            (Err(config), Err(service)) => bail!(
                "shoes 激活失败，配置与服务状态回滚均失败：激活={activation:#}；配置={config:#}；服务={service:#}"
            ),
        };
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
