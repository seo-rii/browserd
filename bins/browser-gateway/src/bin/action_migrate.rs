//! Explicit offline migration of a gateway action namespace. Never run by gateway startup.

use std::time::Duration;

use anyhow::{Context, bail};
use browser_gateway::action_retention_limits_from_lookup;
use browserd_coordination::{RedisGatewayActionConfig, RedisGatewayActionStore, StoreConfig};
use chrono::Utc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args != ["--confirm-gateway-writers-stopped"] {
        bail!(
            "usage: action_migrate --confirm-gateway-writers-stopped; stop all gateway writers first"
        );
    }
    let retention_limits = action_retention_limits_from_lookup(|name| std::env::var(name).ok())?;
    let endpoint = std::env::var("BROWSERD_REDIS_URL")
        .context("BROWSERD_REDIS_URL must be set for the offline migration")?;
    let prefix = std::env::var("BROWSERD_REDIS_PREFIX")
        .context("BROWSERD_REDIS_PREFIX must be set for the offline migration")?;
    let mut config = RedisGatewayActionConfig::new(
        endpoint,
        prefix,
        StoreConfig::default(),
        1,
        Duration::from_secs(5),
    )
    .context("invalid Redis action migration configuration")?
    .with_retention_limits(retention_limits);
    if let Some(path) = std::env::var_os("BROWSERD_FLEET_GATEWAY_CONFIG_FILE") {
        let fleet = browser_gateway::GatewayFleetConfig::load(&std::path::PathBuf::from(path))?;
        config = config.with_fleet_admission(fleet.admission().clone());
    }
    loop {
        let progress = RedisGatewayActionStore::migrate_recovery_format(
            config.clone(),
            true,
            Utc::now(),
        )
        .await
        .context("offline action migration failed; retain the namespace and resume with the same command")?;
        if progress.complete() {
            println!(
                "action format v5 migration complete; pending actions indexed: {}; retained actions backfilled: {}",
                progress.migrated_actions(),
                progress.retention_backfilled_actions()
            );
            return Ok(());
        }
    }
}
