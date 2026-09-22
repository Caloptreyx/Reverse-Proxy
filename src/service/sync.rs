//! The periodic sync: reconcile (fixing when enabled), certificate expiry
//! tracking/renewal and nginx health.
use super::{Ctx, certificates, reconcile};
use crate::db::{Issuance, Proxy, ProxyStatus};
use chrono::Utc;
use std::{collections::HashMap, time::Duration};

pub async fn run(state: &shared::State) -> Result<(), anyhow::Error> {
    let ctx = Ctx::load(state).await?;
    let interval = ctx.settings.sync_interval();

    let result = if ctx.settings.sync_enabled && ctx.is_configured() {
        pass(&ctx).await
    } else {
        Ok(())
    };

    tokio::time::sleep(if ctx.settings.sync_enabled {
        interval
    } else {
        Duration::from_secs(60)
    })
    .await;
    result
}

pub async fn pass(ctx: &Ctx) -> Result<(), anyhow::Error> {
    let client = ctx.client()?;
    let snapshot = reconcile::snapshot(ctx, &client).await?;

    if ctx.settings.auto_reconcile {
        for item in &snapshot.items {
            if let Err(err) = reconcile::fix(ctx, &client, &item.id).await {
                tracing::warn!(item = %item.id, "automatic reconcile failed: {err:?}");
            }
        }
    }

    let certificates: HashMap<i64, _> = snapshot
        .certificates
        .iter()
        .map(|certificate| (certificate.id, certificate))
        .collect();
    let hosts: HashMap<i64, _> = snapshot.hosts.iter().map(|host| (host.id, host)).collect();

    for mut proxy in Proxy::all(ctx.db()).await? {
        if let Some(certificate) = proxy.certificate_id().and_then(|id| certificates.get(&id)) {
            certificates::refresh_expiry(ctx, &client, &mut proxy, certificate).await;
        }

        if proxy.status == ProxyStatus::Live
            && let Some(reason) = proxy
                .host_id()
                .and_then(|id| hosts.get(&id))
                .and_then(|host| host.nginx_error())
        {
            proxy.set_status(ProxyStatus::Failed, Some(reason));
            proxy.next_attempt = Some(Utc::now() + chrono::Duration::minutes(5));
        }

        proxy.last_synced = Some(Utc::now());
        if let Err(err) = proxy.save_state(ctx.db()).await {
            tracing::warn!(proxy = %proxy.uuid, "failed to save proxy during sync: {err:?}");
        }
    }

    Issuance::prune(ctx.db()).await?;
    Ok(())
}
