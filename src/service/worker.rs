//! The issuance worker: processes due proxies one at a time (certbot can't
//! run concurrently) and drains the remote cleanup queue.
use super::{Ctx, certificates, hosts, wait_for_work};
use crate::{
    db::{CertificateMode, CleanupTask, Proxy, ProxyStatus},
    npm::{NpmClient, readable_error},
};
use chrono::Utc;
use std::time::Duration;

/// Retry delay after the proxy manager was unreachable or rejected a push.
const PUSH_RETRY: chrono::Duration = chrono::Duration::minutes(5);

pub async fn run(state: &shared::State) -> Result<(), anyhow::Error> {
    let result = pass(state).await;
    wait_for_work(Duration::from_secs(15)).await;
    result
}

async fn pass(state: &shared::State) -> Result<(), anyhow::Error> {
    let ctx = Ctx::load(state).await?;
    let client = ctx.client().ok();

    if let Some(client) = &client {
        for due in Proxy::due(ctx.db()).await? {
            process(&ctx, client, due.uuid).await;
        }
    }
    drain_cleanup(&ctx, client.as_ref()).await;
    Ok(())
}

async fn process(ctx: &Ctx, client: &NpmClient, uuid: uuid::Uuid) {
    // re-read: a route may have changed or deleted the proxy meanwhile
    let mut proxy = match Proxy::by_uuid(ctx.db(), uuid).await {
        Ok(Some(proxy)) if proxy.next_attempt.is_some_and(|at| at <= Utc::now()) => proxy,
        Ok(_) => return,
        Err(err) => {
            tracing::warn!(proxy = %uuid, "failed to load proxy: {err:?}");
            return;
        }
    };
    proxy.next_attempt = None;

    if let Err(err) = step(ctx, client, &mut proxy).await {
        proxy.set_status(ProxyStatus::Failed, Some(readable_error(&err)));
        proxy.next_attempt = Some(Utc::now() + PUSH_RETRY);
    }

    if let Err(err) = proxy.save_state(ctx.db()).await {
        tracing::error!(proxy = %uuid, "failed to save proxy: {err:?}");
    }
}

async fn step(ctx: &Ctx, client: &NpmClient, proxy: &mut Proxy) -> Result<(), anyhow::Error> {
    if proxy.allocation_uuid.is_none() {
        hosts::push(ctx, client, proxy).await?;
        return Ok(());
    }

    let mut host = hosts::push(ctx, client, proxy).await?;

    if proxy.certificate_id().is_none() {
        match proxy.certificate_mode {
            CertificateMode::Letsencrypt if ctx.settings.allow_letsencrypt => {
                certificates::issue(ctx, client, proxy).await?;
                if proxy.certificate_id().is_some() {
                    // issuance can take minutes - push the latest settings
                    if !proxy.reload_config(ctx.db()).await? {
                        return Ok(());
                    }
                    host = hosts::push(ctx, client, proxy).await?;
                }
            }
            CertificateMode::Letsencrypt => proxy.set_status(
                ProxyStatus::Failed,
                Some("Let's Encrypt certificates are disabled - upload your own certificate.".into()),
            ),
            CertificateMode::Custom => proxy.set_status(
                ProxyStatus::Failed,
                Some("The certificate is missing - upload a new one.".into()),
            ),
        }
    } else {
        proxy.set_status(ProxyStatus::Live, None);
    }

    if proxy.status == ProxyStatus::Live
        && let Some(reason) = host.as_ref().and_then(|host| host.nginx_error())
    {
        proxy.set_status(ProxyStatus::Failed, Some(reason));
        proxy.next_attempt = Some(Utc::now() + PUSH_RETRY);
    }

    Ok(())
}

pub async fn drain_cleanup(ctx: &Ctx, client: Option<&NpmClient>) {
    let tasks = match CleanupTask::pending(ctx.db()).await {
        Ok(tasks) => tasks,
        Err(err) => {
            tracing::warn!("failed to load cleanup tasks: {err:?}");
            return;
        }
    };

    for task in tasks {
        let result = match task.job() {
            Some(job) => hosts::execute(ctx, client, &job).await,
            None => Err(anyhow::anyhow!("unreadable cleanup task")),
        };
        let saved = match result {
            Ok(()) => task.delete(ctx.db()).await,
            Err(err) => task.fail(ctx.db(), &readable_error(&err)).await,
        };
        if let Err(err) = saved {
            tracing::warn!(task = %task.uuid, "failed to update cleanup task: {err:?}");
        }
    }
}
