//! NPM proxy host ownership, pushes and remote removal.
use super::{Ctx, target};
use crate::{
    db::{CleanupJob, CleanupTask, Proxy},
    npm::{HostPayload, NpmClient, NpmProxyHost},
    rules::{marker, nginx},
};

/// The desired NPM host for a proxy. TLS-only options stay off until a
/// certificate is attached.
pub fn desired(ctx: &Ctx, proxy: &Proxy, target: &target::Target) -> HostPayload {
    let certificate_id = proxy.certificate_id().unwrap_or(0);
    let tls = certificate_id > 0;
    let flags = &proxy.flags;
    let custom = if ctx.settings.allow_custom_nginx {
        proxy.advanced_config.as_str()
    } else {
        ""
    };

    HostPayload {
        domain_names: vec![proxy.domain.clone()],
        forward_scheme: proxy.forward_scheme.clone(),
        forward_host: target.host.clone(),
        forward_port: target.port,
        certificate_id,
        ssl_forced: tls && flags.force_https,
        caching_enabled: flags.caching,
        block_exploits: flags.block_exploits,
        allow_websocket_upgrade: flags.websockets,
        http2_support: tls && flags.http2,
        hsts_enabled: tls && flags.hsts,
        hsts_subdomains: tls && flags.hsts && flags.hsts_subdomains,
        access_list_id: 0,
        advanced_config: nginx::compose_advanced_config(&ctx.marker(proxy.uuid), custom),
    }
}

/// The proxy's NPM host - only if the link is intact and the host still
/// carries this proxy's ownership marker.
pub async fn owned(
    ctx: &Ctx,
    client: &NpmClient,
    proxy: &Proxy,
) -> Result<Option<NpmProxyHost>, anyhow::Error> {
    let Some(id) = proxy.host_id() else {
        return Ok(None);
    };
    Ok(client
        .proxy_host(id)
        .await?
        .filter(|host| marker::marker_matches(&host.advanced_config, &ctx.instance_id, proxy.uuid)))
}

/// Brings the proxy's NPM host in line with the panel: creates it when
/// missing, updates drifted fields, disables it while the proxy has no
/// allocation. Updates `npm_proxy_host_id`; the caller saves the proxy.
pub async fn push(
    ctx: &Ctx,
    client: &NpmClient,
    proxy: &mut Proxy,
) -> Result<Option<NpmProxyHost>, anyhow::Error> {
    let existing = owned(ctx, client, proxy).await?;

    let Some(allocation_uuid) = proxy.allocation_uuid else {
        if let Some(host) = &existing
            && host.enabled
        {
            client.set_proxy_host_enabled(host.id, false).await?;
        }
        return Ok(existing);
    };

    let target = target::resolve(ctx, proxy.server_uuid, allocation_uuid).await?;
    let desired = desired(ctx, proxy, &target);

    let host = match existing {
        None => {
            let host = client.create_proxy_host(&desired).await?;
            proxy.npm_proxy_host_id = i32::try_from(host.id).ok();
            host
        }
        Some(host) => {
            let drift = desired.drift(&host);
            let mut host = if drift.iter().any(|field| *field != "enabled") {
                client.update_proxy_host(host.id, &desired).await?
            } else {
                host
            };
            if !host.enabled {
                client.set_proxy_host_enabled(host.id, true).await?;
                host.enabled = true;
            }
            host
        }
    };

    Ok(Some(host))
}

/// Runs a remote cleanup job. Idempotent: resources that are already gone
/// count as done, resources we can't prove we own are left alone.
pub async fn execute(
    ctx: &Ctx,
    client: Option<&NpmClient>,
    job: &CleanupJob,
) -> Result<(), anyhow::Error> {
    let npm = || client.ok_or_else(|| anyhow::anyhow!("the proxy manager is not configured"));

    match job {
        CleanupJob::ProxyHost { id, proxy_uuid } => {
            let client = npm()?;
            if let Some(host) = client.proxy_host(*id).await?
                && marker::marker_matches(&host.advanced_config, &ctx.instance_id, *proxy_uuid)
            {
                client.delete_proxy_host(*id).await?;
            }
        }
        CleanupJob::Certificate { id } => {
            let client = npm()?;
            if let Some(hosts) = client.certificate_usage().await?.get(id)
                && !hosts.is_empty()
            {
                anyhow::bail!("certificate {id} is still used by proxy host(s) {hosts:?}");
            }
            client.delete_certificate(*id).await?;
        }
        CleanupJob::DnsRecord {
            managed_domain_uuid,
            record,
        } => {
            let domain = crate::sm::domain_by_uuid(ctx.db(), *managed_domain_uuid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("the managed domain no longer exists"))?;
            domain
                .provider_client(ctx.db())
                .await?
                .delete_record(&record.id)
                .await?;
        }
    }

    Ok(())
}

/// Runs a cleanup job now, queueing it for the worker when it fails.
pub async fn execute_or_queue(ctx: &Ctx, client: Option<&NpmClient>, job: CleanupJob) {
    if let Err(err) = execute(ctx, client, &job).await {
        tracing::warn!(?job, "remote cleanup failed, queued for retry: {err:?}");
        CleanupTask::queue(ctx.db(), &job, &crate::npm::readable_error(&err)).await;
    }
}

/// Removes everything remote that belongs to a proxy: host first (so the
/// certificate is no longer in use), then an owned certificate, then managed
/// DNS records.
pub async fn remove_remote(ctx: &Ctx, proxy: &Proxy) {
    let client = ctx.client().ok();

    if let Some(id) = proxy.host_id() {
        execute_or_queue(
            ctx,
            client.as_ref(),
            CleanupJob::ProxyHost {
                id,
                proxy_uuid: proxy.uuid,
            },
        )
        .await;
    }

    if proxy.certificate_owned
        && let Some(id) = proxy.certificate_id()
    {
        execute_or_queue(ctx, client.as_ref(), CleanupJob::Certificate { id }).await;
    }

    if let Some(managed_domain_uuid) = proxy.managed_domain_uuid {
        for record in proxy.managed_dns_records.iter() {
            execute_or_queue(
                ctx,
                client.as_ref(),
                CleanupJob::DnsRecord {
                    managed_domain_uuid,
                    record: record.clone(),
                },
            )
            .await;
        }
    }
}
