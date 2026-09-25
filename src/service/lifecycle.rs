//! Proxy lifecycle: create, update, delete, retry and reactions to panel
//! events.
use super::{
    Ctx, certificates, hosts, invalid, is_rejection, managed, upstream,
    validate::{self, DomainRequest, FlagsInput},
    wake_worker,
};
use crate::db::{CertificateMode, CleanupJob, NewProxy, Proxy, ProxyFlags, ProxyStatus};
use chrono::Utc;
use shared::models::{server::Server, server_allocation::ServerAllocation};
use sqlx::types::Json;
use uuid::Uuid;

pub struct CreateInput<'a> {
    pub domain: DomainRequest<'a>,
    pub allocation_uuid: Uuid,
    pub forward_scheme: Option<&'a str>,
    pub flags: FlagsInput,
    pub certificate_mode: &'a str,
    pub custom_certificate: Option<certificates::CustomCertificate<'a>>,
    pub advanced_config: Option<&'a str>,
}

pub struct UpdateInput<'a> {
    pub allocation_uuid: Option<Uuid>,
    pub forward_scheme: Option<&'a str>,
    pub flags: FlagsInput,
    pub certificate_mode: Option<&'a str>,
    pub custom_certificate: Option<certificates::CustomCertificate<'a>>,
    pub advanced_config: Option<&'a str>,
}

async fn verify_allocation(
    ctx: &Ctx,
    server: &Server,
    allocation_uuid: Uuid,
) -> Result<(), anyhow::Error> {
    ServerAllocation::by_server_uuid_uuid(ctx.db(), server.uuid, allocation_uuid)
        .await?
        .map(|_| ())
        .ok_or_else(|| invalid("the allocation does not belong to this server"))
}

const ALLOCATION_REMOVED: &str = "The port this proxy pointed at was removed - choose a new one.";

pub async fn create(
    ctx: &Ctx,
    server: &Server,
    limit: i32,
    input: CreateInput<'_>,
) -> Result<Proxy, anyhow::Error> {
    let client = ctx.client()?;

    if Proxy::count_by_server_uuid(ctx.db(), server.uuid).await? >= i64::from(limit) {
        return Err(invalid(format!(
            "this server has reached its limit of {limit} reverse proxies"
        )));
    }
    verify_allocation(ctx, server, input.allocation_uuid).await?;

    let resolved = validate::resolve_domain(ctx, input.domain).await?;
    let forward_scheme = validate::scheme(input.forward_scheme)?;
    let certificate_mode = validate::certificate_mode(ctx, input.certificate_mode)?;
    if certificate_mode == CertificateMode::Custom && input.custom_certificate.is_none() {
        return Err(invalid("upload a certificate and its private key"));
    }
    let advanced_config = validate::advanced_config(ctx, input.advanced_config)?.unwrap_or_default();

    let mut proxy = Proxy::insert(
        ctx.db(),
        NewProxy {
            server_uuid: server.uuid,
            allocation_uuid: input.allocation_uuid,
            domain: &resolved.fqdn,
            managed_domain_uuid: resolved.managed.as_ref().map(|(domain, _)| domain.uuid),
            managed_name: resolved.managed.as_ref().map(|(_, name)| name.as_str()),
            forward_scheme: &forward_scheme,
            flags: input.flags.apply(ProxyFlags::from(&ctx.settings.defaults)),
            advanced_config: &advanced_config,
            certificate_mode,
        },
    )
    .await
    .map_err(|err| match &err {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            super::conflict("this domain is already used by another proxy")
        }
        _ => err.into(),
    })?;

    let provisioned = async {
        if let Some((domain, _)) = &resolved.managed {
            proxy.managed_dns_records = Json(managed::create_records(ctx, domain, &proxy.domain).await?);
            proxy.save(ctx.db()).await?;
        }

        match &input.custom_certificate {
            Some(custom) if certificate_mode == CertificateMode::Custom => {
                certificates::install_custom(ctx, &client, &mut proxy, custom).await?;
                hosts::push(ctx, &client, &mut proxy).await.map_err(upstream)?;
            }
            _ => {
                match hosts::push(ctx, &client, &mut proxy).await {
                    Ok(_) => proxy.schedule_now(ProxyStatus::Issuing, None),
                    Err(err) if is_rejection(&err) => return Err(upstream(err)),
                    // the proxy manager is unreachable - the worker retries
                    Err(err) => proxy.schedule_now(
                        ProxyStatus::Issuing,
                        Some(format!(
                            "Waiting for the proxy manager: {}",
                            crate::npm::readable_error(&err)
                        )),
                    ),
                }
                wake_worker();
            }
        }

        proxy.save(ctx.db()).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    if let Err(err) = provisioned {
        hosts::remove_remote(ctx, &proxy).await;
        if let Err(delete) = proxy.delete(ctx.db()).await {
            tracing::error!(proxy = %proxy.uuid, "failed to roll back proxy: {delete:?}");
        }
        return Err(err);
    }

    Ok(proxy)
}

/// Applies an update. Returns the proxy and a warning when the change could
/// not reach the proxy manager yet.
pub async fn update(
    ctx: &Ctx,
    server: &Server,
    mut proxy: Proxy,
    input: UpdateInput<'_>,
) -> Result<(Proxy, Option<String>), anyhow::Error> {
    let client = ctx.client()?;

    if let Some(allocation_uuid) = input.allocation_uuid {
        verify_allocation(ctx, server, allocation_uuid).await?;
        proxy.allocation_uuid = Some(allocation_uuid);
    }
    if input.forward_scheme.is_some() {
        proxy.forward_scheme = validate::scheme(input.forward_scheme)?;
    }
    proxy.flags = input.flags.apply(proxy.flags);
    if let Some(config) = validate::advanced_config(ctx, input.advanced_config)? {
        proxy.advanced_config = config;
    }

    let requested_mode = input
        .certificate_mode
        .map(|mode| validate::certificate_mode(ctx, mode))
        .transpose()?;

    let lost_port = proxy.status_message.as_deref() == Some(ALLOCATION_REMOVED);
    if lost_port && input.allocation_uuid.is_none() {
        return Err(invalid("choose a new port for this proxy"));
    }

    // certificate changes: (replaced owned certificate, freshly uploaded one)
    let mut replaced = None;
    let mut uploaded = None;
    let mut switched_to_letsencrypt = false;
    match (requested_mode.unwrap_or(proxy.certificate_mode), &input.custom_certificate) {
        (CertificateMode::Custom, Some(custom)) => {
            if !ctx.settings.allow_custom_certificates {
                return Err(invalid("uploading certificates is disabled"));
            }
            replaced = certificates::install_custom(ctx, &client, &mut proxy, custom).await?;
            uploaded = proxy.certificate_id();
        }
        (CertificateMode::Custom, None) if proxy.certificate_mode != CertificateMode::Custom => {
            return Err(invalid("upload a certificate and its private key"));
        }
        (CertificateMode::Letsencrypt, _) if proxy.certificate_mode != CertificateMode::Letsencrypt => {
            replaced = certificates::previously_owned(&proxy);
            proxy.detach_certificate();
            proxy.certificate_mode = CertificateMode::Letsencrypt;
            proxy.issue_attempts = 0;
            switched_to_letsencrypt = true;
        }
        _ => {}
    }

    // a proxy that got its port back is live again when it has a
    // certificate, otherwise it goes back to the worker - as does one that
    // just switched to Let's Encrypt. Plain edits keep the retry schedule.
    if lost_port && proxy.certificate_id().is_some() {
        proxy.set_status(ProxyStatus::Live, None);
    } else if (lost_port || switched_to_letsencrypt) && proxy.certificate_id().is_none() {
        proxy.schedule_now(ProxyStatus::Issuing, None);
        wake_worker();
    }

    let mut warning = None;
    match hosts::push(ctx, &client, &mut proxy).await {
        Ok(_) => {}
        Err(err) if is_rejection(&err) => {
            if let Some(id) = uploaded {
                hosts::execute_or_queue(ctx, Some(&client), CleanupJob::Certificate { id }).await;
            }
            return Err(upstream(err));
        }
        Err(err) => {
            warning = Some(format!(
                "Saved, but the proxy manager could not be reached ({}). The change is applied on the next sync.",
                crate::npm::readable_error(&err)
            ));
        }
    }

    proxy.save(ctx.db()).await?;

    if let Some(id) = replaced {
        hosts::execute_or_queue(ctx, Some(&client), CleanupJob::Certificate { id }).await;
    }

    Ok((proxy, warning))
}

pub async fn delete(ctx: &Ctx, proxy: &Proxy) -> Result<(), anyhow::Error> {
    hosts::remove_remote(ctx, proxy).await;
    proxy.delete(ctx.db()).await?;
    Ok(())
}

/// Minimum time between user triggered retries.
pub const RETRY_COOLDOWN_MINUTES: i64 = 10;

pub async fn retry(ctx: &Ctx, mut proxy: Proxy, enforce_cooldown: bool) -> Result<Proxy, anyhow::Error> {
    if proxy.status == ProxyStatus::Live {
        return Err(invalid("this proxy is already live"));
    }
    if proxy.allocation_uuid.is_none() {
        return Err(invalid("choose a port for this proxy first"));
    }
    if enforce_cooldown
        && let Some(last) = proxy.last_attempt
    {
        let wait = last + chrono::Duration::minutes(RETRY_COOLDOWN_MINUTES) - Utc::now();
        if wait > chrono::Duration::zero() {
            return Err(invalid(format!(
                "please wait {} more minute(s) before retrying",
                wait.num_minutes() + 1
            )));
        }
    }

    proxy.issue_attempts = 0;
    proxy.schedule_now(ProxyStatus::Issuing, None);
    proxy.save(ctx.db()).await?;
    wake_worker();
    Ok(proxy)
}

// --- panel events ---

pub async fn on_server_deleted(ctx: &Ctx, server_uuid: Uuid) -> Result<(), anyhow::Error> {
    for proxy in Proxy::all_by_server_uuid(ctx.db(), server_uuid).await? {
        hosts::remove_remote(ctx, &proxy).await;
    }
    Ok(())
}

pub async fn on_allocation_deleted(ctx: &Ctx, allocation_uuid: Uuid) -> Result<(), anyhow::Error> {
    let client = ctx.client().ok();
    for mut proxy in Proxy::all_by_allocation_uuid(ctx.db(), allocation_uuid).await? {
        proxy.allocation_uuid = None;
        proxy.next_attempt = None;
        proxy.set_status(ProxyStatus::Failed, Some(ALLOCATION_REMOVED.to_string()));
        if let Some(client) = &client
            && let Err(err) = hosts::push(ctx, client, &mut proxy).await
        {
            tracing::warn!(proxy = %proxy.uuid, "failed to disable proxy host: {err:?}");
        }
        proxy.save(ctx.db()).await?;
    }
    Ok(())
}

pub async fn on_server_transferred(ctx: &Ctx, server_uuid: Uuid) -> Result<(), anyhow::Error> {
    let client = ctx.client()?;
    for mut proxy in Proxy::all_by_server_uuid(ctx.db(), server_uuid).await? {
        if proxy.allocation_uuid.is_none() {
            continue;
        }
        match hosts::push(ctx, &client, &mut proxy).await {
            Ok(_) => proxy.save_state(ctx.db()).await?,
            Err(err) => {
                tracing::warn!(proxy = %proxy.uuid, "failed to update forward target after transfer: {err:?}")
            }
        }
    }
    Ok(())
}
