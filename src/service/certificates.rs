//! Certificates: custom uploads, Let's Encrypt issuance with rate-limit
//! protection, reuse and expiry tracking.
use super::{Ctx, invalid, upstream};
use crate::{
    db::{CertificateMode, Issuance, Proxy, ProxyStatus},
    npm::{self, DnsChallenge, NpmCertificate, NpmClient},
    rules::{backoff, forward, marker},
};
use chrono::{DateTime, Utc};
use std::net::IpAddr;

pub struct CustomCertificate<'a> {
    pub certificate: &'a str,
    pub key: &'a str,
    pub intermediate: Option<&'a str>,
}

impl<'a> CustomCertificate<'a> {
    pub fn from_parts(
        certificate: Option<&'a str>,
        key: Option<&'a str>,
        intermediate: Option<&'a str>,
    ) -> Result<Option<Self>, anyhow::Error> {
        let certificate = certificate.map(str::trim).filter(|s| !s.is_empty());
        let key = key.map(str::trim).filter(|s| !s.is_empty());
        match (certificate, key) {
            (None, None) => Ok(None),
            (Some(certificate), Some(key)) => Ok(Some(Self {
                certificate,
                key,
                intermediate: intermediate.map(str::trim).filter(|s| !s.is_empty()),
            })),
            _ => Err(invalid("both the certificate and its private key are required")),
        }
    }
}

/// Uploads a custom certificate and attaches it to the proxy (the caller
/// pushes the host and saves). Returns a previously owned certificate that
/// is now unused and should be cleaned up.
pub async fn install_custom(
    ctx: &Ctx,
    client: &NpmClient,
    proxy: &mut Proxy,
    input: &CustomCertificate<'_>,
) -> Result<Option<i64>, anyhow::Error> {
    let certificate = client
        .create_custom_certificate(
            &marker::cert_nice_name(&ctx.instance_id, proxy.uuid),
            &proxy.domain,
            input.certificate,
            input.key,
            input.intermediate,
        )
        .await
        .map_err(|err| match err.downcast_ref::<npm::NpmError>() {
            Some(rejected) if rejected.status.is_client_error() => {
                invalid(format!("the certificate was rejected: {}", rejected.readable()))
            }
            _ => upstream(err),
        })?;

    let replaced = previously_owned(proxy);
    proxy.certificate_mode = CertificateMode::Custom;
    proxy.attach_certificate(certificate.id, true, certificate.expires_at());
    proxy.issue_attempts = 0;
    proxy.next_attempt = None;
    proxy.set_status(ProxyStatus::Live, None);
    Ok(replaced)
}

/// The owned certificate currently attached, for cleanup after replacing it.
pub fn previously_owned(proxy: &Proxy) -> Option<i64> {
    proxy
        .certificate_owned
        .then(|| proxy.certificate_id())
        .flatten()
}

/// An existing NPM certificate covering `domain` that stays valid beyond the
/// warning window.
async fn reusable(
    ctx: &Ctx,
    client: &NpmClient,
    domain: &str,
) -> Result<Option<NpmCertificate>, anyhow::Error> {
    let valid_until = Utc::now() + ctx.settings.warning_window();
    Ok(client
        .certificates()
        .await?
        .into_iter()
        .filter(|certificate| npm::covers_domain(&certificate.domain_names, domain))
        .filter(|certificate| certificate.expires_at().is_some_and(|at| at > valid_until))
        .max_by_key(|certificate| certificate.expires_at()))
}

/// DNS-01 via Cloudflare for managed domains when enabled.
async fn dns_challenge(ctx: &Ctx, proxy: &Proxy) -> Result<Option<DnsChallenge>, anyhow::Error> {
    let Some(domain_uuid) = proxy.managed_domain_uuid else {
        return Ok(None);
    };
    if !ctx.settings.managed_dns_challenge
        || !crate::sm::is_active(&ctx.state, ctx.settings.subdomain_manager_integration).await
    {
        return Ok(None);
    }

    match crate::sm::domain_by_uuid(ctx.db(), domain_uuid).await? {
        Some(domain) if domain.provider == "cloudflare" => Ok(Some(DnsChallenge::cloudflare(
            &domain.decrypt_credential(ctx.db()).await?,
            ctx.settings.dns_propagation_seconds,
        ))),
        _ => Ok(None),
    }
}

async fn lookup(host: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host((host, 80)).await {
        Ok(addresses) => {
            let mut ips: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Err(_) => Vec::new(),
    }
}

/// HTTP-01 preflight: the domain must resolve to one of the proxy targets.
async fn preflight(domain: &str, targets: &[String]) -> forward::PreflightCheck {
    let mut target_ips = Vec::new();
    for target in targets {
        match forward::target_as_ip(target) {
            Some(ip) => target_ips.push(ip),
            None => target_ips.extend(lookup(target).await),
        }
    }
    forward::compare_preflight(domain, &lookup(domain).await, &target_ips)
}

/// One issuance step for a proxy that needs a Let's Encrypt certificate.
/// Updates status, schedule and certificate on the proxy; the caller pushes
/// the host when a certificate got attached, and saves.
pub async fn issue(ctx: &Ctx, client: &NpmClient, proxy: &mut Proxy) -> Result<(), anyhow::Error> {
    let now = Utc::now();

    if ctx.settings.reuse_certificates
        && let Some(certificate) = reusable(ctx, client, &proxy.domain).await?
    {
        proxy.attach_certificate(certificate.id, false, certificate.expires_at());
        proxy.issue_attempts = 0;
        proxy.set_status(ProxyStatus::Live, None);
        return Ok(());
    }

    let (hour, week) = Issuance::windows(ctx.db(), &proxy.domain).await?;
    if let Some(at) = backoff::rate_limit_next_attempt(
        now,
        &hour,
        &week,
        ctx.settings.max_issuances_per_hour,
        ctx.settings.max_issuances_per_domain_per_week,
    ) {
        proxy.set_status(
            ProxyStatus::Issuing,
            Some(format!(
                "Waiting for the Let's Encrypt rate-limit window, next attempt at {}",
                at.format("%Y-%m-%d %H:%M UTC")
            )),
        );
        proxy.next_attempt = Some(at);
        return Ok(());
    }

    let dns = dns_challenge(ctx, proxy).await?;
    if dns.is_none()
        && ctx.settings.dns_preflight
        && !ctx.settings.proxy_targets.is_empty()
        && let forward::PreflightCheck::Fail(reason) =
            preflight(&proxy.domain, &ctx.settings.proxy_targets).await
    {
        proxy.set_status(ProxyStatus::PendingDns, Some(reason));
        proxy.next_attempt = Some(now + backoff::preflight_retry_interval(proxy.created, now));
        return Ok(());
    }

    let version = client.version().await?;
    let email = client.me().await?.email.unwrap_or_default();
    proxy.last_attempt = Some(now);

    match client
        .create_letsencrypt_certificate(
            &proxy.domain,
            npm::letsencrypt_meta(&version, &email, dns.as_ref()),
        )
        .await
    {
        Ok(certificate) => {
            Issuance::record(ctx.db(), &proxy.domain, true).await;
            proxy.attach_certificate(certificate.id, true, certificate.expires_at());
            proxy.issue_attempts = 0;
            proxy.set_status(ProxyStatus::Live, None);
        }
        Err(err) => {
            // an unreachable NPM never ran certbot; anything else may have
            // reached Let's Encrypt and counts against the quota
            let never_sent = err
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|err| err.is_connect());
            if never_sent {
                return Err(err);
            }

            Issuance::record(ctx.db(), &proxy.domain, false).await;
            proxy.issue_attempts += 1;
            proxy.set_status(ProxyStatus::Failed, Some(npm::readable_error(&err)));
            proxy.next_attempt =
                backoff::backoff_after_failure(proxy.issue_attempts).map(|delay| now + delay);
        }
    }

    Ok(())
}

pub enum ExpiryState {
    Valid,
    Expiring(DateTime<Utc>),
    Expired(DateTime<Utc>),
}

pub fn expiry_state(
    expires: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    warning: chrono::Duration,
) -> ExpiryState {
    match expires {
        Some(at) if at <= now => ExpiryState::Expired(at),
        Some(at) if at <= now + warning => ExpiryState::Expiring(at),
        _ => ExpiryState::Valid,
    }
}

const EXPIRY_PREFIX: &str = "The certificate expires on";

/// Updates a live/expired proxy's status from its certificate's expiry and
/// renews owned Let's Encrypt certificates NPM failed to renew in time.
pub async fn refresh_expiry(
    ctx: &Ctx,
    client: &NpmClient,
    proxy: &mut Proxy,
    certificate: &NpmCertificate,
) {
    let now = Utc::now();
    proxy.certificate_expires = certificate.expires_at();

    let state = expiry_state(proxy.certificate_expires, now, ctx.settings.warning_window());
    if !matches!(state, ExpiryState::Valid)
        && certificate.is_letsencrypt()
        && proxy.certificate_owned
        && ctx.settings.allow_letsencrypt
        && renew(ctx, client, proxy, certificate.id).await
    {
        proxy.set_status(ProxyStatus::Live, None);
        return;
    }

    match state {
        ExpiryState::Expired(at) => proxy.set_status(
            ProxyStatus::Failed,
            Some(format!(
                "The certificate expired on {}{}",
                at.format("%Y-%m-%d"),
                if proxy.certificate_mode == CertificateMode::Custom {
                    " - upload a new one"
                } else {
                    ""
                }
            )),
        ),
        ExpiryState::Expiring(at) if proxy.status == ProxyStatus::Live => proxy.status_message =
            Some(format!("{EXPIRY_PREFIX} {}", at.format("%Y-%m-%d"))),
        ExpiryState::Valid
            if proxy.status == ProxyStatus::Live
                && proxy
                    .status_message
                    .as_deref()
                    .is_some_and(|message| message.starts_with(EXPIRY_PREFIX)) =>
        {
            proxy.status_message = None
        }
        _ => {}
    }
}

/// Rate-limited renewal. Returns whether a fresh certificate is in place.
async fn renew(ctx: &Ctx, client: &NpmClient, proxy: &mut Proxy, id: i64) -> bool {
    let Ok((hour, week)) = Issuance::windows(ctx.db(), &proxy.domain).await else {
        return false;
    };
    if backoff::rate_limit_next_attempt(
        Utc::now(),
        &hour,
        &week,
        ctx.settings.max_issuances_per_hour,
        ctx.settings.max_issuances_per_domain_per_week,
    )
    .is_some()
    {
        return false;
    }

    match client.renew_certificate(id).await {
        Ok(certificate) => {
            Issuance::record(ctx.db(), &proxy.domain, true).await;
            proxy.certificate_expires = certificate.expires_at();
            matches!(
                expiry_state(proxy.certificate_expires, Utc::now(), ctx.settings.warning_window()),
                ExpiryState::Valid
            )
        }
        Err(err) => {
            Issuance::record(ctx.db(), &proxy.domain, false).await;
            tracing::warn!(proxy = %proxy.uuid, "certificate renewal failed: {err:?}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_states() {
        let now = Utc::now();
        let warning = chrono::Duration::days(14);
        assert!(matches!(expiry_state(None, now, warning), ExpiryState::Valid));
        assert!(matches!(
            expiry_state(Some(now + chrono::Duration::days(30)), now, warning),
            ExpiryState::Valid
        ));
        assert!(matches!(
            expiry_state(Some(now + chrono::Duration::days(3)), now, warning),
            ExpiryState::Expiring(_)
        ));
        assert!(matches!(
            expiry_state(Some(now - chrono::Duration::days(1)), now, warning),
            ExpiryState::Expired(_)
        ));
    }

    #[test]
    fn custom_certificate_parts() {
        assert!(CustomCertificate::from_parts(None, Some(" "), None).unwrap().is_none());
        assert!(CustomCertificate::from_parts(Some("c"), None, None).is_err());
        let parts = CustomCertificate::from_parts(Some(" c "), Some("k"), Some(""))
            .unwrap()
            .unwrap();
        assert_eq!(parts.certificate, "c");
        assert!(parts.intermediate.is_none());
    }
}
