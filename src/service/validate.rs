//! Request validation that needs settings or the database.
use super::{Ctx, conflict, invalid};
use crate::{
    db::{CertificateMode, Proxy, ProxyFlags},
    rules::{domain, nginx},
    settings::ProxyDefaults,
    sm,
};
use uuid::Uuid;

pub enum DomainRequest<'a> {
    Custom { domain: &'a str },
    Managed { domain_uuid: Uuid, name: &'a str },
}

pub struct ResolvedDomain {
    pub fqdn: String,
    pub managed: Option<(sm::SmDomain, String)>,
}

pub async fn resolve_domain(
    ctx: &Ctx,
    request: DomainRequest<'_>,
) -> Result<ResolvedDomain, anyhow::Error> {
    let settings = &ctx.settings;
    let integration = sm::is_active(&ctx.state).await;

    let resolved = match request {
        DomainRequest::Custom { domain } => {
            let fqdn = domain::validate_domain(domain).map_err(invalid)?;
            domain::domain_allowed(&fqdn, &settings.allowed_suffixes, &settings.blocked())
                .map_err(invalid)?;

            if integration && sm::domain_shadowed(ctx.db(), &fqdn).await? {
                return Err(invalid(
                    "this domain is managed by the panel - choose it as a managed subdomain instead",
                ));
            }
            if let Some(panel_host) = panel_host(ctx).await
                && domain::is_under(&fqdn, &panel_host)
            {
                return Err(invalid("this domain belongs to the panel itself"));
            }

            ResolvedDomain {
                fqdn,
                managed: None,
            }
        }
        DomainRequest::Managed { domain_uuid, name } => {
            if !integration {
                return Err(invalid("managed subdomains are not available"));
            }
            let managed = sm::domain_by_uuid(ctx.db(), domain_uuid)
                .await?
                .filter(|domain| domain.enabled)
                .ok_or_else(|| invalid("the selected domain does not exist"))?;

            let name = name.trim().to_lowercase();
            if !domain::LABEL_REGEX.is_match(&name) {
                return Err(invalid(
                    "the name may only contain lowercase letters, numbers and dashes and may not start or end with a dash",
                ));
            }
            if sm::blacklist(ctx.db())
                .await
                .iter()
                .any(|pattern| pattern.is_match(&name))
            {
                return Err(invalid("this name is reserved"));
            }
            if sm::subdomain_taken(ctx.db(), domain_uuid, &name).await? {
                return Err(conflict("this name is already used by a subdomain"));
            }

            ResolvedDomain {
                fqdn: format!("{name}.{}", managed.domain),
                managed: Some((managed, name)),
            }
        }
    };

    if Proxy::domain_taken(ctx.db(), &resolved.fqdn).await? {
        return Err(conflict("this domain is already used by another proxy"));
    }

    Ok(resolved)
}

async fn panel_host(ctx: &Ctx) -> Option<String> {
    let settings = ctx.state.settings.get().await.ok()?;
    reqwest::Url::parse(&settings.app.url)
        .ok()?
        .host_str()
        .map(str::to_lowercase)
}

pub fn scheme(value: Option<&str>) -> Result<String, anyhow::Error> {
    let scheme = value.unwrap_or("http").to_lowercase();
    match scheme.as_str() {
        "http" | "https" => Ok(scheme),
        _ => Err(invalid("the forward scheme must be `http` or `https`")),
    }
}

pub fn certificate_mode(ctx: &Ctx, value: &str) -> Result<CertificateMode, anyhow::Error> {
    match CertificateMode::parse(value) {
        Some(CertificateMode::Letsencrypt) if !ctx.settings.allow_letsencrypt => Err(invalid(
            "let's encrypt certificates are disabled - upload your own certificate",
        )),
        Some(CertificateMode::Custom) if !ctx.settings.allow_custom_certificates => {
            Err(invalid("uploading certificates is disabled"))
        }
        Some(mode) => Ok(mode),
        None => Err(invalid("the certificate mode must be `letsencrypt` or `custom`")),
    }
}

pub fn advanced_config(ctx: &Ctx, value: Option<&str>) -> Result<Option<String>, anyhow::Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !ctx.settings.allow_custom_nginx {
        return if value.trim().is_empty() {
            Ok(Some(String::new()))
        } else {
            Err(invalid("custom nginx configuration is disabled"))
        };
    }
    nginx::validate(value).map(Some).map_err(invalid)
}

/// Optional flag overrides from a request.
#[derive(Default, serde::Deserialize, utoipa::ToSchema)]
pub struct FlagsInput {
    pub websockets: Option<bool>,
    pub caching: Option<bool>,
    pub http2: Option<bool>,
    pub hsts: Option<bool>,
    pub hsts_subdomains: Option<bool>,
    pub force_https: Option<bool>,
    pub block_exploits: Option<bool>,
}

impl FlagsInput {
    pub fn apply(&self, base: ProxyFlags) -> ProxyFlags {
        ProxyFlags {
            websockets: self.websockets.unwrap_or(base.websockets),
            caching: self.caching.unwrap_or(base.caching),
            http2: self.http2.unwrap_or(base.http2),
            hsts: self.hsts.unwrap_or(base.hsts),
            hsts_subdomains: self.hsts_subdomains.unwrap_or(base.hsts_subdomains),
            force_https: self.force_https.unwrap_or(base.force_https),
            block_exploits: self.block_exploits.unwrap_or(base.block_exploits),
        }
    }
}

impl From<&ProxyDefaults> for ProxyFlags {
    fn from(defaults: &ProxyDefaults) -> Self {
        Self {
            websockets: defaults.websockets,
            caching: false,
            http2: defaults.http2,
            hsts: false,
            hsts_subdomains: false,
            force_https: true,
            block_exploits: defaults.block_exploits,
        }
    }
}
