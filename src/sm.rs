//! Runtime-only integration with the Subdomain Manager extension
//! (`dev.caloptreyx.subdomains`) - reads its tables directly when installed,
//! no crate dependency.
use shared::{State, database::Database};
use uuid::Uuid;

pub const SM_PACKAGE_NAME: &str = "dev.caloptreyx.subdomains";
const SM_BLACKLIST_KEY: &str = "dev.caloptreyx.subdomains::blacklist";
const DOMAINS_TABLE: &str = "dev_caloptreyx_subdomains_domains";

/// A Subdomain Manager DNS domain, as stored by that extension.
#[derive(sqlx::FromRow, Clone)]
pub struct SmDomain {
    pub uuid: Uuid,
    pub domain: String,
    pub provider: String,
    pub zone_id: String,
    /// Encrypted provider credential - decrypt via `database.decrypt_base64`.
    pub credential: String,
    pub enabled: bool,
}

impl SmDomain {
    /// Decrypts the stored credential and builds a DNS provider client.
    pub async fn provider_client(
        &self,
        database: &Database,
    ) -> Result<Box<dyn crate::dns::DnsProvider>, anyhow::Error> {
        let credential = database.decrypt_base64(&self.credential).await?;
        crate::dns::build(&self.provider, &self.zone_id, &credential)
    }

    /// The decrypted provider credential (for DNS-01 challenge credentials).
    pub async fn decrypt_credential(&self, database: &Database) -> Result<String, anyhow::Error> {
        Ok(database.decrypt_base64(&self.credential).await?.to_string())
    }
}

/// Whether the integration is usable: the setting is on, SM is loaded and not
/// disabled, and its table exists (e.g. SM uninstalled but proxies remain).
pub async fn is_active(state: &State, setting_enabled: bool) -> bool {
    if !setting_enabled {
        return false;
    }

    let loaded = {
        let extensions = state.extensions.extensions().await;
        extensions
            .iter()
            .any(|ext| ext.package_name == SM_PACKAGE_NAME)
    };
    if !loaded || state.extensions.is_disabled(SM_PACKAGE_NAME) {
        return false;
    }

    table_exists(&state.database, DOMAINS_TABLE).await
}

async fn table_exists(database: &Database, table: &str) -> bool {
    sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass($1)::text")
        .bind(table)
        .fetch_one(database.read())
        .await
        .ok()
        .flatten()
        .is_some()
}

/// All enabled SM domains.
pub async fn enabled_domains(database: &Database) -> Result<Vec<SmDomain>, sqlx::Error> {
    sqlx::query_as::<_, SmDomain>(
        "SELECT uuid, domain, provider, zone_id, credential, enabled
         FROM dev_caloptreyx_subdomains_domains WHERE enabled",
    )
    .fetch_all(database.read())
    .await
}

pub async fn domain_by_uuid(
    database: &Database,
    uuid: Uuid,
) -> Result<Option<SmDomain>, sqlx::Error> {
    sqlx::query_as::<_, SmDomain>(
        "SELECT uuid, domain, provider, zone_id, credential, enabled
         FROM dev_caloptreyx_subdomains_domains WHERE uuid = $1",
    )
    .bind(uuid)
    .fetch_optional(database.read())
    .await
}

/// Whether SM already has a subdomain `(domain_uuid, name)` registered.
pub async fn subdomain_taken(
    database: &Database,
    domain_uuid: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM dev_caloptreyx_subdomains_subdomains
         WHERE domain_uuid = $1 AND name = $2)",
    )
    .bind(domain_uuid)
    .bind(name)
    .fetch_one(database.read())
    .await
}

/// Whether any enabled SM domain equals or contains `domain`
/// (`a.example.com` is under `example.com`).
pub async fn domain_shadowed(database: &Database, domain: &str) -> Result<bool, sqlx::Error> {
    let domains = enabled_domains(database).await?;
    Ok(domains
        .iter()
        .any(|d| crate::rules::domain::is_under(domain, &d.domain)))
}

/// SM's blacklist regexes from the panel settings store (case-insensitive,
/// invalid patterns skipped).
pub async fn blacklist(database: &Database) -> Vec<regex::Regex> {
    let raw: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = $1")
        .bind(SM_BLACKLIST_KEY)
        .fetch_optional(database.read())
        .await
        .ok()
        .flatten();

    raw.and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .map(|patterns| crate::rules::domain::compile_patterns(&patterns))
        .unwrap_or_default()
}
