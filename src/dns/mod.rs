mod bunny;
mod cloudflare;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// DNS record types used for managed proxy records.
/// (variant names are literal DNS record type names)
#[allow(clippy::upper_case_acronyms)]
#[derive(ToSchema, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
}

/// A DNS record to create at a managed domain's provider.
#[derive(Debug, Clone)]
pub struct DnsRecordInput {
    pub record_type: DnsRecordType,
    /// FQDN record name.
    pub name: String,
    pub content: String,
}

/// A record as persisted in `proxies.managed_dns_records` - enough to delete
/// it again.
#[derive(ToSchema, Serialize, Deserialize, Clone, Debug)]
pub struct StoredRecord {
    pub id: String,
    pub record_type: DnsRecordType,
}

#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_record(&self, record: &DnsRecordInput) -> anyhow::Result<StoredRecord>;
    /// Deleting a record that no longer exists (404) counts as success.
    async fn delete_record(&self, id: &str) -> anyhow::Result<()>;
}

pub fn build(
    provider: &str,
    zone_id: &str,
    credential: &str,
) -> anyhow::Result<Box<dyn DnsProvider>> {
    match provider {
        "cloudflare" => Ok(Box::new(cloudflare::CloudflareProvider::new(
            zone_id, credential,
        )?)),
        "bunny" => Ok(Box::new(bunny::BunnyProvider::new(zone_id, credential)?)),
        _ => Err(anyhow::anyhow!("unknown dns provider `{provider}`")),
    }
}
