use super::{DnsProvider, DnsRecordInput, DnsRecordType, StoredRecord};
use std::time::Duration;

const BASE: &str = "https://api.bunny.net";

pub struct BunnyProvider {
    client: reqwest::Client,
    zone_id: String,
    key: String,
}

impl BunnyProvider {
    pub fn new(zone_id: &str, key: &str) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            zone_id: zone_id.to_string(),
            key: key.to_string(),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{BASE}{path}"))
            .header("AccessKey", &self.key)
    }

    /// Fetches the zone's domain name (for relativizing record names).
    async fn zone_domain(&self) -> anyhow::Result<String> {
        let response = self
            .request(reqwest::Method::GET, &format!("/dnszone/{}", self.zone_id))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::response_error(response).await);
        }

        let body: serde_json::Value = response.json().await?;
        body["Domain"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("bunny: zone response missing Domain"))
    }

    /// Extracts the `Message` field from a failed Bunny response.
    async fn response_error(response: reqwest::Response) -> anyhow::Error {
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_default();

        let message = body["Message"].as_str().unwrap_or_default();

        anyhow::anyhow!(
            "bunny: {}",
            if message.is_empty() {
                format!("request failed with status {status}")
            } else {
                message.to_string()
            }
        )
    }
}

/// Bunny record type ids.
pub(crate) fn record_type_int(record_type: DnsRecordType) -> i64 {
    match record_type {
        DnsRecordType::A => 0,
        DnsRecordType::AAAA => 1,
        DnsRecordType::CNAME => 2,
    }
}

/// Converts an FQDN into a Bunny zone-relative record name. The zone apex is
/// represented by an empty name.
pub(crate) fn relative_name(fqdn: &str, zone_domain: &str) -> String {
    if fqdn == zone_domain {
        return String::new();
    }

    match fqdn.strip_suffix(&format!(".{zone_domain}")) {
        Some(relative) => relative.to_string(),
        None => fqdn.to_string(),
    }
}

/// Request body for `PUT /dnszone/{zone}/records` - auto TTL is 300.
pub(crate) fn create_body(record: &DnsRecordInput, zone_domain: &str) -> serde_json::Value {
    serde_json::json!({
        "Type": record_type_int(record.record_type),
        "Name": relative_name(&record.name, zone_domain),
        "Value": record.content,
        "Ttl": 300,
    })
}

#[async_trait::async_trait]
impl DnsProvider for BunnyProvider {
    async fn create_record(&self, record: &DnsRecordInput) -> anyhow::Result<StoredRecord> {
        let zone_domain = self.zone_domain().await?;

        let response = self
            .request(
                reqwest::Method::PUT,
                &format!("/dnszone/{}/records", self.zone_id),
            )
            .json(&create_body(record, &zone_domain))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::response_error(response).await);
        }

        let body: serde_json::Value = response.json().await?;
        let id = body["Id"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("bunny: create response missing record Id"))?;

        Ok(StoredRecord {
            id: id.to_string(),
            record_type: record.record_type,
        })
    }

    async fn delete_record(&self, id: &str) -> anyhow::Result<()> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/dnszone/{}/records/{id}", self.zone_id),
            )
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND || response.status().is_success() {
            return Ok(());
        }

        Err(Self::response_error(response).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_name_strips_zone() {
        assert_eq!(relative_name("play.example.com", "example.com"), "play");
        assert_eq!(relative_name("example.com", "example.com"), "");
        assert_eq!(
            relative_name("play.other.net", "example.com"),
            "play.other.net"
        );
    }

    #[test]
    fn create_body_maps_types() {
        let body = create_body(
            &DnsRecordInput {
                record_type: DnsRecordType::CNAME,
                name: "play.example.com".to_string(),
                content: "npm.example.com".to_string(),
            },
            "example.com",
        );
        assert_eq!(body["Type"], 2);
        assert_eq!(body["Name"], "play");
        assert_eq!(body["Value"], "npm.example.com");
        assert_eq!(body["Ttl"], 300);
    }
}
