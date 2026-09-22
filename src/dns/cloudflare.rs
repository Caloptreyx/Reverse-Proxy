use super::{DnsProvider, DnsRecordInput, StoredRecord};
use std::time::Duration;

const BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareProvider {
    client: reqwest::Client,
    zone_id: String,
    token: String,
}

impl CloudflareProvider {
    pub fn new(zone_id: &str, token: &str) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            zone_id: zone_id.to_string(),
            token: token.to_string(),
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{BASE}{path}"))
            .bearer_auth(&self.token)
    }

    /// Extracts the `errors[].message` list from a failed Cloudflare response.
    async fn response_error(response: reqwest::Response) -> anyhow::Error {
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_default();

        let messages = body["errors"]
            .as_array()
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e["message"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        anyhow::anyhow!(
            "cloudflare: {}",
            if messages.is_empty() {
                format!("request failed with status {status}")
            } else {
                messages
            }
        )
    }
}

/// Request body for `POST /zones/{zone}/dns_records` - not proxied, auto TTL.
pub(crate) fn create_body(record: &DnsRecordInput) -> serde_json::Value {
    serde_json::json!({
        "type": format!("{:?}", record.record_type),
        "name": record.name,
        "content": record.content,
        "ttl": 1,
        "proxied": false,
    })
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_record(&self, record: &DnsRecordInput) -> anyhow::Result<StoredRecord> {
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/zones/{}/dns_records", self.zone_id),
            )
            .json(&create_body(record))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Self::response_error(response).await);
        }

        let body: serde_json::Value = response.json().await?;
        let id = body["result"]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cloudflare: create response missing record id"))?;

        Ok(StoredRecord {
            id: id.to_string(),
            record_type: record.record_type,
        })
    }

    async fn delete_record(&self, id: &str) -> anyhow::Result<()> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/zones/{}/dns_records/{id}", self.zone_id),
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
    use crate::dns::DnsRecordType;

    #[test]
    fn create_body_is_unproxied_auto_ttl() {
        let body = create_body(&DnsRecordInput {
            record_type: DnsRecordType::A,
            name: "play.example.com".to_string(),
            content: "203.0.113.10".to_string(),
        });
        assert_eq!(body["type"], "A");
        assert_eq!(body["name"], "play.example.com");
        assert_eq!(body["content"], "203.0.113.10");
        assert_eq!(body["ttl"], 1);
        assert_eq!(body["proxied"], false);
    }
}
