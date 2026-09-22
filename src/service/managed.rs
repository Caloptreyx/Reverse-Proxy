//! DNS records for managed (Subdomain Manager) domains.
use super::{Ctx, invalid};
use crate::{
    dns::{DnsRecordInput, DnsRecordType, StoredRecord},
    rules::forward::target_as_ip,
    sm::SmDomain,
};
use std::net::IpAddr;

/// The records pointing `fqdn` at the proxy targets: A/AAAA per address, or
/// one CNAME for a hostname target.
pub fn planned_records(fqdn: &str, targets: &[String]) -> Vec<DnsRecordInput> {
    let (addresses, hostnames): (Vec<_>, Vec<_>) =
        targets.iter().partition(|target| target_as_ip(target).is_some());

    if addresses.is_empty() {
        return hostnames
            .first()
            .map(|hostname| DnsRecordInput {
                record_type: DnsRecordType::CNAME,
                name: fqdn.to_string(),
                content: hostname.trim().trim_end_matches('.').to_string(),
            })
            .into_iter()
            .collect();
    }

    addresses
        .iter()
        .filter_map(|target| target_as_ip(target))
        .map(|ip| DnsRecordInput {
            record_type: match ip {
                IpAddr::V4(_) => DnsRecordType::A,
                IpAddr::V6(_) => DnsRecordType::AAAA,
            },
            name: fqdn.to_string(),
            content: ip.to_string(),
        })
        .collect()
}

/// Creates the records at the managed domain's provider. On a partial
/// failure the records created so far are removed again.
pub async fn create_records(
    ctx: &Ctx,
    domain: &SmDomain,
    fqdn: &str,
) -> Result<Vec<StoredRecord>, anyhow::Error> {
    let planned = planned_records(fqdn, &ctx.settings.proxy_targets);
    if planned.is_empty() {
        return Err(invalid(
            "managed subdomains are unavailable: the administrator has not configured the proxy's public address",
        ));
    }

    let provider = domain.provider_client(ctx.db()).await?;
    let mut created = Vec::new();
    for record in &planned {
        match provider.create_record(record).await {
            Ok(stored) => created.push(stored),
            Err(err) => {
                for stored in &created {
                    if let Err(cleanup) = provider.delete_record(&stored.id).await {
                        tracing::warn!(record = %stored.id, "failed to roll back dns record: {cleanup:?}");
                    }
                }
                return Err(super::user_error(
                    format!("failed to create the dns records: {err}"),
                    axum::http::StatusCode::BAD_GATEWAY,
                ));
            }
        }
    }

    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_a_and_aaaa() {
        let records = planned_records(
            "a.example.com",
            &["203.0.113.1".into(), "2001:db8::1".into(), "proxy.example.com".into()],
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, DnsRecordType::A);
        assert_eq!(records[1].record_type, DnsRecordType::AAAA);
        assert!(records.iter().all(|r| r.name == "a.example.com"));
    }

    #[test]
    fn hostname_becomes_one_cname() {
        let records = planned_records("a.example.com", &["proxy.example.com.".into()]);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, DnsRecordType::CNAME);
        assert_eq!(records[0].content, "proxy.example.com");
    }

    #[test]
    fn no_targets_no_records() {
        assert!(planned_records("a.example.com", &[]).is_empty());
    }
}
