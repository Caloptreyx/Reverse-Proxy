//! DNS records for managed (Subdomain Manager) domains.
use super::{Ctx, invalid};
use crate::{
    dns::{DnsRecordInput, DnsRecordType, StoredRecord},
    rules::forward::target_as_ip,
    sm::SmDomain,
};

/// The records pointing `fqdn` at the DNS target: an A/AAAA record for an
/// address, a CNAME for a hostname.
pub fn planned_record(fqdn: &str, target: &str) -> DnsRecordInput {
    match target_as_ip(target) {
        Some(ip) => DnsRecordInput {
            record_type: if ip.is_ipv4() {
                DnsRecordType::A
            } else {
                DnsRecordType::AAAA
            },
            name: fqdn.to_string(),
            content: ip.to_string(),
        },
        None => DnsRecordInput {
            record_type: DnsRecordType::CNAME,
            name: fqdn.to_string(),
            content: target.to_string(),
        },
    }
}

/// Creates the record at the managed domain's provider.
pub async fn create_records(
    ctx: &Ctx,
    domain: &SmDomain,
    fqdn: &str,
) -> Result<Vec<StoredRecord>, anyhow::Error> {
    let Some(target) = ctx.settings.dns_target() else {
        return Err(invalid(
            "managed subdomains are unavailable: the administrator has not configured the DNS target",
        ));
    };

    let provider = domain.provider_client(ctx.db()).await?;
    match provider.create_record(&planned_record(fqdn, target)).await {
        Ok(stored) => Ok(vec![stored]),
        Err(err) => Err(super::user_error(
            format!("failed to create the dns record: {err}"),
            axum::http::StatusCode::BAD_GATEWAY,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_a_and_aaaa() {
        assert_eq!(
            planned_record("a.example.com", "203.0.113.1").record_type,
            DnsRecordType::A
        );
        let record = planned_record("a.example.com", "2001:db8::1");
        assert_eq!(record.record_type, DnsRecordType::AAAA);
        assert_eq!(record.name, "a.example.com");
    }

    #[test]
    fn hostname_becomes_cname() {
        let record = planned_record("a.example.com", "proxy.example.com");
        assert_eq!(record.record_type, DnsRecordType::CNAME);
        assert_eq!(record.content, "proxy.example.com");
    }
}
