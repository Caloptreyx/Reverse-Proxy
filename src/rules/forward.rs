use sqlx::types::ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Resolves the host NPM should forward to for an allocation.
/// Priority: per-node override from settings > the allocation IP when it is
/// not unspecified (`0.0.0.0` / `::`) > the allocation `ip_alias` > the node's
/// own public host. The port is always the allocation's port.
pub fn resolve_forward_host(
    node_override: Option<&str>,
    allocation_ip: IpNetwork,
    allocation_ip_alias: Option<&str>,
    node_host: Option<&str>,
) -> Result<String, shared::response::DisplayError<'static>> {
    if let Some(value) = node_override.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(value.to_string());
    }

    if !allocation_ip.ip().is_unspecified() {
        return Ok(allocation_ip.ip().to_string());
    }

    if let Some(alias) = allocation_ip_alias
        .map(str::trim)
        .map(|alias| alias.trim_end_matches('.'))
        .filter(|alias| !alias.is_empty())
    {
        return Ok(alias.to_string());
    }

    if let Some(host) = node_host.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(host.to_string());
    }

    Err(shared::response::DisplayError::new(
        "could not determine a forward host: the allocation has no usable address and the node has no public hostname; set a forward host override on the node",
    ))
}

/// The node's own public hostname: `public_url` wins over `url`.
pub fn node_public_host(node: &shared::models::node::Node) -> Option<String> {
    node.public_url
        .as_ref()
        .unwrap_or(&node.url)
        .host_str()
        .map(str::to_string)
}

/// Parses the DNS target, which may be a bare IP or a hostname. Returns
/// `Some(IpAddr)` for literal IPs.
pub fn target_as_ip(target: &str) -> Option<IpAddr> {
    let target = target.trim().trim_end_matches('.');
    // tolerate optional brackets around IPv6 literals
    target
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
}

/// Outcome of comparing the domain's resolved addresses against the DNS
/// target.
pub enum PreflightCheck {
    Pass,
    /// Readable message explaining what to fix.
    Fail(String),
}

/// DNS preflight for HTTP-01: `resolved` are the IPs the domain currently
/// resolves to, `targets` the IPs of the DNS target. Passes when any
/// resolved IP is a target.
pub fn compare_preflight(domain: &str, resolved: &[IpAddr], targets: &[IpAddr]) -> PreflightCheck {
    if resolved.is_empty() {
        return PreflightCheck::Fail(format!("{domain} does not resolve yet"));
    }
    if targets.is_empty() {
        return PreflightCheck::Pass;
    }
    if resolved.iter().any(|ip| targets.contains(ip)) {
        return PreflightCheck::Pass;
    }

    let resolved_list = resolved
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let target_list = targets
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let record_kind = |ip: &IpAddr| match ip {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    };

    PreflightCheck::Fail(format!(
        "{domain} resolves to {resolved_list}, expected {target_list} - point an {} record at {}",
        record_kind(&targets[0]),
        targets[0],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpNetwork {
        s.parse().unwrap()
    }

    #[test]
    fn override_wins() {
        assert_eq!(
            resolve_forward_host(
                Some(" 10.9.9.9 "),
                ip("203.0.113.10/32"),
                Some("alias.example.com"),
                Some("node.example.com"),
            )
            .unwrap(),
            "10.9.9.9"
        );
    }

    #[test]
    fn ip_before_alias() {
        assert_eq!(
            resolve_forward_host(None, ip("203.0.113.10/32"), Some("alias.example.com"), None)
                .unwrap(),
            "203.0.113.10"
        );
        assert_eq!(
            resolve_forward_host(None, ip("2001:db8::1/128"), None, None).unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn alias_when_ip_unspecified() {
        assert_eq!(
            resolve_forward_host(None, ip("0.0.0.0/32"), Some("alias.example.com."), None).unwrap(),
            "alias.example.com"
        );
        assert_eq!(
            resolve_forward_host(None, ip("::/128"), Some("alias.example.com"), None).unwrap(),
            "alias.example.com"
        );
    }

    #[test]
    fn node_host_last_resort() {
        assert_eq!(
            resolve_forward_host(None, ip("0.0.0.0/32"), None, Some("node.example.com")).unwrap(),
            "node.example.com"
        );
        assert_eq!(
            resolve_forward_host(
                Some(" "),
                ip("0.0.0.0/32"),
                Some(""),
                Some("node.example.com")
            )
            .unwrap(),
            "node.example.com"
        );
    }

    #[test]
    fn nothing_errors() {
        assert!(resolve_forward_host(None, ip("0.0.0.0/32"), None, None).is_err());
    }

    #[test]
    fn target_ip_parsing() {
        assert_eq!(target_as_ip("1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            target_as_ip(" [2001:db8::5] "),
            Some("2001:db8::5".parse().unwrap())
        );
        assert_eq!(target_as_ip("npm.example.com"), None);
    }

    #[test]
    fn preflight_comparison() {
        let target: IpAddr = "1.2.3.4".parse().unwrap();
        let other: IpAddr = "5.6.7.8".parse().unwrap();

        assert!(matches!(
            compare_preflight("play.example.com", &[target], &[target]),
            PreflightCheck::Pass
        ));
        assert!(matches!(
            compare_preflight("play.example.com", &[other, target], &[target]),
            PreflightCheck::Pass
        ));
        // a target hostname that doesn't resolve can't be checked
        assert!(matches!(
            compare_preflight("play.example.com", &[other], &[]),
            PreflightCheck::Pass
        ));

        match compare_preflight("play.example.com", &[other], &[target]) {
            PreflightCheck::Fail(message) => {
                assert!(message.contains("5.6.7.8"));
                assert!(message.contains("1.2.3.4"));
                assert!(message.contains("A record"));
            }
            PreflightCheck::Pass => panic!("mismatched ips should fail"),
        }

        match compare_preflight("play.example.com", &[], &[target]) {
            PreflightCheck::Fail(message) => {
                assert_eq!(message, "play.example.com does not resolve yet");
            }
            PreflightCheck::Pass => panic!("unresolving domain should fail"),
        }
    }
}
