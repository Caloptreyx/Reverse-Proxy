//! Pure helpers around NPM certificates.
use super::NpmVersion;

#[derive(Clone)]
pub struct DnsChallenge {
    pub provider: &'static str,
    pub credentials: String,
    pub propagation_seconds: u32,
}

impl DnsChallenge {
    pub fn cloudflare(token: &str, propagation_seconds: u32) -> Self {
        Self {
            provider: "cloudflare",
            credentials: format!("# Cloudflare API token\ndns_cloudflare_api_token = {token}\n"),
            propagation_seconds,
        }
    }
}

/// `meta` for a Let's Encrypt certificate request. NPM < 2.13 additionally
/// needs `letsencrypt_email`/`letsencrypt_agree`; newer versions reject them.
pub fn letsencrypt_meta(
    version: &NpmVersion,
    email: &str,
    dns_challenge: Option<&DnsChallenge>,
) -> serde_json::Value {
    let mut meta = serde_json::Map::new();

    if !version.modern_certificate_meta() {
        meta.insert("letsencrypt_email".into(), email.into());
        meta.insert("letsencrypt_agree".into(), true.into());
    }

    meta.insert("dns_challenge".into(), dns_challenge.is_some().into());
    if let Some(dns) = dns_challenge {
        meta.insert("dns_provider".into(), dns.provider.into());
        meta.insert(
            "dns_provider_credentials".into(),
            dns.credentials.clone().into(),
        );
        meta.insert(
            "propagation_seconds".into(),
            dns.propagation_seconds.into(),
        );
    }

    serde_json::Value::Object(meta)
}

/// Whether a certificate's names cover `fqdn`: exact match or a single-label
/// wildcard (`*.example.com` covers `a.example.com`, not `a.b.example.com`).
pub fn covers_domain(cert_domain_names: &[String], fqdn: &str) -> bool {
    cert_domain_names.iter().any(|name| {
        let name = name.to_lowercase();
        if name == fqdn {
            return true;
        }
        name.strip_prefix("*.").is_some_and(|parent| {
            fqdn.strip_suffix(parent)
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        })
    })
}

/// Distills certbot noise out of an NPM certificate error into something a
/// panel user can act on.
pub fn clean_certbot_error(raw: &str) -> String {
    const NOISE: &[&str] = &[
        "saving debug log",
        "ask for help",
        "see the logfile",
        "re-run certbot",
        "rerun certbot",
        "logfile",
    ];
    const SIGNAL: &[&str] = &[
        "detail:",
        "error",
        "failed",
        "invalid",
        "unable to",
        "unauthorized",
        "denied",
        "timed out",
        "timeout",
        "too many",
        "rate limit",
    ];

    let meaningful: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_lowercase();
            !NOISE.iter().any(|noise| lower.contains(noise))
        })
        .collect();

    let preferred: Vec<&str> = meaningful
        .iter()
        .copied()
        .filter(|line| {
            let lower = line.to_lowercase();
            SIGNAL.iter().any(|signal| lower.contains(signal))
        })
        .collect();

    let chosen = if preferred.is_empty() {
        meaningful
    } else {
        preferred
    };
    let joined = chosen.join("; ");
    let message = joined
        .strip_prefix("Error: ")
        .or_else(|| joined.strip_prefix("error: "))
        .unwrap_or(&joined);

    if message.is_empty() {
        return "certificate issuance failed".to_string();
    }
    if message.chars().count() > 500 {
        return format!("{}...", message.chars().take(497).collect::<String>());
    }
    message.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(major: u64, minor: u64) -> NpmVersion {
        NpmVersion {
            major,
            minor,
            revision: 0,
        }
    }

    #[test]
    fn letsencrypt_meta_modern_omits_email_keys() {
        let meta = letsencrypt_meta(&version(2, 13), "a@b.c", None);
        assert_eq!(meta["dns_challenge"], false);
        assert!(meta.get("letsencrypt_email").is_none());
        assert!(meta.get("letsencrypt_agree").is_none());
    }

    #[test]
    fn letsencrypt_meta_legacy_includes_email_keys() {
        let meta = letsencrypt_meta(&version(2, 12), "a@b.c", None);
        assert_eq!(meta["letsencrypt_email"], "a@b.c");
        assert_eq!(meta["letsencrypt_agree"], true);
    }

    #[test]
    fn letsencrypt_meta_dns_challenge() {
        let dns = DnsChallenge::cloudflare("tok123", 30);
        let meta = letsencrypt_meta(&version(2, 15), "a@b.c", Some(&dns));
        assert_eq!(meta["dns_challenge"], true);
        assert_eq!(meta["dns_provider"], "cloudflare");
        assert_eq!(
            meta["dns_provider_credentials"],
            "# Cloudflare API token\ndns_cloudflare_api_token = tok123\n"
        );
        assert_eq!(meta["propagation_seconds"], 30);
    }

    #[test]
    fn covers_domain_exact_and_wildcard() {
        let names = vec!["example.com".to_string(), "*.sub.example.com".to_string()];
        assert!(covers_domain(&names, "example.com"));
        assert!(covers_domain(&names, "a.sub.example.com"));
        assert!(!covers_domain(&names, "a.b.sub.example.com"));
        assert!(!covers_domain(&names, "other.com"));
        assert!(!covers_domain(&names, "example.com.evil.com"));
        assert!(!covers_domain(&names, "xsub.example.com"));

        let wildcard = vec!["*.example.com".to_string()];
        assert!(covers_domain(&wildcard, "play.example.com"));
        assert!(!covers_domain(&wildcard, "example.com"));
        assert!(!covers_domain(&wildcard, ".example.com"));
    }

    #[test]
    fn clean_certbot_error_prefers_detail_lines() {
        let raw = "Saving debug log to /data/logs/letsencrypt.log\n\
                   Plugins selected: Authenticator webroot\n\
                   Certbot failed to authenticate some domains.\n\
                   Detail: 203.0.113.10: Fetching http://a.example.com/.well-known/acme-challenge/x: Timeout during connect\n\
                   Ask for help or search for solutions at https://community.letsencrypt.org.";
        let cleaned = clean_certbot_error(raw);
        assert!(cleaned.contains("Detail: 203.0.113.10"));
        assert!(!cleaned.contains("Ask for help"));
        assert!(!cleaned.contains("Saving debug log"));
        assert!(!cleaned.contains("Plugins selected"));
    }

    #[test]
    fn clean_certbot_error_caps_and_defaults() {
        assert!(clean_certbot_error(&format!("Error: {}", "x".repeat(1000))).chars().count() <= 500);
        assert_eq!(clean_certbot_error(""), "certificate issuance failed");
        assert_eq!(
            clean_certbot_error("Saving debug log to x\nAsk for help"),
            "certificate issuance failed"
        );
        assert_eq!(clean_certbot_error("Error: boom"), "boom");
    }
}
