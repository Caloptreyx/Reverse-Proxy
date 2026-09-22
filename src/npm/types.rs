use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// NPM certificate `expires_on` values are naive `"YYYY-MM-DD HH:MM:SS"` (UTC).
const NPM_TIMESTAMP: &str = "%Y-%m-%d %H:%M:%S";

#[derive(Deserialize, Debug, Clone, Copy)]
pub struct NpmVersion {
    pub major: u64,
    pub minor: u64,
    pub revision: u64,
}

impl NpmVersion {
    /// Certificate meta is `additionalProperties: false` since 2.13 and the
    /// Let's Encrypt account email comes from the API user.
    pub fn modern_certificate_meta(&self) -> bool {
        (self.major, self.minor) >= (2, 13)
    }
}

impl std::fmt::Display for NpmVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.revision)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct NpmUser {
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct NpmProxyHost {
    pub id: i64,
    #[serde(default)]
    pub domain_names: Vec<String>,
    #[serde(default)]
    pub forward_scheme: String,
    #[serde(default)]
    pub forward_host: String,
    #[serde(default)]
    pub forward_port: i32,
    #[serde(default)]
    pub certificate_id: i64,
    #[serde(default)]
    pub ssl_forced: bool,
    #[serde(default)]
    pub caching_enabled: bool,
    #[serde(default)]
    pub block_exploits: bool,
    #[serde(default)]
    pub allow_websocket_upgrade: bool,
    #[serde(default)]
    pub http2_support: bool,
    #[serde(default)]
    pub hsts_enabled: bool,
    #[serde(default)]
    pub hsts_subdomains: bool,
    #[serde(default)]
    pub advanced_config: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub meta: serde_json::Value,
}

fn default_true() -> bool {
    true
}

impl NpmProxyHost {
    /// `Some(reason)` when NPM reports the generated nginx config as broken.
    pub fn nginx_error(&self) -> Option<String> {
        if self.meta["nginx_online"].as_bool() == Some(false) {
            Some(
                self.meta["nginx_err"]
                    .as_str()
                    .filter(|err| !err.is_empty())
                    .unwrap_or("nginx rejected the generated configuration")
                    .to_string(),
            )
        } else {
            None
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct NpmCertificate {
    pub id: i64,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub nice_name: String,
    #[serde(default)]
    pub domain_names: Vec<String>,
    #[serde(default)]
    pub expires_on: Option<String>,
}

impl NpmCertificate {
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_on
            .as_deref()
            .and_then(|raw| chrono::NaiveDateTime::parse_from_str(raw, NPM_TIMESTAMP).ok())
            .map(|dt| dt.and_utc())
    }

    pub fn is_letsencrypt(&self) -> bool {
        self.provider == "letsencrypt"
    }
}

/// The complete desired state of an NPM proxy host. Used both as the
/// create/update payload and as the reference for drift detection.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct HostPayload {
    pub domain_names: Vec<String>,
    pub forward_scheme: String,
    pub forward_host: String,
    pub forward_port: i32,
    pub certificate_id: i64,
    pub ssl_forced: bool,
    pub caching_enabled: bool,
    pub block_exploits: bool,
    pub allow_websocket_upgrade: bool,
    pub http2_support: bool,
    pub hsts_enabled: bool,
    pub hsts_subdomains: bool,
    pub access_list_id: i64,
    pub advanced_config: String,
}

impl HostPayload {
    /// Names of the fields where `host` differs from this desired state.
    pub fn drift(&self, host: &NpmProxyHost) -> Vec<&'static str> {
        let mut fields = Vec::new();
        let mut check = |name: &'static str, differs: bool| {
            if differs {
                fields.push(name);
            }
        };

        check("domain_names", host.domain_names != self.domain_names);
        check("forward_scheme", host.forward_scheme != self.forward_scheme);
        check("forward_host", host.forward_host != self.forward_host);
        check("forward_port", host.forward_port != self.forward_port);
        check("certificate_id", host.certificate_id != self.certificate_id);
        check("ssl_forced", host.ssl_forced != self.ssl_forced);
        check("caching_enabled", host.caching_enabled != self.caching_enabled);
        check("block_exploits", host.block_exploits != self.block_exploits);
        check(
            "allow_websocket_upgrade",
            host.allow_websocket_upgrade != self.allow_websocket_upgrade,
        );
        check("http2_support", host.http2_support != self.http2_support);
        check("hsts_enabled", host.hsts_enabled != self.hsts_enabled);
        check("hsts_subdomains", host.hsts_subdomains != self.hsts_subdomains);
        check(
            "advanced_config",
            host.advanced_config.trim() != self.advanced_config.trim(),
        );
        check("enabled", !host.enabled);

        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> HostPayload {
        HostPayload {
            domain_names: vec!["a.example.com".into()],
            forward_scheme: "http".into(),
            forward_host: "10.0.0.1".into(),
            forward_port: 8080,
            certificate_id: 3,
            ssl_forced: true,
            caching_enabled: false,
            block_exploits: true,
            allow_websocket_upgrade: true,
            http2_support: true,
            hsts_enabled: false,
            hsts_subdomains: false,
            access_list_id: 0,
            advanced_config: "# marker".into(),
        }
    }

    fn host_from(payload: &HostPayload) -> NpmProxyHost {
        serde_json::from_value(serde_json::json!({
            "id": 1,
            "domain_names": payload.domain_names,
            "forward_scheme": payload.forward_scheme,
            "forward_host": payload.forward_host,
            "forward_port": payload.forward_port,
            "certificate_id": payload.certificate_id,
            "ssl_forced": payload.ssl_forced,
            "caching_enabled": payload.caching_enabled,
            "block_exploits": payload.block_exploits,
            "allow_websocket_upgrade": payload.allow_websocket_upgrade,
            "http2_support": payload.http2_support,
            "hsts_enabled": payload.hsts_enabled,
            "hsts_subdomains": payload.hsts_subdomains,
            "advanced_config": format!("{}\n", payload.advanced_config),
            "enabled": true,
            "meta": {"nginx_online": true, "nginx_err": null},
        }))
        .unwrap()
    }

    #[test]
    fn identical_host_has_no_drift() {
        let payload = payload();
        assert!(payload.drift(&host_from(&payload)).is_empty());
    }

    #[test]
    fn drift_lists_changed_fields() {
        let payload = payload();
        let mut host = host_from(&payload);
        host.forward_port = 9000;
        host.hsts_enabled = true;
        host.enabled = false;
        assert_eq!(
            payload.drift(&host),
            vec!["forward_port", "hsts_enabled", "enabled"]
        );
    }

    #[test]
    fn nginx_error_reads_meta() {
        let mut host = host_from(&payload());
        assert!(host.nginx_error().is_none());
        host.meta = serde_json::json!({"nginx_online": false, "nginx_err": "bad directive"});
        assert_eq!(host.nginx_error().as_deref(), Some("bad directive"));
    }

    #[test]
    fn expires_at_parses_npm_format() {
        let cert: NpmCertificate = serde_json::from_value(serde_json::json!({
            "id": 1, "provider": "letsencrypt", "expires_on": "2026-12-21 18:54:09"
        }))
        .unwrap();
        assert_eq!(
            cert.expires_at().unwrap().to_rfc3339(),
            "2026-12-21T18:54:09+00:00"
        );
        let bad = NpmCertificate {
            expires_on: Some("nonsense".into()),
            ..cert
        };
        assert!(bad.expires_at().is_none());
    }
}
