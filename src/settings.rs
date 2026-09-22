use garde::Validate;
use serde::{Deserialize, Serialize};
use shared::extensions::settings::{
    ExtensionSettings, SettingsDeserializeExt, SettingsDeserializer, SettingsSerializeExt,
    SettingsSerializer,
};
use std::time::Duration;
use utoipa::ToSchema;

/// Flags + scheme applied to new proxies when the create payload omits them.
#[derive(ToSchema, Validate, Serialize, Deserialize, Clone)]
pub struct ProxyDefaults {
    #[garde(skip)]
    pub websockets: bool,
    #[garde(skip)]
    pub caching: bool,
    #[garde(skip)]
    pub http2: bool,
    #[garde(skip)]
    pub hsts: bool,
    #[garde(skip)]
    pub hsts_subdomains: bool,
    #[garde(skip)]
    pub force_https: bool,
    #[garde(skip)]
    pub block_exploits: bool,
    #[garde(length(chars, min = 4, max = 5))]
    #[schema(min_length = 4, max_length = 5)]
    pub forward_scheme: String,
}

impl Default for ProxyDefaults {
    fn default() -> Self {
        Self {
            websockets: true,
            caching: false,
            http2: true,
            hsts: false,
            hsts_subdomains: false,
            force_https: true,
            block_exploits: true,
            forward_scheme: "http".to_string(),
        }
    }
}

#[derive(ToSchema, Validate, Serialize, Deserialize, Clone)]
pub struct ExtensionSettingsData {
    /// Base URL of the Nginx Proxy Manager instance, e.g. `http://npm:81`.
    #[garde(length(chars, max = 255))]
    #[schema(max_length = 255)]
    pub npm_url: String,
    /// NPM user (email) used for the API.
    #[garde(length(chars, max = 255))]
    #[schema(max_length = 255)]
    pub npm_identity: String,
    /// Write-only: stored encrypted, never serialized back to clients. An
    /// empty/absent value on update keeps the stored secret.
    #[garde(length(chars, max = 255))]
    #[serde(skip_serializing, default)]
    pub npm_secret: Option<String>,
    /// Seconds before a regular NPM API call is abandoned.
    #[garde(range(min = 5, max = 300))]
    #[schema(minimum = 5, maximum = 300)]
    pub request_timeout_seconds: u32,
    /// Random id of this panel installation, baked into ownership markers.
    #[garde(skip)]
    #[serde(skip_serializing, default)]
    pub instance_id: String,

    /// Public IPs or one hostname of the NPM box: shown to users, used for
    /// the DNS preflight and for managed subdomain records.
    #[garde(inner(length(chars, min = 1, max = 253)))]
    pub proxy_targets: Vec<String>,
    #[garde(skip)]
    pub dns_preflight: bool,

    #[garde(range(min = 0))]
    #[schema(minimum = 0)]
    pub default_limit: i32,
    #[garde(skip)]
    pub allow_custom_domains: bool,
    #[garde(skip)]
    pub allow_letsencrypt: bool,
    #[garde(skip)]
    pub allow_custom_certificates: bool,
    /// Lets users add nginx snippets to their proxy hosts.
    #[garde(skip)]
    pub allow_custom_nginx: bool,
    /// Glob patterns (`example.com`, `*.example.com`); empty = any.
    #[garde(inner(length(chars, min = 1, max = 253)))]
    pub allowed_domains: Vec<String>,
    /// Case-insensitive regexes a domain must not match.
    #[garde(inner(length(chars, min = 1, max = 255)))]
    pub blocked_patterns: Vec<String>,
    #[garde(dive)]
    pub defaults: ProxyDefaults,
    /// Forward host override per node uuid.
    #[garde(skip)]
    #[schema(value_type = std::collections::HashMap<String, String>)]
    pub node_forward_hosts: indexmap::IndexMap<uuid::Uuid, String>,

    #[garde(range(min = 1))]
    #[schema(minimum = 1)]
    pub max_issuances_per_hour: u32,
    #[garde(range(min = 1))]
    #[schema(minimum = 1)]
    pub max_issuances_per_domain_per_week: u32,
    #[garde(skip)]
    pub reuse_certificates: bool,
    /// Live proxies whose certificate expires within this many days get a
    /// warning; reused certificates must be valid for at least this long.
    #[garde(range(min = 1, max = 60))]
    #[schema(minimum = 1, maximum = 60)]
    pub certificate_warning_days: u32,

    #[garde(skip)]
    pub subdomain_manager_integration: bool,
    #[garde(skip)]
    pub managed_dns_challenge: bool,
    #[garde(range(min = 0, max = 600))]
    #[schema(minimum = 0, maximum = 600)]
    pub dns_propagation_seconds: u32,

    /// Run the periodic sync at all.
    #[garde(skip)]
    pub sync_enabled: bool,
    /// Let the sync fix drift and orphans (otherwise it only reports).
    #[garde(skip)]
    pub auto_reconcile: bool,
    #[garde(range(min = 30, max = 86400))]
    #[schema(minimum = 30, maximum = 86400)]
    pub sync_interval_seconds: u32,
}

impl Default for ExtensionSettingsData {
    fn default() -> Self {
        Self {
            npm_url: String::new(),
            npm_identity: String::new(),
            npm_secret: None,
            request_timeout_seconds: 30,
            instance_id: String::new(),
            proxy_targets: Vec::new(),
            dns_preflight: true,
            default_limit: 0,
            allow_custom_domains: true,
            allow_letsencrypt: true,
            allow_custom_certificates: true,
            allow_custom_nginx: false,
            allowed_domains: Vec::new(),
            blocked_patterns: Vec::new(),
            defaults: ProxyDefaults::default(),
            node_forward_hosts: indexmap::IndexMap::new(),
            max_issuances_per_hour: 10,
            max_issuances_per_domain_per_week: 3,
            reuse_certificates: true,
            certificate_warning_days: 14,
            subdomain_manager_integration: true,
            managed_dns_challenge: true,
            dns_propagation_seconds: 30,
            sync_enabled: true,
            auto_reconcile: true,
            sync_interval_seconds: 600,
        }
    }
}

impl ExtensionSettingsData {
    pub fn is_configured(&self) -> bool {
        !self.npm_url.trim().is_empty()
            && !self.npm_identity.trim().is_empty()
            && self.npm_secret.as_deref().is_some_and(|s| !s.is_empty())
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_seconds.clamp(5, 300) as u64)
    }

    pub fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.sync_interval_seconds.clamp(30, 86400) as u64)
    }

    pub fn warning_window(&self) -> chrono::Duration {
        chrono::Duration::days(self.certificate_warning_days.clamp(1, 60) as i64)
    }

    pub fn blocked(&self) -> Vec<regex::Regex> {
        crate::rules::domain::compile_patterns(&self.blocked_patterns)
    }

    /// Readable problems with values garde can't check (regexes, hosts).
    pub fn semantic_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if !matches!(self.defaults.forward_scheme.as_str(), "http" | "https") {
            errors.push("the default forward scheme must be `http` or `https`".to_string());
        }

        for pattern in &self.blocked_patterns {
            if let Err(err) = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
            {
                errors.push(format!("blocked pattern `{pattern}` is not a valid regex: {err}"));
            }
        }

        let valid_host = |host: &str| {
            crate::rules::forward::target_as_ip(host).is_some()
                || crate::rules::domain::validate_domain(host).is_ok()
        };
        for target in &self.proxy_targets {
            if !valid_host(target) {
                errors.push(format!(
                    "proxy target `{target}` is neither an ip address nor a hostname"
                ));
            }
        }
        if self
            .proxy_targets
            .iter()
            .filter(|t| crate::rules::forward::target_as_ip(t).is_none())
            .count()
            > 1
        {
            errors.push("only one hostname may be used as a proxy target".to_string());
        }
        for (node, host) in &self.node_forward_hosts {
            if !valid_host(host) {
                errors.push(format!(
                    "forward host override for node {node} is not a valid ip or hostname"
                ));
            }
        }
        if !self.npm_url.is_empty() && reqwest::Url::parse(&self.npm_url).is_err() {
            errors.push("the npm url is not a valid url".to_string());
        }

        errors
    }
}

#[async_trait::async_trait]
impl SettingsSerializeExt for ExtensionSettingsData {
    async fn serialize(
        &self,
        serializer: SettingsSerializer,
    ) -> Result<SettingsSerializer, anyhow::Error> {
        let serializer = serializer
            .write_raw_setting("npm_url", &*self.npm_url)
            .write_raw_setting("npm_identity", &*self.npm_identity)
            .write_raw_setting("instance_id", &*self.instance_id)
            .write_serde_setting("request_timeout_seconds", &self.request_timeout_seconds)?
            .write_serde_setting("proxy_targets", &self.proxy_targets)?
            .write_serde_setting("dns_preflight", &self.dns_preflight)?
            .write_serde_setting("default_limit", &self.default_limit)?
            .write_serde_setting("allow_custom_domains", &self.allow_custom_domains)?
            .write_serde_setting("allow_letsencrypt", &self.allow_letsencrypt)?
            .write_serde_setting("allow_custom_certificates", &self.allow_custom_certificates)?
            .write_serde_setting("allow_custom_nginx", &self.allow_custom_nginx)?
            .write_serde_setting("allowed_domains", &self.allowed_domains)?
            .write_serde_setting("blocked_patterns", &self.blocked_patterns)?
            .write_serde_setting("defaults", &self.defaults)?
            .write_serde_setting("node_forward_hosts", &self.node_forward_hosts)?
            .write_serde_setting("max_issuances_per_hour", &self.max_issuances_per_hour)?
            .write_serde_setting(
                "max_issuances_per_domain_per_week",
                &self.max_issuances_per_domain_per_week,
            )?
            .write_serde_setting("reuse_certificates", &self.reuse_certificates)?
            .write_serde_setting("certificate_warning_days", &self.certificate_warning_days)?
            .write_serde_setting(
                "subdomain_manager_integration",
                &self.subdomain_manager_integration,
            )?
            .write_serde_setting("managed_dns_challenge", &self.managed_dns_challenge)?
            .write_serde_setting("dns_propagation_seconds", &self.dns_propagation_seconds)?
            .write_serde_setting("sync_enabled", &self.sync_enabled)?
            .write_serde_setting("auto_reconcile", &self.auto_reconcile)?
            .write_serde_setting("sync_interval_seconds", &self.sync_interval_seconds)?;

        Ok(match self.npm_secret.as_deref().filter(|s| !s.is_empty()) {
            Some(secret) => {
                serializer
                    .write_raw_encrypted_setting("npm_secret", secret)
                    .await?
            }
            None => serializer.write_raw_setting("npm_secret", ""),
        })
    }
}

pub struct ExtensionSettingsDataDeserializer;

#[async_trait::async_trait]
impl SettingsDeserializeExt for ExtensionSettingsDataDeserializer {
    async fn deserialize_boxed(
        &self,
        deserializer: SettingsDeserializer<'_>,
    ) -> Result<ExtensionSettings, anyhow::Error> {
        let d = ExtensionSettingsData::default();

        let raw = |key: &str| {
            deserializer
                .read_raw_setting(key)
                .map(|value| value.to_string())
                .unwrap_or_default()
        };
        macro_rules! serde_or {
            ($key:literal, $default:expr) => {
                deserializer.read_serde_setting($key).unwrap_or($default)
            };
        }

        let npm_secret = match deserializer.read_raw_setting("npm_secret") {
            Some(value) if !value.is_empty() => Some(
                deserializer
                    .database
                    .decrypt_base64(value)
                    .await?
                    .to_string(),
            ),
            _ => None,
        };

        Ok(Box::new(ExtensionSettingsData {
            npm_url: raw("npm_url"),
            npm_identity: raw("npm_identity"),
            npm_secret,
            request_timeout_seconds: serde_or!("request_timeout_seconds", d.request_timeout_seconds),
            instance_id: raw("instance_id"),
            proxy_targets: serde_or!("proxy_targets", d.proxy_targets),
            dns_preflight: serde_or!("dns_preflight", d.dns_preflight),
            default_limit: serde_or!("default_limit", d.default_limit),
            allow_custom_domains: serde_or!("allow_custom_domains", d.allow_custom_domains),
            allow_letsencrypt: serde_or!("allow_letsencrypt", d.allow_letsencrypt),
            allow_custom_certificates: serde_or!(
                "allow_custom_certificates",
                d.allow_custom_certificates
            ),
            allow_custom_nginx: serde_or!("allow_custom_nginx", d.allow_custom_nginx),
            allowed_domains: serde_or!("allowed_domains", d.allowed_domains),
            blocked_patterns: serde_or!("blocked_patterns", d.blocked_patterns),
            defaults: serde_or!("defaults", d.defaults),
            node_forward_hosts: serde_or!("node_forward_hosts", d.node_forward_hosts),
            max_issuances_per_hour: serde_or!("max_issuances_per_hour", d.max_issuances_per_hour),
            max_issuances_per_domain_per_week: serde_or!(
                "max_issuances_per_domain_per_week",
                d.max_issuances_per_domain_per_week
            ),
            reuse_certificates: serde_or!("reuse_certificates", d.reuse_certificates),
            certificate_warning_days: serde_or!(
                "certificate_warning_days",
                d.certificate_warning_days
            ),
            subdomain_manager_integration: serde_or!(
                "subdomain_manager_integration",
                d.subdomain_manager_integration
            ),
            managed_dns_challenge: serde_or!("managed_dns_challenge", d.managed_dns_challenge),
            dns_propagation_seconds: serde_or!(
                "dns_propagation_seconds",
                d.dns_propagation_seconds
            ),
            sync_enabled: serde_or!("sync_enabled", d.sync_enabled),
            auto_reconcile: serde_or!("auto_reconcile", d.auto_reconcile),
            sync_interval_seconds: serde_or!("sync_interval_seconds", d.sync_interval_seconds),
        }))
    }
}
