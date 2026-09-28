//! Nginx Proxy Manager / NPMplus API client.
mod cert;
mod multipart;
mod types;

pub use cert::{DnsChallenge, clean_certbot_error, covers_domain, letsencrypt_meta, npmplus_letsencrypt_body};
pub use types::{HostPayload, NpmCertificate, NpmProxyHost, NpmUser, NpmVersion, Server};

use chrono::{DateTime, Utc};
use multipart::MultipartBody;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use sha2::Digest;
use std::{collections::HashMap, sync::LazyLock, time::Duration};

/// An error reported by NPM itself (as opposed to transport failures).
#[derive(Debug)]
pub struct NpmError {
    pub status: StatusCode,
    pub message: String,
    /// certbot output attached to certificate errors (NPM: `debug.stack`,
    /// NPMplus: `error.output`).
    pub detail: Option<String>,
}

impl NpmError {
    /// The most useful single-line reason for a panel user.
    pub fn readable(&self) -> String {
        match &self.detail {
            Some(detail) => clean_certbot_error(detail),
            None => self.message.clone(),
        }
    }
}

impl std::fmt::Display for NpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nginx proxy manager: {}", self.message)
    }
}

impl std::error::Error for NpmError {}

/// Readable reason for any error coming out of the client.
pub fn readable_error(err: &anyhow::Error) -> String {
    match err.downcast_ref::<NpmError>() {
        Some(npm) => npm.readable(),
        None => match err.downcast_ref::<reqwest::Error>() {
            Some(http) if http.is_timeout() || http.is_connect() => {
                let target = http
                    .url()
                    .and_then(|url| {
                        url.host_str()
                            .map(|host| format!("{host}:{}", url.port_or_known_default().unwrap_or(80)))
                    })
                    .unwrap_or_else(|| "the proxy manager".to_string());
                if http.is_timeout() {
                    format!(
                        "{target} did not answer in time - check that the panel server can reach it (firewall, VPN) and that the port is right"
                    )
                } else if is_certificate_error(http) {
                    format!(
                        "{target} presented a tls certificate the panel does not trust - NPMplus uses a self-signed one by default, enable \"accept self-signed certificate\" or give it a trusted certificate"
                    )
                } else {
                    format!("could not connect to {target} - check the url and that the proxy manager is running")
                }
            }
            _ => err.to_string(),
        },
    }
}

fn is_certificate_error(err: &reqwest::Error) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(err);
    while let Some(current) = source {
        if current.to_string().to_ascii_lowercase().contains("certificate") {
            return true;
        }
        source = current.source();
    }
    false
}

enum Body {
    None,
    Json(serde_json::Value),
    Multipart(MultipartBody),
}

/// How requests authenticate: NPM hands out a bearer token, NPMplus sets it
/// as a (signed, `Secure`) cookie instead.
#[derive(Clone, Debug, PartialEq)]
enum Auth {
    Bearer(String),
    Cookie(String),
}

#[derive(Clone)]
struct Session {
    auth: Auth,
    server: Server,
    expires: DateTime<Utc>,
}

static SESSION_CACHE: LazyLock<tokio::sync::Mutex<HashMap<String, Session>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

/// Upper bound for a synchronous Let's Encrypt request (certbot runs inside
/// the request).
const ISSUANCE_TIMEOUT: Duration = Duration::from_secs(600);

/// Credentials from a `POST /api/tokens` response: the `token` field, or all
/// cookies it set when there is none.
fn parse_login<'a>(
    body: &serde_json::Value,
    set_cookies: impl Iterator<Item = &'a str>,
) -> Result<Auth, anyhow::Error> {
    if body["requires_2fa"].as_bool() == Some(true) || body["requiresTotp"].as_bool() == Some(true) {
        anyhow::bail!(NpmError {
            status: StatusCode::UNAUTHORIZED,
            message: "the api user has two-factor authentication enabled - disable 2fa for it"
                .to_string(),
            detail: None,
        });
    }

    if let Some(token) = body["token"].as_str() {
        return Ok(Auth::Bearer(token.to_string()));
    }

    let cookies = set_cookies
        .filter_map(|header| header.split(';').next())
        .map(str::trim)
        .filter(|pair| pair.contains('='))
        .collect::<Vec<_>>()
        .join("; ");
    if cookies.is_empty() {
        anyhow::bail!("the proxy manager returned no token");
    }
    Ok(Auth::Cookie(cookies))
}

pub struct NpmClient {
    http: reqwest::Client,
    base: String,
    identity: String,
    secret: String,
    cache_key: String,
    timeout: Duration,
}

impl NpmClient {
    /// `accept_invalid_certs` skips tls verification (NPMplus serves its api
    /// with a self-signed certificate by default).
    pub fn new(
        url: &str,
        identity: &str,
        secret: &str,
        timeout: Duration,
        accept_invalid_certs: bool,
    ) -> Result<Self, anyhow::Error> {
        let base = url.trim().trim_end_matches('/').to_string();
        if base.is_empty() || identity.trim().is_empty() || secret.is_empty() {
            anyhow::bail!("the nginx proxy manager connection is not configured");
        }

        let cache_key = sha2::Sha256::digest(format!("{base}\n{identity}\n{secret}"))
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        Ok(Self {
            http: reqwest::Client::builder()
                .danger_accept_invalid_certs(accept_invalid_certs)
                .build()?,
            base,
            identity: identity.trim().to_string(),
            secret: secret.to_string(),
            cache_key,
            timeout,
        })
    }

    /// Identifies the server via its unauthenticated health endpoint.
    async fn detect(&self) -> Result<Server, anyhow::Error> {
        let response = self
            .http
            .get(format!("{}/api/", self.base))
            .timeout(self.timeout)
            .send()
            .await?;
        let status = response.status();
        let body: Option<serde_json::Value> = response.json().await.ok();

        match body.as_ref().and_then(Server::from_health) {
            Some(server) if status.is_success() => Ok(server),
            _ => {
                let message = if status == StatusCode::BAD_REQUEST && self.base.starts_with("http://") {
                    "the server expects https - NPMplus serves its api over https, use an https:// url"
                        .to_string()
                } else {
                    format!(
                        "{} did not answer like nginx proxy manager or NPMplus (status {status}) - check the url",
                        self.base
                    )
                };
                anyhow::bail!(NpmError {
                    status,
                    message,
                    detail: None,
                })
            }
        }
    }

    async fn session(&self, force_refresh: bool) -> Result<Session, anyhow::Error> {
        if !force_refresh
            && let Some(cached) = SESSION_CACHE.lock().await.get(&self.cache_key)
            && cached.expires > Utc::now() + chrono::Duration::seconds(60)
        {
            return Ok(cached.clone());
        }

        let server = self.detect().await?;
        let response = self
            .http
            .post(format!("{}/api/tokens", self.base))
            .timeout(self.timeout)
            .json(&serde_json::json!({ "identity": self.identity, "secret": self.secret }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Self::error_from(response).await.into());
        }

        let set_cookies: Vec<String> = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect();
        let body: serde_json::Value = response.json().await?;
        let auth = parse_login(&body, set_cookies.iter().map(String::as_str))?;
        let expires = body["expires"]
            .as_str()
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));

        let session = Session {
            auth,
            server,
            expires,
        };
        SESSION_CACHE
            .lock()
            .await
            .insert(self.cache_key.clone(), session.clone());
        Ok(session)
    }

    /// The proxy manager flavor and version. Logs in when needed.
    pub async fn server(&self) -> Result<Server, anyhow::Error> {
        Ok(self.session(false).await?.server)
    }

    async fn error_from(response: reqwest::Response) -> NpmError {
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or_default();
        let error = &body["error"];

        NpmError {
            status,
            message: error["message"]
                .as_str()
                .or_else(|| error.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("request failed with status {status}")),
            detail: body["debug"]["stack"]
                .as_array()
                .map(|lines| {
                    lines
                        .iter()
                        .filter_map(|line| line.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .or_else(|| error["output"].as_str().map(str::to_string))
                .filter(|detail| !detail.is_empty()),
        }
    }

    /// Sends an authenticated request. Retries once on a stale pooled
    /// connection (nginx drops idle keep-alive sockets) and once with a fresh
    /// session on 401.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: &Body,
        timeout: Duration,
    ) -> Result<reqwest::Response, anyhow::Error> {
        let mut refreshed = false;
        let mut reconnected = false;

        loop {
            let session = self.session(refreshed).await?;
            let mut request = self
                .http
                .request(method.clone(), format!("{}{path}", self.base))
                .timeout(timeout);
            request = match session.auth {
                Auth::Bearer(token) => request.bearer_auth(token),
                Auth::Cookie(cookies) => request.header(reqwest::header::COOKIE, cookies),
            };
            request = match body {
                Body::None => request,
                Body::Json(json) => request.json(json),
                Body::Multipart(multipart) => request
                    .header(reqwest::header::CONTENT_TYPE, multipart.content_type())
                    .body(multipart.build()),
            };

            match request.send().await {
                Err(err) if err.is_request() && !err.is_timeout() && !reconnected => {
                    reconnected = true;
                }
                Err(err) => return Err(err.into()),
                Ok(response) if response.status() == StatusCode::UNAUTHORIZED && !refreshed => {
                    refreshed = true;
                }
                Ok(response) => return Ok(response),
            }
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Body,
    ) -> Result<T, anyhow::Error> {
        self.call_with_timeout(method, path, body, self.timeout)
            .await
    }

    async fn call_with_timeout<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Body,
        timeout: Duration,
    ) -> Result<T, anyhow::Error> {
        let response = self.send(method, path, &body, timeout).await?;
        if !response.status().is_success() {
            return Err(Self::error_from(response).await.into());
        }
        Ok(response.json().await?)
    }

    /// Like [`Self::call`] but maps 404 to `None`.
    async fn call_optional<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Body,
    ) -> Result<Option<T>, anyhow::Error> {
        let response = self.send(method, path, &body, self.timeout).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(Self::error_from(response).await.into());
        }
        Ok(Some(response.json().await?))
    }

    // --- general ---

    pub async fn me(&self) -> Result<NpmUser, anyhow::Error> {
        self.call(Method::GET, "/api/users/me", Body::None).await
    }

    // --- proxy hosts ---

    pub async fn proxy_hosts(&self) -> Result<Vec<NpmProxyHost>, anyhow::Error> {
        self.call(Method::GET, "/api/nginx/proxy-hosts", Body::None)
            .await
    }

    pub async fn proxy_host(&self, id: i64) -> Result<Option<NpmProxyHost>, anyhow::Error> {
        self.call_optional(
            Method::GET,
            &format!("/api/nginx/proxy-hosts/{id}"),
            Body::None,
        )
        .await
    }

    pub async fn create_proxy_host(
        &self,
        payload: &HostPayload,
    ) -> Result<NpmProxyHost, anyhow::Error> {
        let body = payload.body(&self.server().await?)?;
        self.call(Method::POST, "/api/nginx/proxy-hosts", Body::Json(body))
            .await
    }

    pub async fn update_proxy_host(
        &self,
        id: i64,
        payload: &HostPayload,
    ) -> Result<NpmProxyHost, anyhow::Error> {
        let body = payload.body(&self.server().await?)?;
        self.call(
            Method::PUT,
            &format!("/api/nginx/proxy-hosts/{id}"),
            Body::Json(body),
        )
        .await
    }

    /// `false` when the host was already gone.
    pub async fn delete_proxy_host(&self, id: i64) -> Result<bool, anyhow::Error> {
        Ok(self
            .call_optional::<serde_json::Value>(
                Method::DELETE,
                &format!("/api/nginx/proxy-hosts/{id}"),
                Body::None,
            )
            .await?
            .is_some())
    }

    pub async fn set_proxy_host_enabled(&self, id: i64, enabled: bool) -> Result<(), anyhow::Error> {
        let action = if enabled { "enable" } else { "disable" };
        let response = self
            .send(
                Method::POST,
                &format!("/api/nginx/proxy-hosts/{id}/{action}"),
                &Body::None,
                self.timeout,
            )
            .await?;
        // enabling an enabled host (or vice versa) is a 400 "already ..." -
        // the desired state is reached either way
        if response.status().is_success() || response.status() == StatusCode::BAD_REQUEST {
            return Ok(());
        }
        Err(Self::error_from(response).await.into())
    }

    // --- certificates ---

    pub async fn certificates(&self) -> Result<Vec<NpmCertificate>, anyhow::Error> {
        self.call(Method::GET, "/api/nginx/certificates", Body::None)
            .await
    }

    /// Certificates plus the ids of the hosts using each of them.
    pub async fn certificate_usage(&self) -> Result<HashMap<i64, Vec<i64>>, anyhow::Error> {
        let mut usage: HashMap<i64, Vec<i64>> = HashMap::new();
        for host in self.proxy_hosts().await? {
            if host.certificate_id > 0 {
                usage.entry(host.certificate_id).or_default().push(host.id);
            }
        }
        Ok(usage)
    }

    /// Synchronous Let's Encrypt issuance, over HTTP-01 unless a DNS
    /// challenge is given.
    pub async fn create_letsencrypt_certificate(
        &self,
        domain: &str,
        dns_challenge: Option<&DnsChallenge>,
    ) -> Result<NpmCertificate, anyhow::Error> {
        let body = match self.server().await? {
            Server::Npm(version) => {
                let email = if version.modern_certificate_meta() {
                    String::new()
                } else {
                    self.me().await?.email.unwrap_or_default()
                };
                serde_json::json!({
                    "provider": "letsencrypt",
                    "domain_names": [domain],
                    "meta": letsencrypt_meta(&version, &email, dns_challenge),
                })
            }
            Server::NpmPlus(_) => {
                let dns_columns = match dns_challenge {
                    Some(_) => self.npmplus_dns_columns().await?,
                    None => false,
                };
                npmplus_letsencrypt_body(domain, dns_challenge, dns_columns)
            }
        };

        self.call_with_timeout(
            Method::POST,
            "/api/nginx/certificates",
            Body::Json(body),
            ISSUANCE_TIMEOUT,
        )
        .await
    }

    /// Whether this NPMplus takes DNS challenge settings as top-level
    /// `npmplus_*` fields (instead of `meta`), read from its api schema.
    async fn npmplus_dns_columns(&self) -> Result<bool, anyhow::Error> {
        let response = self
            .send(Method::GET, "/api/schema", &Body::None, self.timeout)
            .await?;
        if !response.status().is_success() {
            return Err(Self::error_from(response).await.into());
        }
        Ok(response.text().await?.contains("\"npmplus_dns_challenge\""))
    }

    pub async fn renew_certificate(&self, id: i64) -> Result<NpmCertificate, anyhow::Error> {
        self.call_with_timeout(
            Method::POST,
            &format!("/api/nginx/certificates/{id}/renew"),
            Body::None,
            ISSUANCE_TIMEOUT,
        )
        .await
    }

    /// Validates, creates and uploads a custom certificate. The empty shell is
    /// removed again when the upload fails.
    pub async fn create_custom_certificate(
        &self,
        nice_name: &str,
        domain: &str,
        certificate: &str,
        certificate_key: &str,
        intermediate: Option<&str>,
    ) -> Result<NpmCertificate, anyhow::Error> {
        // NPMplus only accepts `certificate` and `certificate_key` and stores
        // the certificate as the full chain
        let chained;
        let (certificate, intermediate) = match intermediate {
            Some(intermediate) if self.server().await?.is_npmplus() => {
                chained = format!("{}\n{}\n", certificate.trim_end(), intermediate.trim());
                (chained.as_str(), None)
            }
            _ => (certificate, intermediate),
        };

        let files = || {
            let mut body = MultipartBody::new()
                .file("certificate", "certificate.pem", certificate.as_bytes())
                .file("certificate_key", "certificate_key.pem", certificate_key.as_bytes());
            if let Some(intermediate) = intermediate {
                body = body.file(
                    "intermediate_certificate",
                    "intermediate.pem",
                    intermediate.as_bytes(),
                );
            }
            body
        };

        let _: serde_json::Value = self
            .call(
                Method::POST,
                "/api/nginx/certificates/validate",
                Body::Multipart(files()),
            )
            .await?;

        let shell: NpmCertificate = self
            .call(
                Method::POST,
                "/api/nginx/certificates",
                Body::Json(serde_json::json!({
                    "provider": "other",
                    "nice_name": nice_name,
                    "domain_names": [domain],
                })),
            )
            .await?;

        let uploaded: Result<serde_json::Value, _> = self
            .call(
                Method::POST,
                &format!("/api/nginx/certificates/{}/upload", shell.id),
                Body::Multipart(files()),
            )
            .await;
        if let Err(err) = uploaded {
            if let Err(cleanup) = self.delete_certificate(shell.id).await {
                tracing::warn!(certificate = shell.id, "failed to remove certificate shell: {cleanup:?}");
            }
            return Err(err);
        }

        // the upload response carries no expiry - read the stored row
        Ok(self
            .call_optional(
                Method::GET,
                &format!("/api/nginx/certificates/{}", shell.id),
                Body::None,
            )
            .await?
            .unwrap_or(shell))
    }

    /// `false` when the certificate was already gone.
    pub async fn delete_certificate(&self, id: i64) -> Result<bool, anyhow::Error> {
        Ok(self
            .call_optional::<serde_json::Value>(
                Method::DELETE,
                &format!("/api/nginx/certificates/{id}"),
                Body::None,
            )
            .await?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_uses_token_or_cookies() {
        let npm = parse_login(&serde_json::json!({"token": "abc", "expires": "x"}), std::iter::empty());
        assert_eq!(npm.unwrap(), Auth::Bearer("abc".into()));

        let plus = parse_login(
            &serde_json::json!({"expires": "x"}),
            [
                "__Host-Http-token=s%3Aabc.sig; Path=/; Expires=Tue, 29 Sep 2026 17:08:02 GMT; HttpOnly; Secure; SameSite=Strict",
                "other=1",
            ]
            .into_iter(),
        );
        assert_eq!(
            plus.unwrap(),
            Auth::Cookie("__Host-Http-token=s%3Aabc.sig; other=1".into())
        );

        assert!(parse_login(&serde_json::json!({"expires": "x"}), std::iter::empty()).is_err());
        for challenge in [
            serde_json::json!({"requires_2fa": true, "challenge_token": "c"}),
            serde_json::json!({"requiresTotp": true, "expires": "x"}),
        ] {
            let err = parse_login(&challenge, ["a=b"].into_iter()).unwrap_err();
            assert!(readable_error(&err).contains("two-factor"));
        }
    }

    fn env(key: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| panic!("set {key} to run the npm integration test"))
    }

    fn self_signed(domain: &str) -> (String, String) {
        let dir = std::env::temp_dir().join(format!("rpm-itest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let status = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj"])
            .arg(format!("/CN={domain}"))
            .arg("-keyout")
            .arg(dir.join("key.pem"))
            .arg("-out")
            .arg(dir.join("cert.pem"))
            .output()
            .unwrap();
        assert!(status.status.success());
        let pair = (
            std::fs::read_to_string(dir.join("cert.pem")).unwrap(),
            std::fs::read_to_string(dir.join("key.pem")).unwrap(),
        );
        std::fs::remove_dir_all(dir).ok();
        pair
    }

    /// End-to-end check against a disposable NPM or NPMplus instance. Run with
    /// `NPM_TEST_URL=.. NPM_TEST_IDENTITY=.. NPM_TEST_SECRET=.. cargo test -p
    /// dev_caloptreyx_reverseproxy -- --ignored npm_integration --nocapture`;
    /// set `NPM_TEST_INSECURE=1` for NPMplus's self-signed certificate.
    #[tokio::test]
    #[ignore = "requires a disposable nginx proxy manager instance"]
    async fn npm_integration() {
        use crate::rules::marker;

        let client = NpmClient::new(
            &env("NPM_TEST_URL"),
            &env("NPM_TEST_IDENTITY"),
            &env("NPM_TEST_SECRET"),
            Duration::from_secs(30),
            std::env::var("NPM_TEST_INSECURE").is_ok_and(|value| value == "1"),
        )
        .unwrap();
        let server = client.server().await.unwrap();
        println!("{server}, user {:?}", client.me().await.unwrap().email);

        let domain = format!("itest-{}.example.com", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let proxy_uuid = uuid::Uuid::new_v4();
        let mut payload = HostPayload {
            domain_names: vec![domain.clone()],
            forward_scheme: "http".into(),
            forward_host: "127.0.0.1".into(),
            forward_port: 8080,
            certificate_id: 0,
            ssl_forced: false,
            caching_enabled: false,
            block_exploits: true,
            allow_websocket_upgrade: true,
            http2_support: false,
            hsts_enabled: false,
            hsts_subdomains: false,
            access_list_id: 0,
            advanced_config: crate::rules::nginx::compose_advanced_config(
                &marker::build_marker("itest", proxy_uuid),
                "client_max_body_size 10m;",
            ),
        };

        let host = client.create_proxy_host(&payload).await.unwrap();
        println!("created host {}", host.id);
        let drift = payload.drift(&host, &server);
        assert!(drift.is_empty(), "drift: {drift:?}");
        assert!(marker::marker_matches(&host.advanced_config, "itest", proxy_uuid));
        assert!(host.nginx_error().is_none());

        let (certificate, key) = self_signed(&domain);
        let (intermediate, _) = self_signed("itest-ca.example.com");
        let cert = client
            .create_custom_certificate("calagopus:itest:x", &domain, &certificate, &key, Some(&intermediate))
            .await
            .unwrap();
        println!("custom certificate {} expires {:?}", cert.id, cert.expires_at());
        assert!(cert.expires_at().is_some());

        payload.certificate_id = cert.id;
        payload.ssl_forced = true;
        payload.forward_port = 8081;
        let host = client.update_proxy_host(host.id, &payload).await.unwrap();
        let drift = payload.drift(&host, &server);
        assert!(drift.is_empty(), "drift: {drift:?}");

        client.set_proxy_host_enabled(host.id, false).await.unwrap();
        client.set_proxy_host_enabled(host.id, false).await.unwrap();
        assert!(!client.proxy_host(host.id).await.unwrap().unwrap().enabled);
        client.set_proxy_host_enabled(host.id, true).await.unwrap();

        let bad = client
            .create_custom_certificate("calagopus:itest:y", &domain, "garbage", "garbage", None)
            .await
            .unwrap_err();
        println!("invalid certificate: {}", readable_error(&bad));

        // both fail here (no public reachability / fake token); a rejected
        // request shape would fail validation instead of reaching certbot
        let failed = client
            .create_letsencrypt_certificate(&domain, None)
            .await
            .unwrap_err();
        println!("le failure: {}", readable_error(&failed));
        let dns = DnsChallenge::cloudflare("itest-invalid-token", 0);
        let failed = client
            .create_letsencrypt_certificate(&domain, Some(&dns))
            .await
            .unwrap_err();
        println!("le dns failure: {}", readable_error(&failed));
        assert!(!readable_error(&failed).contains("additional properties"));

        assert!(client.delete_proxy_host(host.id).await.unwrap());
        assert!(!client.delete_proxy_host(host.id).await.unwrap());
        assert!(client.delete_certificate(cert.id).await.unwrap());
        assert!(client.proxy_host(host.id).await.unwrap().is_none());
    }
}
