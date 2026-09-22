//! Drift detection between the panel and NPM, and fixes for it.
use super::{Ctx, hosts, invalid, target, wake_worker};
use crate::{
    db::{CertificateMode, CleanupJob, CleanupTask, Proxy, ProxyStatus},
    npm::{HostPayload, NpmCertificate, NpmClient, NpmProxyHost},
    rules::marker,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(ToSchema, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum ReconcileKind {
    /// No linked host, or the linked host is gone / no longer ours.
    MissingHost,
    /// The host is ours but fields diverged from the panel.
    Drift(Vec<String>),
    /// A host carrying this panel's marker that no proxy claims.
    OrphanHost,
    /// A certificate this panel created that no proxy uses any more.
    OrphanCertificate,
    /// The proxy references a certificate that no longer exists.
    MissingCertificate,
}

#[derive(ToSchema, Serialize, Debug)]
pub struct ReconcileItem {
    /// Stable id accepted by the fix endpoint.
    pub id: String,
    pub kind: ReconcileKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_uuid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm_proxy_host_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm_certificate_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub message: String,
}

/// What the panel expects for one proxy.
pub struct Expected {
    pub proxy_uuid: Uuid,
    pub domain: String,
    pub host_id: Option<i64>,
    pub certificate_id: Option<i64>,
    /// `None` when the proxy has no allocation (its host may legitimately be
    /// disabled or missing).
    pub desired: Option<HostPayload>,
}

/// Pure comparison of the expected state with what NPM reports.
pub fn diff(
    instance_id: &str,
    expected: &[Expected],
    hosts: &[NpmProxyHost],
    certificates: &[NpmCertificate],
    owned_certificate_ids: &HashSet<i64>,
) -> Vec<ReconcileItem> {
    let mut items = Vec::new();
    let hosts_by_id: HashMap<i64, &NpmProxyHost> = hosts.iter().map(|host| (host.id, host)).collect();
    let certificate_ids: HashSet<i64> = certificates.iter().map(|cert| cert.id).collect();
    let claimed_proxies: HashSet<Uuid> = expected.iter().map(|e| e.proxy_uuid).collect();
    let used_certificates: HashSet<i64> = expected
        .iter()
        .filter_map(|e| e.certificate_id)
        .chain(hosts.iter().map(|host| host.certificate_id))
        .collect();

    for proxy in expected {
        let item = |kind: ReconcileKind, message: String| ReconcileItem {
            id: format!("{}:{}", kind_id(&kind), proxy.proxy_uuid),
            kind,
            proxy_uuid: Some(proxy.proxy_uuid),
            npm_proxy_host_id: proxy.host_id,
            npm_certificate_id: proxy.certificate_id,
            domain: Some(proxy.domain.clone()),
            message,
        };

        if let Some(desired) = &proxy.desired {
            let host = proxy.host_id.and_then(|id| hosts_by_id.get(&id).copied());
            match host {
                None => items.push(item(
                    ReconcileKind::MissingHost,
                    match proxy.host_id {
                        Some(id) => format!("proxy host {id} no longer exists"),
                        None => "no proxy host exists yet".to_string(),
                    },
                )),
                Some(host)
                    if !marker::marker_matches(&host.advanced_config, instance_id, proxy.proxy_uuid) =>
                {
                    items.push(item(
                        ReconcileKind::MissingHost,
                        format!("proxy host {} is no longer owned by this panel", host.id),
                    ))
                }
                Some(host) => {
                    let fields = desired.drift(host);
                    if !fields.is_empty() {
                        items.push(item(
                            ReconcileKind::Drift(fields.iter().map(|f| f.to_string()).collect()),
                            format!("proxy host {} differs: {}", host.id, fields.join(", ")),
                        ));
                    }
                }
            }
        }

        if let Some(id) = proxy.certificate_id
            && !certificate_ids.contains(&id)
        {
            items.push(item(
                ReconcileKind::MissingCertificate,
                format!("certificate {id} no longer exists"),
            ));
        }
    }

    for host in hosts {
        if let Some((instance, proxy_uuid)) = marker::parse_marker(&host.advanced_config)
            && instance == instance_id
            && !claimed_proxies.contains(&proxy_uuid)
        {
            items.push(ReconcileItem {
                id: format!("orphan_host:{}", host.id),
                kind: ReconcileKind::OrphanHost,
                proxy_uuid: Some(proxy_uuid),
                npm_proxy_host_id: Some(host.id),
                npm_certificate_id: None,
                domain: host.domain_names.first().cloned(),
                message: format!("proxy host {} belongs to a proxy that no longer exists", host.id),
            });
        }
    }

    for certificate in certificates {
        let ours = marker::is_owned_cert_nice_name(&certificate.nice_name, instance_id)
            || owned_certificate_ids.contains(&certificate.id);
        if ours && !used_certificates.contains(&certificate.id) {
            items.push(ReconcileItem {
                id: format!("orphan_certificate:{}", certificate.id),
                kind: ReconcileKind::OrphanCertificate,
                proxy_uuid: None,
                npm_proxy_host_id: None,
                npm_certificate_id: Some(certificate.id),
                domain: certificate.domain_names.first().cloned(),
                message: format!("certificate {} is not used by any proxy", certificate.id),
            });
        }
    }

    items
}

fn kind_id(kind: &ReconcileKind) -> &'static str {
    match kind {
        ReconcileKind::MissingHost => "missing_host",
        ReconcileKind::Drift(_) => "drift",
        ReconcileKind::OrphanHost => "orphan_host",
        ReconcileKind::OrphanCertificate => "orphan_certificate",
        ReconcileKind::MissingCertificate => "missing_certificate",
    }
}

/// Everything a reconcile pass looks at.
pub struct Snapshot {
    pub hosts: Vec<NpmProxyHost>,
    pub certificates: Vec<NpmCertificate>,
    pub items: Vec<ReconcileItem>,
}

pub async fn snapshot(ctx: &Ctx, client: &NpmClient) -> Result<Snapshot, anyhow::Error> {
    let hosts = client.proxy_hosts().await?;
    let certificates = client.certificates().await?;

    let mut expected = Vec::new();
    let mut owned_certificate_ids = HashSet::new();
    for proxy in Proxy::all(ctx.db()).await? {
        let desired = match proxy.allocation_uuid {
            Some(allocation_uuid) => match target::resolve(ctx, proxy.server_uuid, allocation_uuid).await {
                Ok(target) => Some(hosts::desired(ctx, &proxy, &target)),
                Err(err) => {
                    tracing::warn!(proxy = %proxy.uuid, "cannot resolve forward target: {err:?}");
                    None
                }
            },
            None => None,
        };
        if proxy.certificate_owned
            && let Some(id) = proxy.certificate_id()
        {
            owned_certificate_ids.insert(id);
        }
        expected.push(Expected {
            proxy_uuid: proxy.uuid,
            domain: proxy.domain.clone(),
            host_id: proxy.host_id(),
            certificate_id: proxy.certificate_id(),
            desired,
        });
    }

    // certificates queued for deletion are ours as well
    for task in CleanupTask::all(ctx.db()).await? {
        if let Some(CleanupJob::Certificate { id }) = task.job() {
            owned_certificate_ids.insert(id);
        }
    }

    let items = diff(&ctx.instance_id, &expected, &hosts, &certificates, &owned_certificate_ids);
    Ok(Snapshot {
        hosts,
        certificates,
        items,
    })
}

/// Fixes one reported item by id.
pub async fn fix(ctx: &Ctx, client: &NpmClient, id: &str) -> Result<(), anyhow::Error> {
    let (kind, key) = id
        .split_once(':')
        .ok_or_else(|| invalid(format!("unknown reconcile item `{id}`")))?;

    let load = || async {
        let uuid: Uuid = key.parse().map_err(|_| invalid("invalid proxy id"))?;
        Proxy::by_uuid(ctx.db(), uuid)
            .await?
            .ok_or_else(|| invalid("the proxy no longer exists"))
    };
    let number = || key.parse::<i64>().map_err(|_| invalid("invalid id"));

    match kind {
        "missing_host" | "drift" => {
            let mut proxy = load().await?;
            if kind == "missing_host"
                && hosts::owned(ctx, client, &proxy).await?.is_none()
            {
                proxy.npm_proxy_host_id = None;
            }
            hosts::push(ctx, client, &mut proxy).await?;
            proxy.save_state(ctx.db()).await?;
        }
        "missing_certificate" => {
            let mut proxy = load().await?;
            proxy.detach_certificate();
            match proxy.certificate_mode {
                CertificateMode::Letsencrypt => {
                    proxy.schedule_now(ProxyStatus::Issuing, None);
                    wake_worker();
                }
                CertificateMode::Custom => proxy.set_status(
                    ProxyStatus::Failed,
                    Some("The certificate was removed from the proxy manager - upload a new one.".into()),
                ),
            }
            hosts::push(ctx, client, &mut proxy).await?;
            proxy.save_state(ctx.db()).await?;
        }
        "orphan_host" => {
            let id = number()?;
            let host = client
                .proxy_host(id)
                .await?
                .ok_or_else(|| invalid("the proxy host no longer exists"))?;
            let (instance, proxy_uuid) = marker::parse_marker(&host.advanced_config)
                .filter(|(instance, _)| *instance == ctx.instance_id)
                .ok_or_else(|| invalid("this proxy host is not owned by this panel"))?;
            debug_assert_eq!(instance, ctx.instance_id);
            if Proxy::by_uuid(ctx.db(), proxy_uuid).await?.is_some() {
                return Err(invalid("this proxy host is still in use"));
            }
            hosts::execute(ctx, Some(client), &CleanupJob::ProxyHost { id, proxy_uuid }).await?;
        }
        "orphan_certificate" => {
            let id = number()?;
            let snapshot = snapshot(ctx, client).await?;
            if !snapshot.items.iter().any(|item| item.id == format!("orphan_certificate:{id}")) {
                return Err(invalid("this certificate is not an orphan owned by this panel"));
            }
            hosts::execute(ctx, Some(client), &CleanupJob::Certificate { id }).await?;
        }
        _ => return Err(invalid(format!("unknown reconcile item `{id}`"))),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCE: &str = "inst1";

    fn payload(domain: &str, proxy: Uuid, port: i32) -> HostPayload {
        HostPayload {
            domain_names: vec![domain.into()],
            forward_scheme: "http".into(),
            forward_host: "10.0.0.1".into(),
            forward_port: port,
            certificate_id: 0,
            ssl_forced: false,
            caching_enabled: false,
            block_exploits: true,
            allow_websocket_upgrade: true,
            http2_support: false,
            hsts_enabled: false,
            hsts_subdomains: false,
            access_list_id: 0,
            advanced_config: marker::build_marker(INSTANCE, proxy),
        }
    }

    fn host(id: i64, payload: &HostPayload) -> NpmProxyHost {
        let mut value = serde_json::to_value(payload).unwrap();
        value["id"] = id.into();
        value["enabled"] = true.into();
        serde_json::from_value(value).unwrap()
    }

    fn cert(id: i64, nice_name: &str) -> NpmCertificate {
        serde_json::from_value(serde_json::json!({"id": id, "nice_name": nice_name})).unwrap()
    }

    fn expected(uuid: Uuid, host_id: Option<i64>, desired: Option<HostPayload>) -> Expected {
        Expected {
            proxy_uuid: uuid,
            domain: "a.example.com".into(),
            host_id,
            certificate_id: None,
            desired,
        }
    }

    #[test]
    fn in_sync_reports_nothing() {
        let uuid = Uuid::new_v4();
        let desired = payload("a.example.com", uuid, 80);
        let items = diff(
            INSTANCE,
            &[expected(uuid, Some(1), Some(desired.clone()))],
            &[host(1, &desired)],
            &[],
            &HashSet::new(),
        );
        assert!(items.is_empty(), "{items:?}");
    }

    #[test]
    fn missing_foreign_and_drifted_hosts() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let foreign = payload("b.example.com", Uuid::new_v4(), 80);
        let drifted = payload("c.example.com", c, 80);
        let items = diff(
            INSTANCE,
            &[
                expected(a, Some(9), Some(payload("a.example.com", a, 80))),
                expected(b, Some(2), Some(payload("b.example.com", b, 80))),
                expected(c, Some(3), Some(payload("c.example.com", c, 8080))),
            ],
            &[host(2, &foreign), host(3, &drifted)],
            &[],
            &HashSet::new(),
        );
        let ids: Vec<_> = items.iter().map(|i| i.id.clone()).collect();
        assert!(ids.contains(&format!("missing_host:{a}")));
        assert!(ids.contains(&format!("missing_host:{b}")));
        assert!(ids.contains(&format!("drift:{c}")));
        let drift = items.iter().find(|i| i.id == format!("drift:{c}")).unwrap();
        assert_eq!(drift.kind, ReconcileKind::Drift(vec!["forward_port".into()]));
    }

    #[test]
    fn proxies_without_allocation_are_not_missing() {
        let uuid = Uuid::new_v4();
        let items = diff(INSTANCE, &[expected(uuid, None, None)], &[], &[], &HashSet::new());
        assert!(items.is_empty());
    }

    #[test]
    fn orphans_only_for_this_instance() {
        let ours = payload("x.example.com", Uuid::new_v4(), 80);
        let mut other = payload("y.example.com", Uuid::new_v4(), 80);
        other.advanced_config = marker::build_marker("other", Uuid::new_v4());
        let mut unmarked = payload("z.example.com", Uuid::new_v4(), 80);
        unmarked.advanced_config = String::new();

        let items = diff(
            INSTANCE,
            &[],
            &[host(1, &ours), host(2, &other), host(3, &unmarked)],
            &[
                cert(10, &marker::cert_nice_name(INSTANCE, Uuid::new_v4())),
                cert(11, &marker::cert_nice_name("other", Uuid::new_v4())),
                cert(12, "someone's cert"),
                cert(13, "le cert"),
            ],
            &HashSet::from([13]),
        );
        let ids: Vec<_> = items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["orphan_host:1", "orphan_certificate:10", "orphan_certificate:13"]
        );
    }

    #[test]
    fn certificates_in_use_by_hosts_are_not_orphans() {
        let mut desired = payload("x.example.com", Uuid::new_v4(), 80);
        desired.advanced_config = String::new();
        desired.certificate_id = 10;
        let items = diff(
            INSTANCE,
            &[],
            &[host(1, &desired)],
            &[cert(10, &marker::cert_nice_name(INSTANCE, Uuid::new_v4()))],
            &HashSet::new(),
        );
        assert!(items.is_empty(), "{items:?}");
    }

    #[test]
    fn missing_certificate() {
        let uuid = Uuid::new_v4();
        let mut entry = expected(uuid, None, None);
        entry.certificate_id = Some(5);
        let items = diff(INSTANCE, &[entry], &[], &[], &HashSet::new());
        assert_eq!(items[0].id, format!("missing_certificate:{uuid}"));
    }
}
