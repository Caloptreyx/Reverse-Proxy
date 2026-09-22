use super::text_enum;
use crate::dns::StoredRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::{database::Database, models::Pagination};
use sqlx::types::{Json, ipnetwork::IpNetwork};
use utoipa::ToSchema;
use uuid::Uuid;

text_enum!(ProxyStatus {
    PendingDns => "pending_dns",
    Issuing => "issuing",
    Live => "live",
    Failed => "failed",
});

text_enum!(CertificateMode {
    Letsencrypt => "letsencrypt",
    Custom => "custom",
});

/// User-facing proxy options, stored as individual columns.
#[derive(sqlx::FromRow, ToSchema, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyFlags {
    pub websockets: bool,
    pub caching: bool,
    pub http2: bool,
    pub hsts: bool,
    pub hsts_subdomains: bool,
    pub force_https: bool,
    pub block_exploits: bool,
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct Proxy {
    pub uuid: Uuid,
    pub server_uuid: Uuid,
    pub allocation_uuid: Option<Uuid>,
    pub domain: String,
    pub managed_domain_uuid: Option<Uuid>,
    pub managed_name: Option<String>,
    pub managed_dns_records: Json<Vec<StoredRecord>>,
    pub forward_scheme: String,
    #[sqlx(flatten)]
    pub flags: ProxyFlags,
    pub advanced_config: String,
    pub certificate_mode: CertificateMode,
    pub status: ProxyStatus,
    pub status_message: Option<String>,
    pub npm_proxy_host_id: Option<i32>,
    pub npm_certificate_id: Option<i32>,
    pub certificate_owned: bool,
    pub certificate_expires: Option<DateTime<Utc>>,
    pub issue_attempts: i32,
    pub last_attempt: Option<DateTime<Utc>>,
    pub next_attempt: Option<DateTime<Utc>>,
    pub last_synced: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
}

impl Proxy {
    pub fn host_id(&self) -> Option<i64> {
        self.npm_proxy_host_id.map(i64::from)
    }

    pub fn certificate_id(&self) -> Option<i64> {
        self.npm_certificate_id.map(i64::from)
    }

    pub fn set_status(&mut self, status: ProxyStatus, message: Option<String>) {
        self.status = status;
        self.status_message = message;
    }

    /// Queue for the issuance worker right away.
    pub fn schedule_now(&mut self, status: ProxyStatus, message: Option<String>) {
        self.set_status(status, message);
        self.next_attempt = Some(Utc::now());
    }

    pub fn attach_certificate(
        &mut self,
        id: i64,
        owned: bool,
        expires: Option<DateTime<Utc>>,
    ) {
        self.npm_certificate_id = i32::try_from(id).ok();
        self.certificate_owned = owned;
        self.certificate_expires = expires;
    }

    pub fn detach_certificate(&mut self) {
        self.npm_certificate_id = None;
        self.certificate_owned = false;
        self.certificate_expires = None;
    }
}

/// Values for a new proxy row.
pub struct NewProxy<'a> {
    pub server_uuid: Uuid,
    pub allocation_uuid: Uuid,
    pub domain: &'a str,
    pub managed_domain_uuid: Option<Uuid>,
    pub managed_name: Option<&'a str>,
    pub forward_scheme: &'a str,
    pub flags: ProxyFlags,
    pub advanced_config: &'a str,
    pub certificate_mode: CertificateMode,
}

const TABLE: &str = "dev_caloptreyx_reverseproxy_proxies";

const JOINED_SELECT: &str = "
    SELECT p.*, sv.name AS server_name, u.username AS owner_username,
           na.ip AS alloc_ip, na.ip_alias AS alloc_ip_alias, na.port AS alloc_port,
           COUNT(*) OVER() AS total_count
    FROM dev_caloptreyx_reverseproxy_proxies p
    JOIN servers sv ON sv.uuid = p.server_uuid
    JOIN users u ON u.uuid = sv.owner_uuid
    LEFT JOIN server_allocations sa ON sa.uuid = p.allocation_uuid
    LEFT JOIN node_allocations na ON na.uuid = sa.allocation_uuid";

impl Proxy {
    pub async fn by_uuid(database: &Database, uuid: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE} WHERE uuid = $1"
        )))
        .bind(uuid)
        .fetch_optional(database.read())
        .await
    }

    pub async fn by_server_uuid_uuid(
        database: &Database,
        server_uuid: Uuid,
        uuid: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE} WHERE server_uuid = $1 AND uuid = $2"
        )))
        .bind(server_uuid)
        .bind(uuid)
        .fetch_optional(database.read())
        .await
    }

    pub async fn all(database: &Database) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE} ORDER BY created"
        )))
        .fetch_all(database.read())
        .await
    }

    pub async fn all_by_server_uuid(
        database: &Database,
        server_uuid: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE} WHERE server_uuid = $1 ORDER BY created"
        )))
        .bind(server_uuid)
        .fetch_all(database.read())
        .await
    }

    pub async fn all_by_allocation_uuid(
        database: &Database,
        allocation_uuid: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE} WHERE allocation_uuid = $1"
        )))
        .bind(allocation_uuid)
        .fetch_all(database.read())
        .await
    }

    /// Proxies whose next worker attempt is due, oldest first.
    pub async fn due(database: &Database) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT * FROM {TABLE}
             WHERE next_attempt IS NOT NULL AND next_attempt <= now()
             ORDER BY next_attempt"
        )))
        .fetch_all(database.read())
        .await
    }

    pub async fn count_by_server_uuid(
        database: &Database,
        server_uuid: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM {TABLE} WHERE server_uuid = $1"
        )))
        .bind(server_uuid)
        .fetch_one(database.read())
        .await
    }

    pub async fn count_failing(database: &Database) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM {TABLE} WHERE status <> 'live'"
        )))
        .fetch_one(database.read())
        .await
    }

    pub async fn domain_taken(database: &Database, domain: &str) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS(SELECT 1 FROM {TABLE} WHERE domain = $1)"
        )))
        .bind(domain)
        .fetch_one(database.read())
        .await
    }

    pub async fn insert(database: &Database, new: NewProxy<'_>) -> Result<Self, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "INSERT INTO {TABLE}
                 (server_uuid, allocation_uuid, domain, managed_domain_uuid, managed_name,
                  forward_scheme, websockets, caching, http2, hsts, hsts_subdomains,
                  force_https, block_exploits, advanced_config, certificate_mode, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'issuing')
             RETURNING *"
        )))
        .bind(new.server_uuid)
        .bind(new.allocation_uuid)
        .bind(new.domain)
        .bind(new.managed_domain_uuid)
        .bind(new.managed_name)
        .bind(new.forward_scheme)
        .bind(new.flags.websockets)
        .bind(new.flags.caching)
        .bind(new.flags.http2)
        .bind(new.flags.hsts)
        .bind(new.flags.hsts_subdomains)
        .bind(new.flags.force_https)
        .bind(new.flags.block_exploits)
        .bind(new.advanced_config)
        .bind(new.certificate_mode)
        .fetch_one(database.write())
        .await
    }

    /// Persists every mutable column.
    pub async fn save(&self, database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE {TABLE} SET
                 allocation_uuid = $2, managed_dns_records = $3, forward_scheme = $4,
                 websockets = $5, caching = $6, http2 = $7, hsts = $8, hsts_subdomains = $9,
                 force_https = $10, block_exploits = $11, advanced_config = $12,
                 certificate_mode = $13, status = $14, status_message = $15,
                 npm_proxy_host_id = $16, npm_certificate_id = $17, certificate_owned = $18,
                 certificate_expires = $19, issue_attempts = $20, last_attempt = $21,
                 next_attempt = $22, last_synced = $23
             WHERE uuid = $1"
        )))
        .bind(self.uuid)
        .bind(self.allocation_uuid)
        .bind(&self.managed_dns_records)
        .bind(&self.forward_scheme)
        .bind(self.flags.websockets)
        .bind(self.flags.caching)
        .bind(self.flags.http2)
        .bind(self.flags.hsts)
        .bind(self.flags.hsts_subdomains)
        .bind(self.flags.force_https)
        .bind(self.flags.block_exploits)
        .bind(&self.advanced_config)
        .bind(self.certificate_mode)
        .bind(self.status)
        .bind(&self.status_message)
        .bind(self.npm_proxy_host_id)
        .bind(self.npm_certificate_id)
        .bind(self.certificate_owned)
        .bind(self.certificate_expires)
        .bind(self.issue_attempts)
        .bind(self.last_attempt)
        .bind(self.next_attempt)
        .bind(self.last_synced)
        .execute(database.write())
        .await?;
        Ok(())
    }

    /// Persists only the state columns background tasks own, so a long
    /// running issuance never overwrites a concurrent user edit.
    pub async fn save_state(&self, database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE {TABLE} SET
                 status = $2, status_message = $3, npm_proxy_host_id = $4,
                 npm_certificate_id = $5, certificate_owned = $6, certificate_expires = $7,
                 issue_attempts = $8, last_attempt = $9, next_attempt = $10, last_synced = $11
             WHERE uuid = $1"
        )))
        .bind(self.uuid)
        .bind(self.status)
        .bind(&self.status_message)
        .bind(self.npm_proxy_host_id)
        .bind(self.npm_certificate_id)
        .bind(self.certificate_owned)
        .bind(self.certificate_expires)
        .bind(self.issue_attempts)
        .bind(self.last_attempt)
        .bind(self.next_attempt)
        .bind(self.last_synced)
        .execute(database.write())
        .await?;
        Ok(())
    }

    /// Picks up user-editable columns changed since this row was loaded.
    /// Returns `false` when the proxy was deleted meanwhile.
    pub async fn reload_config(&mut self, database: &Database) -> Result<bool, sqlx::Error> {
        let Some(fresh) = Self::by_uuid(database, self.uuid).await? else {
            return Ok(false);
        };
        self.allocation_uuid = fresh.allocation_uuid;
        self.forward_scheme = fresh.forward_scheme;
        self.flags = fresh.flags;
        self.advanced_config = fresh.advanced_config;
        self.certificate_mode = fresh.certificate_mode;
        Ok(true)
    }

    pub async fn delete(&self, database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM {TABLE} WHERE uuid = $1"
        )))
        .bind(self.uuid)
        .execute(database.write())
        .await?;
        Ok(())
    }
}

/// A proxy with the server, owner and allocation data the API needs.
#[derive(sqlx::FromRow)]
pub struct JoinedProxy {
    #[sqlx(flatten)]
    pub proxy: Proxy,
    pub server_name: String,
    pub owner_username: String,
    pub alloc_ip: Option<IpNetwork>,
    pub alloc_ip_alias: Option<String>,
    pub alloc_port: Option<i32>,
    pub total_count: i64,
}

impl JoinedProxy {
    pub async fn by_uuid(database: &Database, uuid: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{JOINED_SELECT} WHERE p.uuid = $1"
        )))
        .bind(uuid)
        .fetch_optional(database.read())
        .await
    }

    pub async fn all_by_server_uuid(
        database: &Database,
        server_uuid: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{JOINED_SELECT} WHERE p.server_uuid = $1 ORDER BY p.created"
        )))
        .bind(server_uuid)
        .fetch_all(database.read())
        .await
    }

    /// Fleet listing searched by domain, server name or owner.
    pub async fn all_with_pagination(
        database: &Database,
        page: i64,
        per_page: i64,
        search: Option<&str>,
        status: Option<ProxyStatus>,
    ) -> Result<Pagination<ApiAdminProxy>, sqlx::Error> {
        let rows: Vec<Self> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{JOINED_SELECT}
             WHERE ($1::text IS NULL
                    OR p.domain ILIKE '%' || $1 || '%'
                    OR sv.name ILIKE '%' || $1 || '%'
                    OR u.username ILIKE '%' || $1 || '%')
               AND ($2::text IS NULL OR p.status = $2)
             ORDER BY p.created LIMIT $3 OFFSET $4"
        )))
        .bind(search)
        .bind(status.map(|status| status.as_str()))
        .bind(per_page)
        .bind(per_page * (page - 1))
        .fetch_all(database.read())
        .await?;

        Ok(Pagination {
            total: rows.first().map_or(0, |row| row.total_count),
            per_page,
            page,
            data: rows.into_iter().map(Self::into_admin_api).collect(),
        })
    }

    pub fn into_api(self) -> ApiProxy {
        let allocation = match (self.proxy.allocation_uuid, self.alloc_ip, self.alloc_port) {
            (Some(uuid), Some(ip), Some(port)) => Some(ApiAllocationRef {
                uuid,
                ip: ip.ip().to_string(),
                ip_alias: self.alloc_ip_alias,
                port,
            }),
            _ => None,
        };
        let proxy = self.proxy;

        ApiProxy {
            uuid: proxy.uuid,
            domain: proxy.domain,
            managed_domain_uuid: proxy.managed_domain_uuid,
            managed_name: proxy.managed_name,
            allocation,
            forward_scheme: proxy.forward_scheme,
            flags: proxy.flags,
            advanced_config: proxy.advanced_config,
            certificate_mode: proxy.certificate_mode,
            status: proxy.status,
            status_message: proxy.status_message,
            certificate_expires: proxy.certificate_expires,
            issue_attempts: proxy.issue_attempts,
            next_attempt: proxy.next_attempt,
            created: proxy.created,
        }
    }

    pub fn into_admin_api(self) -> ApiAdminProxy {
        let server = ApiServerRef {
            uuid: self.proxy.server_uuid,
            name: self.server_name.clone(),
            owner: self.owner_username.clone(),
        };
        ApiAdminProxy {
            proxy: self.into_api(),
            server,
        }
    }
}

#[derive(ToSchema, Serialize)]
pub struct ApiAllocationRef {
    pub uuid: Uuid,
    pub ip: String,
    pub ip_alias: Option<String>,
    pub port: i32,
}

/// A proxy as users see it. NPM ids are never exposed.
#[derive(ToSchema, Serialize)]
pub struct ApiProxy {
    pub uuid: Uuid,
    pub domain: String,
    pub managed_domain_uuid: Option<Uuid>,
    pub managed_name: Option<String>,
    pub allocation: Option<ApiAllocationRef>,
    pub forward_scheme: String,
    #[serde(flatten)]
    #[schema(inline)]
    pub flags: ProxyFlags,
    pub advanced_config: String,
    pub certificate_mode: CertificateMode,
    pub status: ProxyStatus,
    pub status_message: Option<String>,
    pub certificate_expires: Option<DateTime<Utc>>,
    pub issue_attempts: i32,
    pub next_attempt: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
}

#[derive(ToSchema, Serialize)]
pub struct ApiServerRef {
    pub uuid: Uuid,
    pub name: String,
    pub owner: String,
}

#[derive(ToSchema, Serialize)]
pub struct ApiAdminProxy {
    #[serde(flatten)]
    #[schema(inline)]
    pub proxy: ApiProxy,
    pub server: ApiServerRef,
}
