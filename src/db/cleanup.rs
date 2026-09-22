use crate::dns::StoredRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::database::Database;
use sqlx::types::Json;
use utoipa::ToSchema;
use uuid::Uuid;

/// A remote deletion that has to happen even though the proxy row is gone.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CleanupJob {
    /// Only deleted while it still carries this proxy's ownership marker.
    ProxyHost { id: i64, proxy_uuid: Uuid },
    /// Only deleted while no other proxy host uses it.
    Certificate { id: i64 },
    DnsRecord {
        managed_domain_uuid: Uuid,
        record: StoredRecord,
    },
}

impl CleanupJob {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ProxyHost { .. } => "proxy_host",
            Self::Certificate { .. } => "certificate",
            Self::DnsRecord { .. } => "dns_record",
        }
    }
}

/// Retries before a task is left for an admin to look at.
pub const MAX_CLEANUP_ATTEMPTS: i32 = 20;

#[derive(sqlx::FromRow, ToSchema, Serialize)]
pub struct CleanupTask {
    pub uuid: Uuid,
    pub kind: String,
    #[schema(value_type = serde_json::Value)]
    pub payload: Json<serde_json::Value>,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created: DateTime<Utc>,
}

impl CleanupTask {
    pub fn job(&self) -> Option<CleanupJob> {
        serde_json::from_value(self.payload.0.clone()).ok()
    }

    pub async fn queue(database: &Database, job: &CleanupJob, error: &str) {
        let payload = serde_json::to_value(job).unwrap_or_default();
        if let Err(err) = sqlx::query(
            "INSERT INTO dev_caloptreyx_reverseproxy_cleanup (kind, payload, last_error)
             VALUES ($1, $2, $3)",
        )
        .bind(job.kind())
        .bind(Json(payload))
        .bind(error)
        .execute(database.write())
        .await
        {
            tracing::error!(?job, "failed to queue remote cleanup: {err:?}");
        }
    }

    pub async fn all(database: &Database) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM dev_caloptreyx_reverseproxy_cleanup ORDER BY created")
            .fetch_all(database.read())
            .await
    }

    pub async fn pending(database: &Database) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            "SELECT * FROM dev_caloptreyx_reverseproxy_cleanup WHERE attempts < $1 ORDER BY created",
        )
        .bind(MAX_CLEANUP_ATTEMPTS)
        .fetch_all(database.read())
        .await
    }

    pub async fn by_uuid(database: &Database, uuid: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM dev_caloptreyx_reverseproxy_cleanup WHERE uuid = $1")
            .bind(uuid)
            .fetch_optional(database.read())
            .await
    }

    pub async fn fail(&self, database: &Database, error: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE dev_caloptreyx_reverseproxy_cleanup
             SET attempts = attempts + 1, last_error = $2 WHERE uuid = $1",
        )
        .bind(self.uuid)
        .bind(error)
        .execute(database.write())
        .await?;
        Ok(())
    }

    pub async fn delete(&self, database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM dev_caloptreyx_reverseproxy_cleanup WHERE uuid = $1")
            .bind(self.uuid)
            .execute(database.write())
            .await?;
        Ok(())
    }
}
