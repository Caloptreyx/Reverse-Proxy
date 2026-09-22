use chrono::{DateTime, Utc};
use shared::database::Database;

/// Ledger of Let's Encrypt attempts (issuance and renewal, success or
/// failure) used for rate-limit protection.
pub struct Issuance;

impl Issuance {
    pub async fn record(database: &Database, domain: &str, success: bool) {
        if let Err(err) = sqlx::query(
            "INSERT INTO dev_caloptreyx_reverseproxy_issuances (domain, success) VALUES ($1, $2)",
        )
        .bind(domain)
        .bind(success)
        .execute(database.write())
        .await
        {
            tracing::warn!(domain, "failed to record issuance attempt: {err:?}");
        }
    }

    /// `(attempts in the last hour, attempts for domain in the last week)`.
    pub async fn windows(
        database: &Database,
        domain: &str,
    ) -> Result<(Vec<DateTime<Utc>>, Vec<DateTime<Utc>>), sqlx::Error> {
        let hour = sqlx::query_scalar(
            "SELECT created FROM dev_caloptreyx_reverseproxy_issuances
             WHERE created > now() - interval '1 hour'",
        )
        .fetch_all(database.read())
        .await?;
        let week = sqlx::query_scalar(
            "SELECT created FROM dev_caloptreyx_reverseproxy_issuances
             WHERE domain = $1 AND created > now() - interval '7 days'",
        )
        .bind(domain)
        .fetch_all(database.read())
        .await?;
        Ok((hour, week))
    }

    /// Drops ledger rows no window looks at any more.
    pub async fn prune(database: &Database) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM dev_caloptreyx_reverseproxy_issuances WHERE created < now() - interval '8 days'",
        )
        .execute(database.write())
        .await?;
        Ok(())
    }
}
