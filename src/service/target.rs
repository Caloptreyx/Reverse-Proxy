//! Where a proxy forwards to.
use super::{Ctx, invalid};
use shared::models::{ByUuid, node::Node, server_allocation::ServerAllocation};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: i32,
}

pub async fn resolve(
    ctx: &Ctx,
    server_uuid: Uuid,
    allocation_uuid: Uuid,
) -> Result<Target, anyhow::Error> {
    let allocation = ServerAllocation::by_uuid(ctx.db(), allocation_uuid)
        .await?
        .ok_or_else(|| invalid("the allocation no longer exists"))?
        .allocation;

    let node_uuid: Uuid = sqlx::query_scalar("SELECT node_uuid FROM servers WHERE uuid = $1")
        .bind(server_uuid)
        .fetch_one(ctx.db().read())
        .await?;

    let node_host = match Node::by_uuid(ctx.db(), node_uuid).await {
        Ok(node) => crate::rules::forward::node_public_host(&node),
        Err(err) => {
            tracing::warn!(node = %node_uuid, "failed to load node: {err:?}");
            None
        }
    };

    let host = crate::rules::forward::resolve_forward_host(
        ctx.settings
            .node_forward_hosts
            .get(&node_uuid)
            .map(String::as_str),
        allocation.ip,
        allocation.ip_alias.as_deref(),
        node_host.as_deref(),
    )?;

    Ok(Target {
        host,
        port: allocation.port,
    })
}
