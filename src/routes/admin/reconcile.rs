use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod report {
    use crate::service::{Ctx, reconcile};
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::user::GetPermissionManager,
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        items: Vec<reconcile::ReconcileItem>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = UNAUTHORIZED, body = ApiError),
    ))]
    pub async fn route(state: GetState, permissions: GetPermissionManager) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.read")?;

        let ctx = Ctx::load(&state).await?;
        let client = ctx.client()?;
        let snapshot = reconcile::snapshot(&ctx, &client)
            .await
            .map_err(crate::service::upstream)?;

        ApiResponse::new_serialized(Response {
            items: snapshot.items,
        })
        .ok()
    }
}

mod fix {
    use crate::service::{Ctx, invalid, reconcile};
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::{admin_activity::GetAdminActivityLogger, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        /// Item ids from the report.
        items: Option<Vec<String>>,
        /// Fix everything currently reported.
        all: Option<bool>,
    }

    #[derive(ToSchema, Serialize)]
    struct ItemResult {
        id: String,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        results: Vec<ItemResult>,
    }

    #[utoipa::path(post, path = "/fix", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = UNAUTHORIZED, body = ApiError),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        shared::Payload(data): shared::Payload<Payload>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let ctx = Ctx::load(&state).await?;
        let client = ctx.client()?;

        let ids = if data.all == Some(true) {
            reconcile::snapshot(&ctx, &client)
                .await
                .map_err(crate::service::upstream)?
                .items
                .into_iter()
                .map(|item| item.id)
                .collect()
        } else {
            data.items
                .filter(|items| !items.is_empty())
                .ok_or_else(|| invalid("select at least one item"))?
        };

        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let result = reconcile::fix(&ctx, &client, &id).await;
            results.push(ItemResult {
                ok: result.is_ok(),
                message: result.err().map(|err| crate::npm::readable_error(&err)),
                id,
            });
        }

        activity_logger
            .log(
                "settings:extensions:reverse-proxy.reconcile",
                serde_json::json!({
                    "fixed": results.iter().filter(|r| r.ok).map(|r| &r.id).collect::<Vec<_>>(),
                    "failed": results.iter().filter(|r| !r.ok).map(|r| &r.id).collect::<Vec<_>>(),
                }),
            )
            .await;

        ApiResponse::new_serialized(Response { results }).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(report::route))
        .routes(routes!(fix::route))
        .with_state(state.clone())
}
