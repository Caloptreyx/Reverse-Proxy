use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod list {
    use crate::db::{ApiAdminProxy, JoinedProxy, Proxy, ProxyStatus};
    use axum::extract::Query;
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::{Pagination, PaginationParamsWithSearch, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    /// Separate from the pagination params: `serde(flatten)` breaks
    /// number parsing in query strings.
    #[derive(ToSchema, Deserialize)]
    pub struct Filter {
        status: Option<ProxyStatus>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        #[schema(inline)]
        proxies: Pagination<ApiAdminProxy>,
        /// Proxies that are not live.
        failing: i64,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = UNAUTHORIZED, body = ApiError),
    ), params(
        ("page" = i64, Query, description = "The page number", example = "1"),
        ("per_page" = i64, Query, description = "The number of items per page", example = "10"),
        ("search" = Option<String>, Query, description = "Search by domain, server or owner"),
        ("status" = Option<ProxyStatus>, Query, description = "Filter by status"),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        Query(pagination): Query<PaginationParamsWithSearch>,
        Query(filter): Query<Filter>,
    ) -> ApiResponseResult {
        if let Some(response) = crate::routes::validation_error(&pagination) {
            return response.ok();
        }
        permissions.has_admin_permission("proxies.read")?;

        ApiResponse::new_serialized(Response {
            proxies: JoinedProxy::all_with_pagination(
                &state.database,
                pagination.page,
                pagination.per_page,
                pagination.search.as_deref(),
                filter.status,
            )
            .await?,
            failing: Proxy::count_failing(&state.database).await?,
        })
        .ok()
    }
}

mod retry {
    use crate::{
        db::Proxy,
        service::{Ctx, lifecycle},
    };
    use axum::extract::Path;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{admin_activity::GetAdminActivityLogger, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/{proxy}/retry", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
    ), params(("proxy" = uuid::Uuid, description = "The proxy ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        Path(proxy): Path<uuid::Uuid>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let proxy = Proxy::by_uuid(&state.database, proxy)
            .await?
            .ok_or_else(|| crate::routes::not_found("proxy"))?;
        let proxy = lifecycle::retry(&Ctx::load(&state).await?, proxy, false).await?;

        activity_logger
            .log(
                "settings:extensions:reverse-proxy.retry",
                serde_json::json!({ "uuid": proxy.uuid, "domain": proxy.domain }),
            )
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

mod delete {
    use crate::{
        db::Proxy,
        service::{Ctx, lifecycle},
    };
    use axum::extract::Path;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{admin_activity::GetAdminActivityLogger, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/{proxy}", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(("proxy" = uuid::Uuid, description = "The proxy ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        Path(proxy): Path<uuid::Uuid>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let proxy = Proxy::by_uuid(&state.database, proxy)
            .await?
            .ok_or_else(|| crate::routes::not_found("proxy"))?;
        lifecycle::delete(&Ctx::load(&state).await?, &proxy).await?;

        activity_logger
            .log(
                "settings:extensions:reverse-proxy.delete",
                serde_json::json!({
                    "uuid": proxy.uuid,
                    "domain": proxy.domain,
                    "server_uuid": proxy.server_uuid,
                }),
            )
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(list::route))
        .routes(routes!(retry::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
