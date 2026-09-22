use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod list {
    use crate::db::CleanupTask;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::user::GetPermissionManager,
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        tasks: Vec<CleanupTask>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ))]
    pub async fn route(state: GetState, permissions: GetPermissionManager) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.read")?;

        ApiResponse::new_serialized(Response {
            tasks: CleanupTask::all(&state.database).await?,
        })
        .ok()
    }
}

mod delete {
    use crate::db::CleanupTask;
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

    #[utoipa::path(delete, path = "/{task}", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(("task" = uuid::Uuid, description = "The cleanup task ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        Path(task): Path<uuid::Uuid>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let task = CleanupTask::by_uuid(&state.database, task)
            .await?
            .ok_or_else(|| crate::routes::not_found("cleanup task"))?;
        task.delete(&state.database).await?;

        activity_logger
            .log(
                "settings:extensions:reverse-proxy.cleanup-drop",
                serde_json::json!({ "uuid": task.uuid, "kind": task.kind, "payload": task.payload.0 }),
            )
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(list::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
