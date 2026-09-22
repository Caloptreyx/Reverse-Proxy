use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod list {
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{node::Node, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct ApiNode {
        uuid: uuid::Uuid,
        name: String,
        /// The node's own public host (fallback forward target).
        public_host: Option<String>,
        forward_host: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        nodes: Vec<ApiNode>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ))]
    pub async fn route(state: GetState, permissions: GetPermissionManager) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.read")?;

        let settings = crate::service::current_settings(&state).await?;
        let mut nodes = Vec::new();
        let mut page = 1;
        loop {
            let batch = Node::all_with_pagination(&state.database, page, 100, None).await?;
            let done = batch.data.len() < 100;
            nodes.extend(batch.data.into_iter().map(|node| ApiNode {
                public_host: crate::rules::forward::node_public_host(&node),
                forward_host: settings.node_forward_hosts.get(&node.uuid).cloned(),
                uuid: node.uuid,
                name: node.name.to_string(),
            }));
            if done {
                break;
            }
            page += 1;
        }

        ApiResponse::new_serialized(Response { nodes }).ok()
    }
}

mod update {
    use crate::settings::ExtensionSettingsData;
    use axum::extract::Path;
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::{admin_activity::GetAdminActivityLogger, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        /// IP or hostname; empty/null removes the override.
        forward_host: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(put, path = "/{node}", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
    ), params(("node" = uuid::Uuid, description = "The node ID")), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        Path(node): Path<uuid::Uuid>,
        shared::Payload(data): shared::Payload<Payload>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let host = data
            .forward_host
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty());
        if let Some(host) = &host
            && crate::rules::forward::target_as_ip(host).is_none()
            && crate::rules::domain::validate_domain(host).is_err()
        {
            return Err(crate::service::invalid("the forward host must be an ip address or hostname").into());
        }

        let mut settings = state.settings.get_mut().await?;
        let extension = settings.find_mut_extension_settings::<ExtensionSettingsData>()?;
        match &host {
            Some(host) => {
                extension.node_forward_hosts.insert(node, host.clone());
            }
            None => {
                extension.node_forward_hosts.shift_remove(&node);
            }
        }
        settings.save().await?;

        activity_logger
            .log(
                "settings:extensions:reverse-proxy.node-override",
                serde_json::json!({ "node_uuid": node, "forward_host": host }),
            )
            .await;

        // forward targets changed - let the sync push them
        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(list::route))
        .routes(routes!(update::route))
        .with_state(state.clone())
}
