use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod get {
    use crate::settings::ExtensionSettingsData;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::user::GetPermissionManager,
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {
        settings: ExtensionSettingsData,
        /// Whether an NPM password is stored (it is never returned).
        has_npm_secret: bool,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ))]
    pub async fn route(state: GetState, permissions: GetPermissionManager) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.read")?;

        let settings = crate::service::current_settings(&state).await?;
        ApiResponse::new_serialized(Response {
            has_npm_secret: settings.npm_secret.is_some(),
            settings,
        })
        .ok()
    }
}

mod put {
    use crate::settings::ExtensionSettingsData;
    use axum::http::StatusCode;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{admin_activity::GetAdminActivityLogger, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(put, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = UNAUTHORIZED, body = ApiError),
    ), request_body = ExtensionSettingsData)]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        activity_logger: GetAdminActivityLogger,
        shared::Payload(mut data): shared::Payload<ExtensionSettingsData>,
    ) -> ApiResponseResult {
        if let Some(response) = crate::routes::validation_error(&data) {
            return response.ok();
        }
        permissions.has_admin_permission("proxies.manage")?;

        let errors = data.semantic_errors();
        if !errors.is_empty() {
            return ApiResponse::new_serialized(ApiError::new_strings_value(errors))
                .with_status(StatusCode::BAD_REQUEST)
                .ok();
        }

        let mut settings = state.settings.get_mut().await?;
        let extension = settings.find_mut_extension_settings::<ExtensionSettingsData>()?;

        // the password is write-only, the instance id is never editable
        if data.npm_secret.as_deref().is_none_or(str::is_empty) {
            data.npm_secret = extension.npm_secret.clone();
        }
        data.instance_id = extension.instance_id.clone();
        let secret_changed = data.npm_secret != extension.npm_secret;
        *extension = data;

        let log = serde_json::json!({
            "npm_url": extension.npm_url,
            "npm_identity": extension.npm_identity,
            "npm_secret_changed": secret_changed,
            "dns_target": extension.dns_target,
            "allow_letsencrypt": extension.allow_letsencrypt,
            "allow_custom_certificates": extension.allow_custom_certificates,
            "allow_custom_nginx": extension.allow_custom_nginx,
            "sync_enabled": extension.sync_enabled,
        });
        settings.save().await?;

        activity_logger
            .log("settings:extensions:reverse-proxy.update", log)
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .routes(routes!(put::route))
        .with_state(state.clone())
}
