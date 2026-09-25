use super::State;
use crate::db::{JoinedProxy, Proxy};
use shared::{models::server::Server, response::ApiResponse};
use utoipa_axum::{router::OpenApiRouter, routes};

/// The proxy with this uuid, scoped to the server.
async fn find_proxy(state: &State, server: &Server, uuid: uuid::Uuid) -> Result<Proxy, ApiResponse> {
    Proxy::by_server_uuid_uuid(&state.database, server.uuid, uuid)
        .await?
        .ok_or_else(|| super::not_found("proxy"))
}

async fn api_proxy(state: &State, uuid: uuid::Uuid) -> Result<crate::db::ApiProxy, ApiResponse> {
    JoinedProxy::by_uuid(&state.database, uuid)
        .await?
        .map(JoinedProxy::into_api)
        .ok_or_else(|| super::not_found("proxy"))
}

mod list {
    use crate::{
        db::{ApiProxy, JoinedProxy},
        model,
        service::Ctx,
        settings::ProxyDefaults,
    };
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{server::GetServer, user::GetPermissionManager},
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct ManagedDomain {
        uuid: uuid::Uuid,
        domain: String,
        /// Certificates are issued through Cloudflare DNS validation.
        dns_challenge: bool,
    }

    #[derive(ToSchema, Serialize)]
    struct Options {
        allow_letsencrypt: bool,
        allow_custom_certificates: bool,
        allow_custom_nginx: bool,
        /// Where users point their DNS; empty when unset.
        dns_target: String,
        defaults: ProxyDefaults,
        managed_domains: Vec<ManagedDomain>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        proxies: Vec<ApiProxy>,
        limit: i32,
        configured: bool,
        options: Options,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ), params(("server" = uuid::Uuid, description = "The server ID")))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
    ) -> ApiResponseResult {
        permissions.has_server_permission("proxies.read")?;

        let ctx = Ctx::load(&state).await?;
        let settings = &ctx.settings;

        let managed_domains = if crate::sm::is_active(&state).await {
            crate::sm::enabled_domains(&state.database)
                .await?
                .into_iter()
                .map(|domain| ManagedDomain {
                    dns_challenge: domain.provider == "cloudflare",
                    uuid: domain.uuid,
                    domain: domain.domain,
                })
                .collect()
        } else {
            Vec::new()
        };

        ApiResponse::new_serialized(Response {
            proxies: JoinedProxy::all_by_server_uuid(&state.database, server.uuid)
                .await?
                .into_iter()
                .map(JoinedProxy::into_api)
                .collect(),
            limit: model::reverse_proxy_limit(&server)?,
            configured: ctx.is_configured(),
            options: Options {
                allow_letsencrypt: settings.allow_letsencrypt,
                allow_custom_certificates: settings.allow_custom_certificates,
                allow_custom_nginx: settings.allow_custom_nginx,
                dns_target: settings.dns_target().unwrap_or_default().to_string(),
                defaults: settings.defaults.clone(),
                managed_domains,
            },
        })
        .ok()
    }
}

mod create {
    use crate::{
        db::ApiProxy,
        model,
        service::{
            Ctx,
            certificates::CustomCertificate,
            invalid,
            lifecycle::{self, CreateInput},
            validate::{DomainRequest, FlagsInput},
        },
    };
    use garde::Validate;
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::{
            server::{GetServer, GetServerActivityLogger},
            user::GetPermissionManager,
        },
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Validate, Deserialize)]
    pub struct Payload {
        /// `custom` (own domain) or `managed` (Subdomain Manager domain).
        #[garde(length(chars, min = 1, max = 15))]
        kind: String,
        #[garde(length(chars, max = 253))]
        domain: Option<String>,
        #[garde(skip)]
        managed_domain_uuid: Option<uuid::Uuid>,
        #[garde(length(chars, max = 63))]
        name: Option<String>,
        #[garde(skip)]
        allocation_uuid: uuid::Uuid,
        #[garde(length(chars, max = 5))]
        forward_scheme: Option<String>,
        #[garde(skip)]
        #[serde(flatten)]
        #[schema(inline)]
        flags: FlagsInput,
        /// `letsencrypt` or `custom`.
        #[garde(length(chars, min = 1, max = 15))]
        certificate_mode: String,
        #[garde(length(chars, max = 16384))]
        certificate: Option<String>,
        #[garde(length(chars, max = 16384))]
        certificate_key: Option<String>,
        #[garde(length(chars, max = 16384))]
        intermediate_certificate: Option<String>,
        #[garde(length(chars, max = 4096))]
        advanced_config: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        proxy: ApiProxy,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = CONFLICT, body = ApiError),
    ), params(("server" = uuid::Uuid, description = "The server ID")), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
        activity_logger: GetServerActivityLogger,
        shared::Payload(data): shared::Payload<Payload>,
    ) -> ApiResponseResult {
        if let Some(response) = crate::routes::validation_error(&data) {
            return response.ok();
        }
        permissions.has_server_permission("proxies.create")?;

        let domain = match data.kind.as_str() {
            "custom" => DomainRequest::Custom {
                domain: data
                    .domain
                    .as_deref()
                    .ok_or_else(|| invalid("a domain is required"))?,
            },
            "managed" => DomainRequest::Managed {
                domain_uuid: data
                    .managed_domain_uuid
                    .ok_or_else(|| invalid("choose a domain"))?,
                name: data.name.as_deref().ok_or_else(|| invalid("a name is required"))?,
            },
            _ => return Err(invalid("the kind must be `custom` or `managed`").into()),
        };

        let ctx = Ctx::load(&state).await?;
        let proxy = lifecycle::create(
            &ctx,
            &server,
            model::reverse_proxy_limit(&server)?,
            CreateInput {
                domain,
                allocation_uuid: data.allocation_uuid,
                forward_scheme: data.forward_scheme.as_deref(),
                flags: data.flags,
                certificate_mode: &data.certificate_mode,
                custom_certificate: CustomCertificate::from_parts(
                    data.certificate.as_deref(),
                    data.certificate_key.as_deref(),
                    data.intermediate_certificate.as_deref(),
                )?,
                advanced_config: data.advanced_config.as_deref(),
            },
        )
        .await?;

        activity_logger
            .log(
                "server:reverse-proxy.create",
                serde_json::json!({
                    "uuid": proxy.uuid,
                    "domain": proxy.domain,
                    "allocation_uuid": proxy.allocation_uuid,
                    "certificate_mode": proxy.certificate_mode,
                    "managed": proxy.managed_domain_uuid.is_some(),
                }),
            )
            .await;

        ApiResponse::new_serialized(Response {
            proxy: super::api_proxy(&state, proxy.uuid).await?,
        })
        .ok()
    }
}

mod update {
    use crate::{
        db::ApiProxy,
        service::{
            Ctx,
            certificates::CustomCertificate,
            lifecycle::{self, UpdateInput},
            validate::FlagsInput,
        },
    };
    use axum::extract::Path;
    use garde::Validate;
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::{
            server::{GetServer, GetServerActivityLogger},
            user::GetPermissionManager,
        },
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Validate, Deserialize)]
    pub struct Payload {
        #[garde(skip)]
        allocation_uuid: Option<uuid::Uuid>,
        #[garde(length(chars, max = 5))]
        forward_scheme: Option<String>,
        #[garde(skip)]
        #[serde(flatten)]
        #[schema(inline)]
        flags: FlagsInput,
        /// Switching to `letsencrypt` schedules issuance; `custom` needs
        /// certificate material unless the proxy already uses one.
        #[garde(length(chars, max = 15))]
        certificate_mode: Option<String>,
        #[garde(length(chars, max = 16384))]
        certificate: Option<String>,
        #[garde(length(chars, max = 16384))]
        certificate_key: Option<String>,
        #[garde(length(chars, max = 16384))]
        intermediate_certificate: Option<String>,
        #[garde(length(chars, max = 4096))]
        advanced_config: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        proxy: ApiProxy,
        #[serde(skip_serializing_if = "Option::is_none")]
        warning: Option<String>,
    }

    #[utoipa::path(patch, path = "/{proxy}", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        ("server" = uuid::Uuid, description = "The server ID"),
        ("proxy" = uuid::Uuid, description = "The proxy ID"),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
        activity_logger: GetServerActivityLogger,
        Path((_server, proxy_uuid)): Path<(String, uuid::Uuid)>,
        shared::Payload(data): shared::Payload<Payload>,
    ) -> ApiResponseResult {
        if let Some(response) = crate::routes::validation_error(&data) {
            return response.ok();
        }
        permissions.has_server_permission("proxies.update")?;

        let proxy = super::find_proxy(&state, &server, proxy_uuid).await?;
        let ctx = Ctx::load(&state).await?;
        let (proxy, warning) = lifecycle::update(
            &ctx,
            &server,
            proxy,
            UpdateInput {
                allocation_uuid: data.allocation_uuid,
                forward_scheme: data.forward_scheme.as_deref(),
                flags: data.flags,
                certificate_mode: data.certificate_mode.as_deref(),
                custom_certificate: CustomCertificate::from_parts(
                    data.certificate.as_deref(),
                    data.certificate_key.as_deref(),
                    data.intermediate_certificate.as_deref(),
                )?,
                advanced_config: data.advanced_config.as_deref(),
            },
        )
        .await?;

        activity_logger
            .log(
                "server:reverse-proxy.update",
                serde_json::json!({
                    "uuid": proxy.uuid,
                    "domain": proxy.domain,
                    "allocation_uuid": proxy.allocation_uuid,
                    "forward_scheme": proxy.forward_scheme,
                    "flags": proxy.flags,
                    "certificate_mode": proxy.certificate_mode,
                    "certificate_uploaded": data.certificate.is_some(),
                    "advanced_config_changed": data.advanced_config.is_some(),
                }),
            )
            .await;

        ApiResponse::new_serialized(Response {
            proxy: super::api_proxy(&state, proxy.uuid).await?,
            warning,
        })
        .ok()
    }
}

mod delete {
    use crate::service::{Ctx, lifecycle};
    use axum::extract::Path;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{
            server::{GetServer, GetServerActivityLogger},
            user::GetPermissionManager,
        },
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(delete, path = "/{proxy}", responses(
        (status = OK, body = inline(Response)),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        ("server" = uuid::Uuid, description = "The server ID"),
        ("proxy" = uuid::Uuid, description = "The proxy ID"),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
        activity_logger: GetServerActivityLogger,
        Path((_server, proxy_uuid)): Path<(String, uuid::Uuid)>,
    ) -> ApiResponseResult {
        permissions.has_server_permission("proxies.delete")?;

        let proxy = super::find_proxy(&state, &server, proxy_uuid).await?;
        lifecycle::delete(&Ctx::load(&state).await?, &proxy).await?;

        activity_logger
            .log(
                "server:reverse-proxy.delete",
                serde_json::json!({ "uuid": proxy.uuid, "domain": proxy.domain }),
            )
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

mod retry {
    use crate::service::{Ctx, lifecycle};
    use axum::extract::Path;
    use serde::Serialize;
    use shared::{
        ApiError, GetState,
        models::{
            server::{GetServer, GetServerActivityLogger},
            user::GetPermissionManager,
        },
        response::{ApiResponse, ApiResponseResult},
    };
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/{proxy}/retry", responses(
        (status = OK, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
        (status = NOT_FOUND, body = ApiError),
    ), params(
        ("server" = uuid::Uuid, description = "The server ID"),
        ("proxy" = uuid::Uuid, description = "The proxy ID"),
    ))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        server: GetServer,
        activity_logger: GetServerActivityLogger,
        Path((_server, proxy_uuid)): Path<(String, uuid::Uuid)>,
    ) -> ApiResponseResult {
        permissions.has_server_permission("proxies.update")?;

        let proxy = super::find_proxy(&state, &server, proxy_uuid).await?;
        let proxy = lifecycle::retry(&Ctx::load(&state).await?, proxy, true).await?;

        activity_logger
            .log(
                "server:reverse-proxy.retry",
                serde_json::json!({ "uuid": proxy.uuid, "domain": proxy.domain }),
            )
            .await;

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(list::route))
        .routes(routes!(create::route))
        .routes(routes!(update::route))
        .routes(routes!(delete::route))
        .routes(routes!(retry::route))
        .with_state(state.clone())
}
