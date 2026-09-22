use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod test {
    use crate::npm::{NpmClient, readable_error};
    use serde::{Deserialize, Serialize};
    use shared::{
        ApiError, GetState,
        models::user::GetPermissionManager,
        response::{ApiResponse, ApiResponseResult},
    };
    use std::time::Duration;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        /// Unsaved values from the form; stored settings are used for
        /// anything left out.
        npm_url: Option<String>,
        npm_identity: Option<String>,
        npm_secret: Option<String>,
        request_timeout_seconds: Option<u32>,
    }

    #[derive(ToSchema, Serialize)]
    struct Check {
        name: &'static str,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        checks: Vec<Check>,
    }

    fn check(checks: &mut Vec<Check>, name: &'static str, result: Result<(), String>) -> bool {
        let ok = result.is_ok();
        checks.push(Check {
            name,
            ok,
            message: result.err(),
        });
        ok
    }

    #[utoipa::path(post, path = "/test", responses(
        (status = OK, body = inline(Response)),
        (status = UNAUTHORIZED, body = ApiError),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        permissions: GetPermissionManager,
        shared::Payload(data): shared::Payload<Payload>,
    ) -> ApiResponseResult {
        permissions.has_admin_permission("proxies.manage")?;

        let stored = crate::service::current_settings(&state).await?;
        let secret = data
            .npm_secret
            .filter(|secret| !secret.is_empty())
            .or(stored.npm_secret)
            .unwrap_or_default();
        let timeout = data
            .request_timeout_seconds
            .unwrap_or(stored.request_timeout_seconds)
            .clamp(5, 300);

        let mut checks = Vec::new();
        let mut version = None;
        let mut email = None;

        let client = NpmClient::new(
            data.npm_url.as_deref().unwrap_or(&stored.npm_url),
            data.npm_identity.as_deref().unwrap_or(&stored.npm_identity),
            &secret,
            Duration::from_secs(timeout as u64),
        );

        let connected = match &client {
            Ok(client) => match client.version().await {
                Ok(found) => {
                    version = Some(found.to_string());
                    check(
                        &mut checks,
                        "login",
                        Ok(()),
                    );
                    check(
                        &mut checks,
                        "version",
                        if (found.major, found.minor) >= (2, 10) {
                            Ok(())
                        } else {
                            Err(format!("version {found} is older than 2.10 - please upgrade"))
                        },
                    );
                    true
                }
                Err(err) => check(&mut checks, "login", Err(readable_error(&err))),
            },
            Err(err) => check(&mut checks, "configuration", Err(err.to_string())),
        };

        if connected && let Ok(client) = &client {
            let user = client.me().await;
            check(
                &mut checks,
                "user_email",
                match &user {
                    Ok(user) => match user.email.as_deref().filter(|email| !email.is_empty()) {
                        Some(found) if found.ends_with("@example.com") => Err(format!(
                            "{found} - let's encrypt rejects example.com addresses, set a real email on the api user"
                        )),
                        Some(found) => {
                            email = Some(found.to_string());
                            Ok(())
                        }
                        None => Err("the api user has no email - let's encrypt needs one".into()),
                    },
                    Err(err) => Err(readable_error(err)),
                },
            );
            if email.is_none()
                && let Ok(user) = &user
            {
                email = user.email.clone();
            }

            let hosts = client.proxy_hosts().await.map(|_| ()).map_err(|err| readable_error(&err));
            check(&mut checks, "proxy_hosts", hosts);
            let certificates = client
                .certificates()
                .await
                .map(|_| ())
                .map_err(|err| readable_error(&err));
            check(&mut checks, "certificates", certificates);
        }

        ApiResponse::new_serialized(Response {
            ok: checks.iter().all(|check| check.ok),
            version,
            email,
            checks,
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(test::route))
        .with_state(state.clone())
}
