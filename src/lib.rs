use indexmap::IndexMap;
use shared::{
    Extendible, State,
    extensions::{
        Extension, ExtensionPermissionsBuilder, ExtensionRouteBuilder,
        background_tasks::BackgroundTaskBuilder, settings::ExtensionSettingsDeserializer,
    },
    models::{
        BaseModel, CreatableModel, DeletableModel, EventEmittingModel, ListenerPriority,
        UpdatableModel,
        server::{ApiServerFeatureLimits, Server, ServerEvent},
        server_allocation::ServerAllocation,
    },
    permissions::PermissionGroup,
};
use std::sync::Arc;

mod db;
mod dns;
mod model;
mod npm;
mod routes;
mod rules;
mod service;
mod settings;
mod sm;


/// Runs an event reaction with a fresh context; never fails the panel
/// operation that triggered it.
async fn react<F, Fut>(state: &State, what: &str, reaction: F)
where
    F: FnOnce(service::Ctx) -> Fut,
    Fut: Future<Output = Result<(), anyhow::Error>>,
{
    let result = match service::Ctx::load(state).await {
        Ok(ctx) => reaction(ctx).await,
        Err(err) => Err(err),
    };
    if let Err(err) = result {
        tracing::warn!("reverse proxy: failed to handle {what}: {err:?}");
    }
}

#[derive(Default)]
pub struct ExtensionStruct;

#[async_trait::async_trait]
impl Extension for ExtensionStruct {
    async fn initialize(&mut self, _state: State) {
        Server::register_model_extension(model::ServerExtension);

        // `feature_limits.proxies` on create, else the configured default
        Server::register_create_handler(
            ListenerPriority::Normal,
            |options, query_builder, state, _transaction| {
                Box::pin(async move {
                    let limit = match options
                        .feature_limits
                        .parse_extended::<model::ExtendedApiServerFeatureLimits>()
                        .ok()
                        .and_then(|extended| extended.proxies)
                    {
                        Some(limit) => limit,
                        None => service::current_settings(state)
                            .await
                            .map(|settings| settings.default_limit)
                            .unwrap_or(0),
                    };
                    query_builder.set("reverse_proxy_limit", limit.max(0));
                    Ok(())
                })
            },
        );

        // only when the client actually sent `proxies`
        Server::register_update_handler(
            ListenerPriority::Normal,
            |_server, options, query_builder, _state, _transaction| {
                Box::pin(async move {
                    if let Some(feature_limits) = &options.feature_limits
                        && let Ok(extended) =
                            feature_limits.parse_extended::<model::ExtendedApiServerFeatureLimits>()
                        && let Some(value) = extended.proxies
                    {
                        query_builder.set("reverse_proxy_limit", Some(value.max(0)));
                    }
                    Ok(())
                })
            },
        );

        // rows go with ON DELETE CASCADE; remote resources are removed here
        // (or queued for the worker)
        Server::register_delete_handler(
            ListenerPriority::Normal,
            |server, _options, state, _transaction| {
                Box::pin(async move {
                    let server_uuid = server.uuid;
                    react(state, "server deletion", |ctx| async move {
                        service::lifecycle::on_server_deleted(&ctx, server_uuid).await
                    })
                    .await;
                    Ok(())
                })
            },
        );

        ServerAllocation::register_delete_handler(
            ListenerPriority::Normal,
            |allocation, _options, state, _transaction| {
                Box::pin(async move {
                    let allocation_uuid = allocation.uuid;
                    react(state, "allocation deletion", |ctx| async move {
                        service::lifecycle::on_allocation_deleted(&ctx, allocation_uuid).await
                    })
                    .await;
                    Ok(())
                })
            },
        );

        Server::register_event_handler(|state, event| async move {
            if let ServerEvent::TransferCompleted {
                server,
                successful: true,
                ..
            } = &*event
            {
                let server_uuid = server.uuid;
                react(&state, "server transfer", |ctx| async move {
                    service::lifecycle::on_server_transferred(&ctx, server_uuid).await
                })
                .await;
            }
            Ok(())
        });

        ApiServerFeatureLimits::extend_validated(
            |server, _state| {
                Box::pin(
                    async move { Ok(server.parse_model_extension::<model::ServerExtension>()?) },
                )
            },
            |_limits, extension, _state| model::ExtendedApiServerFeatureLimits {
                proxies: Some(extension.reverse_proxy_limit),
            },
        );
    }

    async fn initialize_router(
        &mut self,
        state: State,
        builder: ExtensionRouteBuilder,
    ) -> ExtensionRouteBuilder {
        builder
            .add_admin_api_router(|router| {
                router.nest(
                    "/extensions/dev.caloptreyx.reverseproxy",
                    routes::admin::router(&state),
                )
            })
            .add_client_server_api_router(|router| {
                router.nest("/reverse-proxies", routes::server::router(&state))
            })
    }

    async fn initialize_background_tasks(
        &mut self,
        _state: State,
        builder: BackgroundTaskBuilder,
    ) -> BackgroundTaskBuilder {
        builder
            .add_task("reverse-proxy-worker", |state| async move {
                service::worker::run(&state).await
            })
            .await;
        builder
            .add_task("reverse-proxy-sync", |state| async move {
                service::sync::run(&state).await
            })
            .await;
        builder
    }

    async fn initialize_permissions(
        &mut self,
        _state: State,
        mut builder: ExtensionPermissionsBuilder,
    ) -> ExtensionPermissionsBuilder {
        builder.server_permissions.insert(
            "proxies",
            PermissionGroup {
                description: "Permissions that control the ability to manage reverse proxies for this server.",
                permissions: IndexMap::from([
                    (
                        "read",
                        "Allows viewing the server's reverse proxies, its limit and the available domains.",
                    ),
                    ("create", "Allows creating new reverse proxies for the server."),
                    (
                        "update",
                        "Allows changing a reverse proxy's port, options and certificate, and retrying it.",
                    ),
                    ("delete", "Allows deleting the server's reverse proxies."),
                ]),
            },
        );

        builder.admin_permissions.insert(
            "proxies",
            PermissionGroup {
                description: "Permissions that control the ability to manage the reverse proxy manager extension.",
                permissions: IndexMap::from([
                    (
                        "read",
                        "Allows viewing the extension's settings, all proxies and the reconcile report.",
                    ),
                    (
                        "manage",
                        "Allows changing settings and managing proxies, node overrides and the cleanup queue.",
                    ),
                ]),
            },
        );

        builder
    }

    async fn settings_deserializer(&self, _state: State) -> ExtensionSettingsDeserializer {
        Arc::new(settings::ExtensionSettingsDataDeserializer)
    }
}
