use super::State;
use utoipa_axum::router::OpenApiRouter;

mod cleanup;
mod connection;
mod nodes;
mod proxies;
mod reconcile;
mod settings;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/settings", settings::router(state))
        .nest("/connection", connection::router(state))
        .nest("/proxies", proxies::router(state))
        .nest("/nodes", nodes::router(state))
        .nest("/reconcile", reconcile::router(state))
        .nest("/cleanup", cleanup::router(state))
        .with_state(state.clone())
}
