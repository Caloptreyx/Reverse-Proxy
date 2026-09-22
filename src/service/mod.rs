//! Everything that talks to NPM, DNS providers or mutates proxies lives
//! here; routes, event handlers and background tasks only call into it.
pub mod certificates;
pub mod hosts;
pub mod lifecycle;
pub mod managed;
pub mod reconcile;
pub mod sync;
pub mod target;
pub mod validate;
pub mod worker;

use crate::{npm::NpmClient, settings::ExtensionSettingsData};
use axum::http::StatusCode;
use shared::{State, database::Database, response::DisplayError};
use std::sync::LazyLock;
use tokio::sync::Notify;
use uuid::Uuid;

/// Settings + identity for one unit of work.
pub struct Ctx {
    pub state: State,
    pub settings: ExtensionSettingsData,
    pub instance_id: String,
}

impl Ctx {
    pub async fn load(state: &State) -> Result<Self, anyhow::Error> {
        let settings = current_settings(state).await?;
        let instance_id = if settings.instance_id.is_empty() {
            ensure_instance_id(state).await?
        } else {
            settings.instance_id.clone()
        };

        Ok(Self {
            state: state.clone(),
            settings,
            instance_id,
        })
    }

    pub fn db(&self) -> &Database {
        &self.state.database
    }

    pub fn is_configured(&self) -> bool {
        self.settings.is_configured()
    }

    pub fn client(&self) -> Result<NpmClient, anyhow::Error> {
        if !self.is_configured() {
            return Err(invalid("the reverse proxy integration is not configured yet"));
        }
        NpmClient::new(
            &self.settings.npm_url,
            &self.settings.npm_identity,
            self.settings.npm_secret.as_deref().unwrap_or_default(),
            self.settings.request_timeout(),
        )
    }

    pub fn marker(&self, proxy_uuid: Uuid) -> String {
        crate::rules::marker::build_marker(&self.instance_id, proxy_uuid)
    }
}

pub async fn current_settings(state: &State) -> Result<ExtensionSettingsData, anyhow::Error> {
    Ok(state
        .settings
        .get()
        .await?
        .find_extension_settings::<ExtensionSettingsData>()
        .cloned()
        .unwrap_or_default())
}

async fn ensure_instance_id(state: &State) -> Result<String, anyhow::Error> {
    let mut settings = state.settings.get_mut().await?;
    let extension = settings.find_mut_extension_settings::<ExtensionSettingsData>()?;
    if extension.instance_id.is_empty() {
        extension.instance_id = Uuid::new_v4().simple().to_string()[..16].to_string();
    }
    let instance_id = extension.instance_id.clone();
    settings.save().await?;
    Ok(instance_id)
}

pub fn user_error(message: impl Into<String>, status: StatusCode) -> anyhow::Error {
    DisplayError::new(message.into()).with_status(status).into()
}

pub fn invalid(message: impl Into<String>) -> anyhow::Error {
    user_error(message, StatusCode::BAD_REQUEST)
}

pub fn conflict(message: impl Into<String>) -> anyhow::Error {
    user_error(message, StatusCode::CONFLICT)
}

/// Turns an NPM/transport error into a readable 502 for API callers.
pub fn upstream(err: anyhow::Error) -> anyhow::Error {
    if err.downcast_ref::<DisplayError>().is_some() {
        return err;
    }
    user_error(
        format!("nginx proxy manager: {}", crate::npm::readable_error(&err)),
        StatusCode::BAD_GATEWAY,
    )
}

/// Whether NPM itself answered (and rejected the request), as opposed to
/// being unreachable.
pub fn is_rejection(err: &anyhow::Error) -> bool {
    err.downcast_ref::<crate::npm::NpmError>().is_some()
        || err.downcast_ref::<DisplayError>().is_some()
}

static WAKE: LazyLock<Notify> = LazyLock::new(Notify::new);

/// Wakes the issuance worker after something was scheduled.
pub fn wake_worker() {
    WAKE.notify_one();
}

pub(crate) async fn wait_for_work(max: std::time::Duration) {
    tokio::select! {
        _ = WAKE.notified() => {},
        _ = tokio::time::sleep(max) => {},
    }
}
