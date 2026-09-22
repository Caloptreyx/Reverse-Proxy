use garde::Validate;
use serde::{Deserialize, Serialize};
use shared::{
    database::DatabaseError,
    models::{
        BaseModel, ModelExtension, ModelExtensionMapType, SafeModelExtension, server::Server,
    },
};
use sqlx::{Row, postgres::PgRow};
use std::collections::BTreeMap;
use utoipa::ToSchema;

/// The extension's column on `servers` - a per-server reverse proxy cap.
#[derive(Serialize, Deserialize)]
pub struct ServerExtensionData {
    pub reverse_proxy_limit: i32,
}

pub struct ServerExtension;

impl SafeModelExtension for ServerExtension {
    type Value = ServerExtensionData;

    fn name() -> &'static str {
        ServerExtension.extension_name()
    }
}

impl ModelExtension for ServerExtension {
    fn extension_name(&self) -> &'static str {
        "dev.caloptreyx.reverseproxy"
    }

    fn extended_columns(&self, prefix: &str) -> BTreeMap<&'static str, compact_str::CompactString> {
        BTreeMap::from([(
            "servers.reverse_proxy_limit",
            compact_str::format_compact!("{prefix}reverse_proxy_limit"),
        )])
    }

    fn map_extended(
        &self,
        prefix: &str,
        row: &PgRow,
    ) -> Result<ModelExtensionMapType, DatabaseError> {
        Ok(Box::new(ServerExtensionData {
            reverse_proxy_limit: row
                .try_get(compact_str::format_compact!("{prefix}reverse_proxy_limit").as_str())?,
        }))
    }
}

/// Extension fields on `ApiServerFeatureLimits`. `proxies` is optional so
/// clients unaware of the extension don't reset the limit on updates.
#[derive(ToSchema, Validate, Serialize, Deserialize)]
pub struct ExtendedApiServerFeatureLimits {
    #[garde(range(min = 0))]
    #[schema(minimum = 0)]
    pub proxies: Option<i32>,
}

/// Reads a server's configured reverse proxy limit from its extension data.
pub fn reverse_proxy_limit(server: &Server) -> Result<i32, DatabaseError> {
    Ok(server
        .parse_model_extension::<ServerExtension>()?
        .reverse_proxy_limit)
}
