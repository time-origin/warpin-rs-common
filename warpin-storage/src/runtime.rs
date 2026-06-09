use anyhow::{Result, anyhow};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{DatabaseSettings, SchemaPlan, SchemaSyncReport, connect, health_check, sync_schema};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DatabaseBootstrapOptions {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub sync_schema_on_boot: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseRuntimeState {
    #[default]
    Disabled,
    Connected,
    Degraded,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DatabaseRuntimeStatus {
    pub configured: bool,
    pub connected: bool,
    pub healthy: bool,
    pub required: bool,
    pub sync_schema_on_boot: bool,
    pub state: DatabaseRuntimeState,
    pub detail: String,
    pub url: Option<String>,
    pub schema_sync: Option<SchemaSyncReport>,
}

#[derive(Clone, Debug, Default)]
pub struct DatabaseRuntime {
    connection: Option<Arc<DatabaseConnection>>,
    status: DatabaseRuntimeStatus,
}

impl DatabaseRuntime {
    pub fn disabled(
        settings: &DatabaseSettings,
        options: &DatabaseBootstrapOptions,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            connection: None,
            status: DatabaseRuntimeStatus {
                configured: settings.is_configured(),
                connected: false,
                healthy: false,
                required: options.required,
                sync_schema_on_boot: options.sync_schema_on_boot,
                state: DatabaseRuntimeState::Disabled,
                detail: detail.into(),
                url: settings.redacted_url(),
                schema_sync: None,
            },
        }
    }

    pub async fn bootstrap(
        settings: &DatabaseSettings,
        options: &DatabaseBootstrapOptions,
        plan: &SchemaPlan,
    ) -> Self {
        if !settings.is_configured() {
            return Self::disabled(settings, options, "database url is not configured");
        }

        match connect(settings).await {
            Ok(connection) => Self::from_connected(connection, settings, options, plan).await,
            Err(err) => Self {
                connection: None,
                status: DatabaseRuntimeStatus {
                    configured: true,
                    connected: false,
                    healthy: false,
                    required: options.required,
                    sync_schema_on_boot: options.sync_schema_on_boot,
                    state: DatabaseRuntimeState::Degraded,
                    detail: err.to_string(),
                    url: settings.redacted_url(),
                    schema_sync: None,
                },
            },
        }
    }

    async fn from_connected(
        connection: DatabaseConnection,
        settings: &DatabaseSettings,
        options: &DatabaseBootstrapOptions,
        plan: &SchemaPlan,
    ) -> Self {
        let health_result = health_check(&connection).await;
        let sync_result = if options.sync_schema_on_boot && health_result.is_ok() {
            Some(sync_schema(&connection, plan).await)
        } else {
            None
        };

        let schema_sync = match &sync_result {
            Some(Ok(report)) => Some(report.clone()),
            _ => None,
        };

        let mut status = DatabaseRuntimeStatus {
            configured: true,
            connected: true,
            healthy: health_result.is_ok(),
            required: options.required,
            sync_schema_on_boot: options.sync_schema_on_boot,
            state: DatabaseRuntimeState::Connected,
            detail: "database connection is ready".to_string(),
            url: settings.redacted_url(),
            schema_sync,
        };

        if let Err(err) = health_result {
            status.state = DatabaseRuntimeState::Degraded;
            status.healthy = false;
            status.detail = err.to_string();
        }

        if let Some(Err(err)) = &sync_result {
            status.state = DatabaseRuntimeState::Degraded;
            status.detail = err.to_string();
        }

        Self {
            connection: Some(Arc::new(connection)),
            status,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.status.connected && self.status.healthy
    }

    pub fn connection(&self) -> Option<&DatabaseConnection> {
        self.connection.as_deref()
    }

    pub fn connection_arc(&self) -> Option<Arc<DatabaseConnection>> {
        self.connection.as_ref().map(Arc::clone)
    }

    pub fn require_connection(&self) -> Result<&DatabaseConnection> {
        self.connection
            .as_deref()
            .ok_or_else(|| anyhow!("database connection is not available"))
    }

    pub fn status(&self) -> &DatabaseRuntimeStatus {
        &self.status
    }
}
