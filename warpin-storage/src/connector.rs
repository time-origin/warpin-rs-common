use anyhow::{Context, Result, ensure};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DatabaseSettings {
    pub url: String,
    pub max_connections: Option<u32>,
    pub min_connections: Option<u32>,
    pub connect_timeout_secs: Option<u64>,
}

impl DatabaseSettings {
    pub fn is_configured(&self) -> bool {
        !self.url.trim().is_empty()
    }

    pub fn redacted_url(&self) -> Option<String> {
        redact_database_url(&self.url)
    }

    pub fn to_connect_options(&self) -> ConnectOptions {
        let mut options = ConnectOptions::new(self.url.clone());

        options.max_connections(self.max_connections.unwrap_or(20));
        options.min_connections(self.min_connections.unwrap_or(1));
        options.connect_timeout(Duration::from_secs(self.connect_timeout_secs.unwrap_or(3)));

        options.sqlx_logging(false);
        options
    }
}

pub async fn connect(settings: &DatabaseSettings) -> Result<DatabaseConnection> {
    ensure!(settings.is_configured(), "database url is not configured");

    Database::connect(settings.to_connect_options())
        .await
        .with_context(|| "failed to connect database")
}

pub async fn health_check(connection: &DatabaseConnection) -> Result<()> {
    connection
        .execute_unprepared("SELECT 1")
        .await
        .with_context(|| "database health check failed")?;

    Ok(())
}

fn redact_database_url(url: &str) -> Option<String> {
    if url.trim().is_empty() {
        return None;
    }

    let Some(scheme_separator) = url.find("://") else {
        return Some(url.to_string());
    };

    let credentials_start = scheme_separator + 3;
    let rest = &url[credentials_start..];

    let Some(at_index) = rest.find('@') else {
        return Some(url.to_string());
    };

    let credentials = &rest[..at_index];
    if !credentials.contains(':') {
        return Some(url.to_string());
    }

    let mut redacted = String::with_capacity(url.len());
    redacted.push_str(&url[..credentials_start]);

    let username = credentials.split(':').next().unwrap_or_default();
    redacted.push_str(username);
    redacted.push_str(":***@");
    redacted.push_str(&rest[at_index + 1..]);

    Some(redacted)
}
