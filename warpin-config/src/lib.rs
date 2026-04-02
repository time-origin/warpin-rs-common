use anyhow::{Context, Result};
use config::{Config, Environment, File, FileFormat};
use serde::{Deserialize, de::DeserializeOwned};
use std::{env, net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 7000,
        }
    }
}

impl ServerConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .with_context(|| format!("invalid socket address {}:{}", self.host, self.port))
    }
}

pub fn current_environment() -> String {
    env::var("TTC_ENV").unwrap_or_else(|_| "local".to_string())
}

pub fn load_config<T>(config_path_env: &str, env_prefix: &str, default_path: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let path = env::var(config_path_env).unwrap_or_else(|_| default_path.to_string());
    let path_buf = PathBuf::from(&path);

    let builder = Config::builder()
        .add_source(
            File::from(path_buf.clone())
                .required(true)
                .format(FileFormat::Toml),
        )
        .add_source(Environment::with_prefix(env_prefix).separator("__"));

    builder
        .build()
        .with_context(|| format!("failed to build config from {}", path_buf.display()))?
        .try_deserialize()
        .with_context(|| format!("failed to deserialize config from {}", path_buf.display()))
}
