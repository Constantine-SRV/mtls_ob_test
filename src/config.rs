//! Agent config from a TOML file (path in env CONFIG, default ./agent.toml).
//! IP allowlists are per-server (with a common [network].allow_ips default),
//! CN allowlists are per-server.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub network: NetworkCfg,
    pub data: ServerCfg,
    pub mgmt: ServerCfg,
    pub oceanbase: ObCfg,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkCfg {
    /// Common IP/CIDR allowlist used when a server has no allow_ips of its own.
    #[serde(default)]
    pub allow_ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerCfg {
    pub listen: String,
    /// Allowed client-cert CNs for this server.
    #[serde(default)]
    pub allow_cn: Vec<String>,
    /// Optional per-server IP allowlist; if absent, [network].allow_ips is used.
    pub allow_ips: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObCfg {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub ca: String,
}

impl FileConfig {
    pub fn data_allow_ips(&self) -> Vec<String> {
        self.data
            .allow_ips
            .clone()
            .unwrap_or_else(|| self.network.allow_ips.clone())
    }
    pub fn mgmt_allow_ips(&self) -> Vec<String> {
        self.mgmt
            .allow_ips
            .clone()
            .unwrap_or_else(|| self.network.allow_ips.clone())
    }
}

pub fn load() -> Result<FileConfig> {
    let path = std::env::var("CONFIG").unwrap_or_else(|_| "./agent.toml".to_string());
    let text = std::fs::read_to_string(&path).with_context(|| format!("read config {path}"))?;
    let cfg: FileConfig = toml::from_str(&text).with_context(|| format!("parse TOML {path}"))?;
    Ok(cfg)
}
