//! Конфиг из env. Холодный старт: на диске только CA, клиентского серта нет.

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub ob_host: String,
    pub ob_port: u16,
    pub ob_user: String,
    pub ca_path: PathBuf,
    pub data_addr: String, // HTTP: /version /health
    pub mgmt_addr: String, // HTTPS (встроенный серт): POST /cert, GET /cert/validity
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Ok(Self {
            ob_host: env("OB_HOST", "192.168.55.202"),
            ob_port: env("OB_PORT", "2881").parse()?,
            ob_user: env("OB_USER", "nm_test"),
            ca_path: PathBuf::from(env("OB_CA", &format!("{home}/certpas/ca.pem"))),
            data_addr: env("DATA_ADDR", "0.0.0.0:8080"),
            mgmt_addr: env("MGMT_ADDR", "0.0.0.0:9443"),
        })
    }
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}
