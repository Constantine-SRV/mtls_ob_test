//! Shared state for both servers + hot cert reload.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use crate::certinfo::{self, CertInfo};
use crate::config::FileConfig;
use crate::credentials::Identity;
use crate::db::Db;

#[derive(Clone)]
pub struct ClientCred {
    pub cert_pem: Vec<u8>,
    #[allow(dead_code)] // kept for a future reload endpoint; not read yet
    pub key_pem: Vec<u8>,
}

pub struct Shared {
    pub ob_host: String,
    pub ob_port: u16,
    pub ob_user: String,
    pub ca_pem: Vec<u8>,
    pub client: RwLock<Option<ClientCred>>,
    pub db: RwLock<Option<Db>>,
}

impl Shared {
    pub fn new(cfg: &FileConfig) -> Result<Arc<Self>> {
        let ca_pem = std::fs::read(&cfg.oceanbase.ca)
            .with_context(|| format!("read CA {}", cfg.oceanbase.ca))?;
        Ok(Arc::new(Self {
            ob_host: cfg.oceanbase.host.clone(),
            ob_port: cfg.oceanbase.port,
            ob_user: cfg.oceanbase.user.clone(),
            ca_pem,
            client: RwLock::new(None),
            db: RwLock::new(None),
        }))
    }

    /// Hot install/replace of the client cert. State is changed only if the cert
    /// actually authenticates against OB (self-check), otherwise it errors out.
    pub async fn install_cert(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<CertInfo> {
        let info = certinfo::describe(&cert_pem)?;
        println!(
            "[cert] upload: CN={} valid {}..{} | cert {} bytes, key {} bytes",
            info.cn,
            info.not_before,
            info.not_after,
            cert_pem.len(),
            key_pem.len()
        );
        println!(
            "[cert] self-check -> OceanBase {}:{} user '{}'",
            self.ob_host, self.ob_port, self.ob_user
        );

        let id = Identity {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            ca_pem: self.ca_pem.clone(),
        };
        let db = Db::connect(&id, &self.ob_host, self.ob_port, &self.ob_user);

        // Print the exact reason from mysql_async, then surface a generic message.
        match db.version_json().await {
            Ok(v) => {
                println!("[cert] self-check OK: {v}");
            }
            Err(e) => {
                eprintln!("[cert] self-check FAIL: {e:?}");
                return Err(e).context("new cert failed to authenticate against OceanBase");
            }
        }

        *self.client.write().await = Some(ClientCred { cert_pem, key_pem });
        *self.db.write().await = Some(db);
        println!("[cert] installed, agent is now Ready");
        Ok(info)
    }
}
