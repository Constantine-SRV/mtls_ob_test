//! Shared state for both servers + hot cert reload.
//! On upload the data server's TLS cert is swapped to the uploaded (valid) cert,
//! so clients can talk to the data port without `-k`. The mgmt server keeps its
//! embedded self-signed cert (stable bootstrap identity).

use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::RwLock;

use crate::certinfo::{self, CertInfo};
use crate::config::FileConfig;
use crate::credentials::Identity;
use crate::db::Db;
use crate::tls;

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
    /// Handle to the data server's TLS config (same ArcSwap as the running server).
    pub data_tls: RustlsConfig,
    /// CN allowlist for the data server (needed to rebuild its ServerConfig on reload).
    pub data_allow_cn: Vec<String>,
    pub client: RwLock<Option<ClientCred>>,
    pub db: RwLock<Option<Db>>,
}

impl Shared {
    pub fn new(cfg: &FileConfig, ca_pem: Vec<u8>, data_tls: RustlsConfig) -> Arc<Self> {
        Arc::new(Self {
            ob_host: cfg.oceanbase.host.clone(),
            ob_port: cfg.oceanbase.port,
            ob_user: cfg.oceanbase.user.clone(),
            ca_pem,
            data_tls,
            data_allow_cn: cfg.data.allow_cn.clone(),
            client: RwLock::new(None),
            db: RwLock::new(None),
        })
    }

    /// Hot install/replace of the cert. State changes only if the cert actually
    /// authenticates against OB (self-check). On success, also swaps the data
    /// server's TLS cert to this (valid) cert so the data port drops self-signed.
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

        match db.version_json().await {
            Ok(v) => println!("[cert] self-check OK: {v}"),
            Err(e) => {
                eprintln!("[cert] self-check FAIL: {e:?}");
                return Err(e).context("new cert failed to authenticate against OceanBase");
            }
        }

        // Swap the data server's TLS cert to the uploaded one (same client verifier).
        match tls::build_server_config(
            &cert_pem,
            &key_pem,
            &self.ca_pem,
            self.data_allow_cn.clone(),
            "data",
        ) {
            Ok(server_cfg) => {
                self.data_tls.reload_from_config(server_cfg);
                println!("[cert] data TLS reloaded: data port now presents the uploaded cert");
            }
            Err(e) => {
                // Client->OB path already works; keep serving (self-signed) on data.
                eprintln!("[cert] WARN: data TLS reload failed, data port stays self-signed: {e:?}");
            }
        }

        *self.client.write().await = Some(ClientCred { cert_pem, key_pem });
        *self.db.write().await = Some(db);
        println!("[cert] installed, agent is now Ready");
        Ok(info)
    }
}