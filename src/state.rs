//! Shared state for both servers + hot cert reload.
//!
//! Two independent certs are tracked:
//!   - client cert  -> agent's identity when connecting to OceanBase;
//!   - server cert  -> what the data port presents to callers (hot-reloaded).
//! The mgmt server keeps its embedded self-signed cert.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use tokio::sync::RwLock;

use crate::certinfo::{self, CertInfo};
use crate::config::FileConfig;
use crate::credentials::Identity;
use crate::db::Db;
use crate::tls;
use crate::util::now_ts;

pub struct Shared {
    pub ob_host: String,
    pub ob_port: u16,
    pub ob_user: String,
    /// CA loaded at startup (used to verify OB's server cert and incoming clients).
    pub ca_pem: Vec<u8>,
    pub data_tls: RustlsConfig,
    pub data_allow_cn: Vec<String>,
    /// Current client cert (to OceanBase) — stored for /cert/validity.
    pub client_cert: RwLock<Option<Vec<u8>>>,
    /// Current server cert (data port) — stored for /cert/validity.
    pub server_cert: RwLock<Option<Vec<u8>>>,
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
            client_cert: RwLock::new(None),
            server_cert: RwLock::new(None),
            db: RwLock::new(None),
        })
    }

    /// Install the client cert used to connect to OceanBase. Verified by actually
    /// connecting (self-check). `extra_ca` (e.g. Vault root_cert) is added to the
    /// roots used to verify OB's server cert.
    pub async fn install_client(
        &self,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        extra_ca: Option<Vec<u8>>,
    ) -> Result<CertInfo> {
        let info = certinfo::describe(&cert_pem)?;
        println!(
            "{} [client] install: CN={} valid {}..{}",
            now_ts(),
            info.cn,
            info.not_before,
            info.not_after
        );

        // roots for verifying OB's server cert: startup CA (+ optional Vault root)
        let mut ca = self.ca_pem.clone();
        if let Some(extra) = extra_ca {
            if !ca.ends_with(b"\n") {
                ca.push(b'\n');
            }
            ca.extend_from_slice(&extra);
        }

        let id = Identity {
            cert_pem: cert_pem.clone(),
            key_pem,
            ca_pem: ca,
        };
        let db = Db::connect(&id, &self.ob_host, self.ob_port, &self.ob_user);
        println!(
            "{} [client] self-check -> OceanBase {}:{} user '{}'",
            now_ts(),
            self.ob_host,
            self.ob_port,
            self.ob_user
        );
        match db.version().await {
            Ok(v) => println!("{} [client] self-check OK: version={v}", now_ts()),
            Err(e) => {
                eprintln!("{} [client] self-check FAIL: {e:?}", now_ts());
                return Err(e).context("client cert failed to authenticate against OceanBase");
            }
        }

        *self.client_cert.write().await = Some(cert_pem);
        *self.db.write().await = Some(db);
        println!("{} [client] installed", now_ts());
        Ok(info)
    }

    /// Install the server cert presented by the data port (hot-reload). The client
    /// verifier (CA + CN allowlist) is unchanged.
    pub async fn install_server(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<CertInfo> {
        let info = certinfo::describe(&cert_pem)?;
        println!(
            "{} [server] install: CN={} valid {}..{}",
            now_ts(),
            info.cn,
            info.not_before,
            info.not_after
        );

        let server_cfg = tls::build_server_config(
            &cert_pem,
            &key_pem,
            &self.ca_pem,
            self.data_allow_cn.clone(),
            "data",
        )
        .context("build data server config from new cert")?;
        self.data_tls.reload_from_config(server_cfg);
        println!("{} [server] data TLS reloaded: data port now presents this cert", now_ts());

        *self.server_cert.write().await = Some(cert_pem);
        Ok(info)
    }

    /// Legacy multipart path: one uploaded cert used both as client (to OB) and
    /// as the data server cert.
    pub async fn install_cert(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<CertInfo> {
        let info = self
            .install_client(cert_pem.clone(), key_pem.clone(), None)
            .await?;
        self.install_server(cert_pem, key_pem).await?;
        println!("{} [cert] installed (client + server), agent is now Ready", now_ts());
        Ok(info)
    }
}
