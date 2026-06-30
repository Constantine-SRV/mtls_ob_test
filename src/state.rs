//! Разделяемое состояние обоих серверов. Текущая идентичность и пул живут
//! за RwLock — это и есть точка горячей замены серта (POST /cert).

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;

use crate::certinfo::{self, CertInfo};
use crate::config::Config;
use crate::credentials::Identity;
use crate::db::Db;

#[derive(Clone)]
pub struct ClientCred {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub struct Shared {
    pub ob_host: String,
    pub ob_port: u16,
    pub ob_user: String,
    pub data_addr: String,
    pub mgmt_addr: String,
    pub ca_pem: Vec<u8>,
    pub client: RwLock<Option<ClientCred>>, // текущий клиентский серт+ключ
    pub db: RwLock<Option<Db>>,             // текущий пул к OB (None = фаза NoCert)
}

impl Shared {
    pub fn new(cfg: Config) -> Result<Arc<Self>> {
        let ca_pem = std::fs::read(&cfg.ca_path)
            .with_context(|| format!("чтение CA {:?}", cfg.ca_path))?;
        Ok(Arc::new(Self {
            ob_host: cfg.ob_host,
            ob_port: cfg.ob_port,
            ob_user: cfg.ob_user,
            data_addr: cfg.data_addr,
            mgmt_addr: cfg.mgmt_addr,
            ca_pem,
            client: RwLock::new(None),
            db: RwLock::new(None),
        }))
    }

    /// Горячая установка/замена клиентского серта.
    /// Меняем состояние ТОЛЬКО если новый серт реально аутентифицировался в OB
    /// (self-check запросом) — иначе оставляем прежний и возвращаем ошибку.
    pub async fn install_cert(&self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Result<CertInfo> {
        let info = certinfo::describe(&cert_pem)?;

        let id = Identity {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            ca_pem: self.ca_pem.clone(),
        };
        let db = Db::connect(&id, &self.ob_host, self.ob_port, &self.ob_user);
        db.version_json()
            .await
            .context("новый серт не аутентифицировался в OceanBase")?;

        *self.client.write().await = Some(ClientCred { cert_pem, key_pem });
        *self.db.write().await = Some(db);
        Ok(info)
    }
}
