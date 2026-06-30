//! Прототип агента мониторинга OceanBase, фаза «холодный старт».
//! Стартует БЕЗ клиентского серта (только встроенный mgmt-серт + CA на диске).
//! Серт заливается в рантайме через mgmt-эндпоинт и живёт только в памяти.
//!
//! Два сервера:
//!   data  HTTP   :8080  -> GET /version, GET /health
//!   mgmt  HTTPS  :9443  -> POST /cert (multipart cert+key), GET /cert/validity

mod api;
mod certinfo;
mod config;
mod credentials;
mod db;
mod error;
mod mgmt;
mod state;

use std::net::SocketAddr;

use anyhow::Result;
use axum_server::tls_rustls::RustlsConfig;

use state::Shared;

// Встроенный самоподписанный серт mgmt-сервера (личность, которую пинит центр).
// Публичен в каждом бинаре — это идентичность канала, не секрет.
const MGMT_CERT: &str = include_str!("../embedded/mgmt-cert.pem");
const MGMT_KEY: &str = include_str!("../embedded/mgmt-key.pem");

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::Config::from_env()?;
    println!("[*] OB target {}:{} user '{}'", cfg.ob_host, cfg.ob_port, cfg.ob_user);

    let shared = Shared::new(cfg)?;
    println!(
        "[OK] CA в памяти ({} б). Клиентского серта НЕТ — фаза NoCert.",
        shared.ca_pem.len()
    );

    let data_app = api::data_router(shared.clone());
    let mgmt_app = mgmt::mgmt_router(shared.clone());

    let data_listener = tokio::net::TcpListener::bind(&shared.data_addr).await?;
    println!("[*] data  HTTP  http://{}  -> GET /version  GET /health", shared.data_addr);

    let tls =
        RustlsConfig::from_pem(MGMT_CERT.as_bytes().to_vec(), MGMT_KEY.as_bytes().to_vec()).await?;
    let mgmt_addr: SocketAddr = shared.mgmt_addr.parse()?;
    println!(
        "[*] mgmt  HTTPS https://{} -> POST /cert  GET /cert/validity (встроенный серт)",
        shared.mgmt_addr
    );

    let data_task = tokio::spawn(async move { axum::serve(data_listener, data_app).await });
    let mgmt_task = tokio::spawn(async move {
        axum_server::bind_rustls(mgmt_addr, tls)
            .serve(mgmt_app.into_make_service())
            .await
    });

    println!("[*] оба сервера подняты, жду заливку серта...");
    tokio::select! {
        r = data_task => { r??; }
        r = mgmt_task => { r??; }
    }
    Ok(())
}
