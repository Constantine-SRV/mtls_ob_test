//! OceanBase monitoring agent prototype. Cold start, cert kept only in memory.
//! Both servers are HTTPS + mTLS (client cert required) + IP allowlist + CN allowlist.
//!
//!   data :8443  GET /version, GET /health   (server cert becomes the uploaded one)
//!   mgmt :9443  POST /cert, GET /cert/validity  (keeps the embedded self-signed cert)
//!
//! Config: ./agent.toml (or env CONFIG).

mod acl;
mod api;
mod certinfo;
mod config;
mod credentials;
mod db;
mod error;
mod mgmt;
mod state;
mod tls;
mod util;
mod vault;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};

use state::Shared;
use util::now_ts;

// Embedded self-signed cert used at start for both servers (channel identity, not a secret).
// The data server swaps to the uploaded cert after a successful /cert; mgmt keeps this one.
const MGMT_CERT: &str = include_str!("../embedded/mgmt-cert.pem");
const MGMT_KEY: &str = include_str!("../embedded/mgmt-key.pem");

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider as process default (needed by reqwest no-provider).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = config::load()?;
    println!(
        "{} [*] OB target {}:{} user '{}'",
        now_ts(),
        cfg.oceanbase.host,
        cfg.oceanbase.port,
        cfg.oceanbase.user
    );

    let ca_pem = std::fs::read(&cfg.oceanbase.ca)
        .with_context(|| format!("read CA {}", cfg.oceanbase.ca))?;
    println!(
        "{} [OK] CA loaded ({} bytes). No client cert yet -- phase NoCert.",
        now_ts(),
        ca_pem.len()
    );

    let data_nets = Arc::new(acl::parse_nets(&cfg.data_allow_ips()));
    let mgmt_nets = Arc::new(acl::parse_nets(&cfg.mgmt_allow_ips()));

    let data_tls = tls::build_rustls(
        MGMT_CERT.as_bytes(),
        MGMT_KEY.as_bytes(),
        &ca_pem,
        cfg.data.allow_cn.clone(),
        "data",
    )
    .context("data TLS")?;
    let mgmt_tls = tls::build_rustls(
        MGMT_CERT.as_bytes(),
        MGMT_KEY.as_bytes(),
        &ca_pem,
        cfg.mgmt.allow_cn.clone(),
        "mgmt",
    )
    .context("mgmt TLS")?;

    let shared = Shared::new(&cfg, ca_pem, data_tls.clone());

    let data_app = api::data_router(shared.clone(), data_nets);
    let mgmt_app = mgmt::mgmt_router(shared.clone(), mgmt_nets);

    let data_addr: SocketAddr = cfg.data.listen.parse().context("data.listen")?;
    let mgmt_addr: SocketAddr = cfg.mgmt.listen.parse().context("mgmt.listen")?;
    println!("{} [*] data  HTTPS+mTLS https://{}  allow_cn={:?}", now_ts(), data_addr, cfg.data.allow_cn);
    println!("{} [*] mgmt  HTTPS+mTLS https://{}  allow_cn={:?}", now_ts(), mgmt_addr, cfg.mgmt.allow_cn);

    let data_task = tokio::spawn(async move {
        axum_server::bind_rustls(data_addr, data_tls)
            .serve(data_app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    });
    let mgmt_task = tokio::spawn(async move {
        axum_server::bind_rustls(mgmt_addr, mgmt_tls)
            .serve(mgmt_app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    });

    println!("{} [*] both servers up (mTLS). data serves self-signed until /cert, then the uploaded cert.", now_ts());
    tokio::select! {
        r = data_task => { r??; }
        r = mgmt_task => { r??; }
    }
    Ok(())
}
