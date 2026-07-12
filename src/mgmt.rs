//! mgmt server (HTTPS+mTLS): cert upload (multipart), Vault fetch, cert info.

use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::http::header;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::acl::{ip_guard, GuardState};
use crate::certinfo;
use crate::error::ApiError;
use crate::state::Shared;
use crate::util::now_ts;
use crate::vault;

pub fn mgmt_router(shared: Arc<Shared>, nets: Arc<Vec<IpNet>>) -> Router {
    let guard = GuardState { nets, label: "mgmt" };
    Router::new()
        .route("/cert", post(upload_cert))
        .route("/cert/fetch", post(fetch_cert))
        .route("/cert/validity", get(validity))
        .with_state(shared)
        .layer(middleware::from_fn_with_state(guard, ip_guard))
}

// ---- POST /cert : legacy multipart upload (one cert for both roles) ----

async fn upload_cert(
    State(sh): State<Arc<Shared>>,
    mut mp: Multipart,
) -> Result<Response, ApiError> {
    let mut cert: Option<Vec<u8>> = None;
    let mut key: Option<Vec<u8>> = None;

    while let Some(field) = mp.next_field().await? {
        let name = field.name().map(|s| s.to_string());
        let data = field.bytes().await?.to_vec();
        match name.as_deref() {
            Some("cert") => cert = Some(data),
            Some("key") => key = Some(data),
            _ => {}
        }
    }

    let cert = cert.ok_or_else(|| anyhow::anyhow!("missing field 'cert' (curl -F cert=@file.pem)"))?;
    let key = key.ok_or_else(|| anyhow::anyhow!("missing field 'key' (curl -F key=@file.pem)"))?;

    let info = sh.install_cert(cert, key).await?;
    let body = json!({
        "ok": true,
        "cn": info.cn,
        "not_before": info.not_before,
        "not_after": info.not_after,
        "note": "cert accepted and verified by connecting to OceanBase",
        "ts": now_ts()
    })
    .to_string()
        + "\n";
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

// ---- POST /cert/fetch : agent fetches certs from Vault using params from the caller ----

#[derive(Deserialize)]
struct VaultFetch {
    url: String,
    body: Value, // passed to Vault verbatim
}

#[derive(Deserialize)]
struct FetchReq {
    token: String,
    namespace: String,
    #[serde(default)]
    insecure: bool,
    client: Option<VaultFetch>,
    server: Option<VaultFetch>,
}

async fn fetch_cert(
    State(sh): State<Arc<Shared>>,
    Json(req): Json<FetchReq>,
) -> Result<Response, ApiError> {
    let mut client_out = Value::Null;
    let mut server_out = Value::Null;

    if let Some(c) = req.client.as_ref() {
        println!("{} [fetch] client cert from {}", now_ts(), c.url);
        let vc = vault::fetch(&c.url, &req.token, &req.namespace, &c.body, req.insecure).await?;
        let info = sh.install_client(vc.cert_pem, vc.key_pem, vc.root_pem).await?;
        client_out = json!({ "cn": info.cn, "not_before": info.not_before, "not_after": info.not_after });
    }

    if let Some(s) = req.server.as_ref() {
        println!("{} [fetch] server cert from {}", now_ts(), s.url);
        let vc = vault::fetch(&s.url, &req.token, &req.namespace, &s.body, req.insecure).await?;
        let info = sh.install_server(vc.cert_pem, vc.key_pem).await?;
        server_out = json!({ "cn": info.cn, "not_before": info.not_before, "not_after": info.not_after });
    }

    let body = json!({
        "ok": true,
        "client": client_out,
        "server": server_out,
        "ts": now_ts()
    })
    .to_string()
        + "\n";
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

// ---- GET /cert/validity : show both client and server certs ----

fn describe_opt(pem: &Option<Vec<u8>>) -> Value {
    match pem.as_deref().map(certinfo::describe) {
        Some(Ok(i)) => json!({
            "cn": i.cn,
            "not_before": i.not_before,
            "not_after": i.not_after
        }),
        _ => Value::Null,
    }
}

async fn validity(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let client = sh.client_cert.read().await.clone();
    let server = sh.server_cert.read().await.clone();

    if client.is_none() && server.is_none() {
        return Err(ApiError::NoCert);
    }

    let body = json!({
        "client": describe_opt(&client),
        "server": describe_opt(&server),
        "ts": now_ts()
    })
    .to_string()
        + "\n";
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
