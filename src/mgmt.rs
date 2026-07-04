//! mgmt server (HTTPS+mTLS): cert upload and cert info. + IP allowlist.

use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::http::header;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use ipnet::IpNet;

use crate::acl::{ip_guard, GuardState};
use crate::certinfo;
use crate::error::ApiError;
use crate::state::Shared;
use crate::util::now_ts;

pub fn mgmt_router(shared: Arc<Shared>, nets: Arc<Vec<IpNet>>) -> Router {
    let guard = GuardState { nets, label: "mgmt" };
    Router::new()
        .route("/cert", post(upload_cert))
        .route("/cert/validity", get(validity))
        .with_state(shared)
        .layer(middleware::from_fn_with_state(guard, ip_guard))
}

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
    let body = serde_json::json!({
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

async fn validity(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let cred = sh.client.read().await.clone();
    let Some(cred) = cred else {
        return Err(ApiError::NoCert);
    };
    let info = certinfo::describe(&cred.cert_pem)?;
    let body = serde_json::json!({
        "cn": info.cn,
        "not_before": info.not_before,
        "not_after": info.not_after,
        "ts": now_ts()
    })
    .to_string()
        + "\n";
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
