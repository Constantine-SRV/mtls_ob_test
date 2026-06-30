//! mgmt-сервер (HTTPS на встроенном серте): заливка и инфо о серте.

use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::certinfo;
use crate::error::ApiError;
use crate::state::Shared;

pub fn mgmt_router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/cert", post(upload_cert))
        .route("/cert/validity", get(validity))
        .with_state(shared)
}

/// POST /cert  (multipart: поля cert и key — PEM-файлы)
/// Заливает новый клиентский серт, проверяет его подключением к OB, ставит в память.
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

    let cert = cert.ok_or_else(|| anyhow::anyhow!("нет поля 'cert' (curl -F cert=@file.pem)"))?;
    let key = key.ok_or_else(|| anyhow::anyhow!("нет поля 'key' (curl -F key=@file.pem)"))?;

    let info = sh.install_cert(cert, key).await?;
    let body = serde_json::json!({
        "ok": true,
        "cn": info.cn,
        "not_before": info.not_before,
        "not_after": info.not_after,
        "note": "серт принят и проверен подключением к OceanBase"
    })
    .to_string();
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

/// GET /cert/validity -> CN + срок действия текущего серта (или 503 nocert).
async fn validity(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let cred = sh.client.read().await.clone();
    let Some(cred) = cred else {
        return Err(ApiError::NoCert);
    };
    let info = certinfo::describe(&cred.cert_pem)?;
    let body = serde_json::json!({
        "cn": info.cn,
        "not_before": info.not_before,
        "not_after": info.not_after
    })
    .to_string();
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
