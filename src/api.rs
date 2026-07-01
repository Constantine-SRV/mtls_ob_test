//! data server (HTTPS+mTLS): /version (queries OB) and /health. + IP allowlist.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ipnet::IpNet;

use crate::acl::{ip_guard, GuardState};
use crate::error::ApiError;
use crate::state::Shared;

pub fn data_router(shared: Arc<Shared>, nets: Arc<Vec<IpNet>>) -> Router {
    let guard = GuardState { nets, label: "data" };
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .with_state(shared)
        .layer(middleware::from_fn_with_state(guard, ip_guard))
}

async fn health() -> &'static str {
    "ok"
}

async fn version(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let db = sh.db.read().await.clone();
    let Some(db) = db else {
        return Err(ApiError::NoCert);
    };
    let body = db.version_json().await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
