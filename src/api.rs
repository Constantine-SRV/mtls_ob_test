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
use crate::util::now_ts;

pub fn data_router(shared: Arc<Shared>, nets: Arc<Vec<IpNet>>) -> Router {
    let guard = GuardState { nets, label: "data" };
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .with_state(shared)
        .layer(middleware::from_fn_with_state(guard, ip_guard))
}

async fn health() -> &'static str {
    "ok\n"
}

async fn version(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let db = sh.db.read().await.clone();
    let Some(db) = db else {
        return Err(ApiError::NoCert);
    };
    let v = db.version().await?;
    let body = serde_json::json!({ "version": v, "ts": now_ts() }).to_string() + "\n";
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
