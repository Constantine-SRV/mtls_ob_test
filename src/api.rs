//! data-сервер (plain HTTP): /version (ходит в OB) и /health.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::error::ApiError;
use crate::state::Shared;

pub fn data_router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .with_state(shared)
}

async fn health() -> &'static str {
    "ok"
}

/// GET /version -> запрос в OceanBase. Если серта ещё нет -> 503 nocert.
async fn version(State(sh): State<Arc<Shared>>) -> Result<Response, ApiError> {
    let db = sh.db.read().await.clone();
    let Some(db) = db else {
        return Err(ApiError::NoCert);
    };
    let body = db.version_json().await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}
