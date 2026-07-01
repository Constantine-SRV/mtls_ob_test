//! Single API error type. NoCert -> 503, everything else -> 500, JSON body.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

pub enum ApiError {
    NoCert,
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiError::NoCert => (StatusCode::SERVICE_UNAVAILABLE, "nocert".to_string()),
            ApiError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let body = serde_json::json!({ "error": msg }).to_string();
        (code, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        ApiError::Internal(e.into())
    }
}
