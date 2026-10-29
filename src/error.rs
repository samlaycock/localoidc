use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// An RFC 6749 style error response.
#[derive(Debug)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    pub fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self { status, error, description: description.into() }
    }
    pub fn invalid_request(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", d)
    }
    pub fn invalid_grant(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", d)
    }
    pub fn invalid_client(d: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", d)
    }
    pub fn invalid_token(d: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_token", d)
    }

    pub fn body(&self) -> serde_json::Value {
        json!({ "error": self.error, "error_description": self.description })
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let mut resp = (self.status, no_store(), Json(self.body())).into_response();
        crate::inspector::ErrorNote::attach(&mut resp, self.error, &self.description);
        if self.status == StatusCode::UNAUTHORIZED {
            let challenge = if self.error == "invalid_client" {
                r#"Basic realm="localoidc""#.to_string()
            } else {
                format!(r#"Bearer error="{}", error_description="{}""#, self.error, self.description.replace('"', "'"))
            };
            if let Ok(v) = challenge.parse() {
                resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
            }
        }
        resp
    }
}

pub fn no_store() -> [(header::HeaderName, &'static str); 2] {
    [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")]
}
