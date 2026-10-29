//! Fault injection: make the next matching requests fail on purpose (or respond slowly), so an
//! app's error handling can be tested. Faults are armed over HTTP (`/dev/api/faults` or `/dev`)
//! and live in memory only.
//!
//! Back-channel endpoints (token, userinfo, JWKS, ...) are handled by a middleware that answers
//! with an OAuth error instead of calling the handler. Authorization requests are handled by the
//! `/authorize` handler itself, so the error is redirected back to the client like a real one.

use std::sync::Mutex;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::no_store;
use crate::inspector::ErrorNote;
use crate::state::AppState;

/// Longest delay a fault may add.
pub const MAX_DELAY_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    Authorize,
    Token,
    Userinfo,
    Jwks,
    Discovery,
    Introspect,
    Revoke,
    DeviceAuthorization,
    Par,
    Register,
    EndSession,
}

impl Endpoint {
    /// The endpoint a path within an issuer belongs to, including provider-specific aliases
    /// (`/login/oauth/access_token`, `/protocol/openid-connect/certs`, `/api/users/@me`, ...).
    /// Authorization endpoints aren't classified: the `/authorize` handler applies those faults.
    pub fn for_path(path: &str) -> Option<Endpoint> {
        let p = path.trim_end_matches('/').to_ascii_lowercase();
        // localoidc's own tools (`/dev/api/token`, ...) are never faulted.
        if p == "/dev" || p.starts_with("/dev/") {
            return None;
        }
        let last = p.rsplit('/').next().unwrap_or_default();
        Some(match last {
            _ if p == "/.well-known/jwks.json" || p == "/jwks" => Endpoint::Jwks,
            _ if p.starts_with("/.well-known/") => Endpoint::Discovery,
            "keys" | "certs" => Endpoint::Jwks,
            "token" | "access_token" => Endpoint::Token,
            "userinfo" | "user" | "me" | "@me" | "emails" => Endpoint::Userinfo,
            "introspect" => Endpoint::Introspect,
            "revoke" => Endpoint::Revoke,
            "device_authorization" => Endpoint::DeviceAuthorization,
            "par" => Endpoint::Par,
            "register" => Endpoint::Register,
            "end_session" | "logout" => Endpoint::EndSession,
            _ => return None,
        })
    }
}

/// How to arm a fault (`POST /dev/api/faults`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultRequest {
    pub endpoint: Endpoint,
    /// Only requests to this issuer: `root` or a preset id. Default: any.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Only requests from this client. Default: any.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Only token requests with this grant type. Default: any.
    #[serde(default)]
    pub grant_type: Option<String>,
    /// The OAuth error to return. Default: `server_error`, or none if only `delay_ms` is set.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
    /// HTTP status for back-channel errors. Default: depends on `error` (401 for `invalid_client`
    /// and `invalid_token`, 500 for `server_error`, 503 for `temporarily_unavailable`, else 400).
    #[serde(default)]
    pub status: Option<u16>,
    /// Wait this long before answering (or before handling, if there's no error).
    #[serde(default)]
    pub delay_ms: u64,
    /// How many matching requests to affect. Default 1.
    #[serde(default)]
    pub count: Option<u32>,
    /// Affect every matching request until the fault is removed.
    #[serde(default)]
    pub always: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fault {
    pub id: u64,
    pub endpoint: Endpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    pub status: u16,
    pub delay_ms: u64,
    /// Requests still to affect; `null` means until removed.
    pub remaining: Option<u32>,
}

impl Fault {
    pub fn from_request(req: FaultRequest) -> Result<Self, String> {
        if req.delay_ms > MAX_DELAY_MS {
            return Err(format!("delay_ms must be at most {MAX_DELAY_MS}"));
        }
        if let Some(status) = req.status
            && !(400..=599).contains(&status)
        {
            return Err("status must be between 400 and 599".into());
        }
        if req.count == Some(0) {
            return Err("count must be at least 1".into());
        }
        if req.always && req.count.is_some() {
            return Err("send count or always, not both".into());
        }
        let error = match req.error.filter(|e| !e.is_empty()) {
            Some(e) => Some(e),
            None if req.delay_ms > 0 && req.status.is_none() => None,
            None => Some(match req.status {
                Some(s) if s >= 500 => "server_error".to_string(),
                Some(_) => "invalid_request".to_string(),
                None => "server_error".to_string(),
            }),
        };
        let status = req.status.unwrap_or(match error.as_deref() {
            Some("invalid_client" | "invalid_token") => 401,
            Some("server_error") => 500,
            Some("temporarily_unavailable") => 503,
            _ => 400,
        });
        Ok(Self {
            id: 0,
            endpoint: req.endpoint,
            issuer: req.issuer.filter(|s| !s.is_empty()),
            client_id: req.client_id.filter(|s| !s.is_empty()),
            grant_type: req.grant_type.filter(|s| !s.is_empty()),
            error,
            error_description: req.error_description.filter(|s| !s.is_empty()),
            status,
            delay_ms: req.delay_ms,
            remaining: if req.always { None } else { Some(req.count.unwrap_or(1)) },
        })
    }

    pub fn description(&self) -> String {
        self.error_description.clone().unwrap_or_else(|| format!("injected by localoidc (fault {})", self.id))
    }

    pub async fn wait(&self) {
        if self.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        }
    }
}

/// What a request looks like to the matcher.
pub struct Target<'a> {
    pub endpoint: Endpoint,
    pub issuer: &'a str,
    pub client_id: Option<&'a str>,
    pub grant_type: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct Faults {
    inner: Mutex<(u64, Vec<Fault>)>,
}

impl Faults {
    pub fn add(&self, mut fault: Fault) -> Fault {
        let mut inner = self.inner.lock().unwrap();
        inner.0 += 1;
        fault.id = inner.0;
        inner.1.push(fault.clone());
        fault
    }

    pub fn list(&self) -> Vec<Fault> {
        self.inner.lock().unwrap().1.clone()
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.1.len();
        inner.1.retain(|f| f.id != id);
        inner.1.len() != before
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().1.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().1.is_empty()
    }

    /// The oldest fault matching `target`, used up by one if it has a count.
    pub fn take(&self, target: &Target) -> Option<Fault> {
        let mut inner = self.inner.lock().unwrap();
        let faults = &mut inner.1;
        let index = faults.iter().position(|f| {
            f.endpoint == target.endpoint
                && f.issuer.as_deref().is_none_or(|i| i == target.issuer)
                && f.client_id.as_deref().is_none_or(|c| Some(c) == target.client_id)
                && f.grant_type.as_deref().is_none_or(|g| Some(g) == target.grant_type)
        })?;
        let fault = faults[index].clone();
        if let Some(remaining) = &mut faults[index].remaining {
            *remaining -= 1;
            if *remaining == 0 {
                faults.remove(index);
            }
        }
        Some(fault)
    }
}

/// The OAuth error response for a back-channel fault.
fn error_response(fault: &Fault, error: &str) -> Response {
    let description = fault.description();
    let status = StatusCode::from_u16(fault.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp =
        (status, no_store(), Json(json!({ "error": error, "error_description": description }))).into_response();
    if let Ok(v) = HeaderValue::from_str(&fault.id.to_string()) {
        resp.headers_mut().insert("x-localoidc-fault", v);
    }
    ErrorNote::attach(&mut resp, error, description);
    resp
}

/// Apply armed faults to back-channel requests.
pub async fn apply(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if state.faults.is_empty() {
        return next.run(request).await;
    }
    let path = request.uri().path().to_string();
    let (issuer, within) = crate::inspector::strip_issuer(&path);
    let Some(endpoint) = Endpoint::for_path(within) else {
        return next.run(request).await;
    };
    // The client and grant type come from the query, a form body or the Authorization header.
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, crate::inspector::MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let params = crate::inspector::request_params(
        parts.uri.query().unwrap_or_default(),
        &crate::inspector::content_type(&parts.headers),
        &body,
    );
    let client = params
        .get("client_id")
        .cloned()
        .filter(|c| !c.is_empty())
        .or_else(|| crate::inspector::describe_authorization(&parts.headers).1);
    let target = Target {
        endpoint,
        issuer,
        client_id: client.as_deref(),
        grant_type: params.get("grant_type").map(String::as_str),
    };
    let fault = state.faults.take(&target);
    let request = Request::from_parts(parts, Body::from(body));
    let Some(fault) = fault else {
        return next.run(request).await;
    };
    fault.wait().await;
    match &fault.error {
        Some(error) => error_response(&fault, error),
        None => next.run(request).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault(json: serde_json::Value) -> Result<Fault, String> {
        Fault::from_request(serde_json::from_value(json).unwrap())
    }

    #[test]
    fn classifies_paths_and_provider_aliases() {
        use Endpoint::*;
        for (path, endpoint) in [
            ("/token", Token),
            ("/login/oauth/access_token", Token),
            ("/protocol/openid-connect/token", Token),
            ("/userinfo", Userinfo),
            ("/oauth2/userInfo", Userinfo),
            ("/api/users/@me", Userinfo),
            ("/jwks", Jwks),
            ("/.well-known/jwks.json", Jwks),
            ("/protocol/openid-connect/certs", Jwks),
            ("/.well-known/openid-configuration", Discovery),
            ("/protocol/openid-connect/token/introspect", Introspect),
            ("/v1/logout", EndSession),
        ] {
            assert_eq!(Endpoint::for_path(path), Some(endpoint), "{path}");
        }
        for path in ["/authorize", "/o/oauth2/v2/auth", "/dev/api/token", "/tokeninfo", "/login"] {
            assert_eq!(Endpoint::for_path(path), None, "{path}");
        }
    }

    #[test]
    fn defaults_and_validation() {
        let f = fault(json!({ "endpoint": "token" })).unwrap();
        assert_eq!((f.error.as_deref(), f.status, f.remaining), (Some("server_error"), 500, Some(1)));
        let f = fault(json!({ "endpoint": "token", "error": "invalid_grant" })).unwrap();
        assert_eq!(f.status, 400);
        let f = fault(json!({ "endpoint": "userinfo", "error": "invalid_token", "always": true })).unwrap();
        assert_eq!((f.status, f.remaining), (401, None));
        let f = fault(json!({ "endpoint": "jwks", "delay_ms": 2000 })).unwrap();
        assert_eq!(f.error, None);
        let f = fault(json!({ "endpoint": "jwks", "status": 503 })).unwrap();
        assert_eq!(f.error.as_deref(), Some("server_error"));
        assert!(fault(json!({ "endpoint": "token", "delay_ms": 60_000 })).is_err());
        assert!(fault(json!({ "endpoint": "token", "status": 200 })).is_err());
        assert!(fault(json!({ "endpoint": "token", "count": 0 })).is_err());
        assert!(fault(json!({ "endpoint": "token", "count": 2, "always": true })).is_err());
        assert!(serde_json::from_value::<FaultRequest>(json!({ "endpoint": "nope" })).is_err());
    }

    #[test]
    fn matching_counts_down_and_filters() {
        let faults = Faults::default();
        faults.add(fault(json!({ "endpoint": "token", "client_id": "a", "count": 2 })).unwrap());
        faults.add(fault(json!({ "endpoint": "token", "grant_type": "refresh_token", "always": true })).unwrap());
        let target = |client: &'static str, grant: &'static str| Target {
            endpoint: Endpoint::Token,
            issuer: "root",
            client_id: Some(client),
            grant_type: Some(grant),
        };
        assert_eq!(faults.take(&target("a", "authorization_code")).map(|f| f.id), Some(1));
        assert_eq!(faults.take(&target("b", "authorization_code")).map(|f| f.id), None);
        assert_eq!(faults.take(&target("a", "authorization_code")).map(|f| f.id), Some(1));
        assert_eq!(faults.take(&target("a", "authorization_code")).map(|f| f.id), None);
        for _ in 0..3 {
            assert_eq!(faults.take(&target("b", "refresh_token")).map(|f| f.id), Some(2));
        }
        assert!(faults.remove(2) && faults.is_empty());
    }
}
