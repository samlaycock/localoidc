//! Non-standard developer endpoints: a token generator page and JSON API.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

use crate::error::{OAuthError, no_store};
use crate::html::app_page;
use crate::keys::decode_unverified;
use crate::presets;
use crate::state::{AppState, Grant};
use crate::tenant::Tenant;
use crate::tokens::{self, IssueOpts};
use crate::util::{has_scope, merge_claims};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DevTokenRequest {
    /// Declared user (`[[users]]` in the config file) whose claims `claims` are merged over.
    pub user: Option<String>,
    /// Provider preset whose claim shape/defaults are used.
    pub preset: Option<String>,
    pub client_id: Option<String>,
    pub audience: Option<OneOrMany>,
    pub scope: Option<String>,
    /// Identity claims (ID token + userinfo + access token), merged over the preset defaults.
    pub claims: Map<String, Value>,
    /// Claims placed only in the access token.
    pub access_token_claims: Map<String, Value>,
    /// Merge `claims` over the preset defaults (default true).
    pub defaults: Option<bool>,
    /// Lifetime of the access and ID tokens in seconds.
    pub expires_in: Option<i64>,
    pub id_token: Option<bool>,
    pub refresh_token: Option<bool>,
    pub nonce: Option<String>,
}

pub fn mint(state: &AppState, tenant: &Tenant, req: DevTokenRequest) -> Result<Value, OAuthError> {
    let explicit = match &req.preset {
        Some(id) => {
            Some(presets::get(id).ok_or_else(|| OAuthError::invalid_request(format!("unknown preset '{id}'")))?)
        }
        None => None,
    };
    let fallback = tenant.default_preset(&state.config);
    let (preset, mut claims, mut access_claims) = match &req.user {
        Some(id) => state
            .config
            .user(id)
            .ok_or_else(|| OAuthError::invalid_request(format!("unknown user '{id}'")))?
            .resolve(explicit, fallback),
        None => {
            let preset = explicit.unwrap_or(fallback);
            let claims = if req.defaults.unwrap_or(true) { preset.default_claims() } else { Map::new() };
            (preset, claims, Map::new())
        }
    };
    preset.apply_overrides(&mut claims, &req.claims);
    merge_claims(&mut access_claims, &req.access_token_claims);
    let scope = req.scope.unwrap_or_else(|| preset.default_scope.to_string());
    let grant = Grant {
        client_id: req.client_id.unwrap_or_else(|| "localoidc-dev".into()),
        scope: scope.clone(),
        preset: preset.id.into(),
        claims,
        access_claims,
        nonce: req.nonce,
        auth_time: state.now(),
        sid: Some(uuid::Uuid::new_v4().to_string()),
        audience: match req.audience {
            Some(OneOrMany::One(a)) => a.split_whitespace().map(String::from).collect(),
            Some(OneOrMany::Many(a)) => a,
            None => vec![],
        },
        acr: None,
        requested_claims: Default::default(),
    };
    let opts = IssueOpts {
        id_token: req.id_token.unwrap_or_else(|| has_scope(&scope, "openid") || preset.protocol == "oidc"),
        refresh_token: req.refresh_token.unwrap_or(true),
        include_nonce: true,
        ttl: req.expires_in,
    };
    let issued = tokens::issue(state, tenant, &grant, &opts);
    let mut out = issued.to_json();
    out["issuer"] = json!(tenant.issuer);
    out["preset"] = json!(preset.id);
    out["access_token_claims"] = decode_unverified(&issued.access_token).unwrap_or_else(|| {
        json!({ "opaque": true, "note": format!("{} uses opaque access tokens; use /userinfo or /introspect", preset.name) })
    });
    if let Some(id) = &issued.id_token {
        out["id_token_claims"] = decode_unverified(id).unwrap_or(Value::Null);
    }
    if issued.refresh_token.is_some() {
        out["refresh_token_expires_in"] = json!(state.config.refresh_token_ttl);
    }
    Ok(out)
}

pub async fn api_token_post(
    State(state): State<AppState>,
    tenant: Tenant,
    Json(req): Json<DevTokenRequest>,
) -> Response {
    match mint(&state, &tenant, req) {
        Ok(v) => (no_store(), Json(v)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// GET variant for quick curl use: known keys are options, every other query parameter becomes a claim.
pub async fn api_token_get(
    State(state): State<AppState>,
    tenant: Tenant,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let mut req = DevTokenRequest::default();
    for (k, v) in q {
        let parse_json = |raw: &str| {
            crate::util::parse_claims_object(raw).map_err(|e| OAuthError::invalid_request(format!("{k}: {e}")))
        };
        match k.as_str() {
            "user" => req.user = Some(v),
            "preset" => req.preset = Some(v),
            "client_id" => req.client_id = Some(v),
            "audience" | "aud" => req.audience = Some(OneOrMany::One(v)),
            "scope" => req.scope = Some(v),
            "nonce" => req.nonce = Some(v),
            "expires_in" => req.expires_in = v.parse().ok(),
            "defaults" => req.defaults = Some(v != "false"),
            "id_token" => req.id_token = Some(v != "false"),
            "refresh_token" => req.refresh_token = Some(v != "false"),
            "claims" => match parse_json(&v) {
                Ok(m) => req.claims.extend(m),
                Err(e) => return e.into_response(),
            },
            "access_token_claims" => match parse_json(&v) {
                Ok(m) => req.access_token_claims = m,
                Err(e) => return e.into_response(),
            },
            "format" => {}
            _ => {
                // `sub` always stays a string; other values are parsed as JSON when possible.
                let value = match serde_json::from_str::<Value>(&v) {
                    Ok(parsed) if k != "sub" && !parsed.is_string() => parsed,
                    _ => Value::String(v),
                };
                req.claims.insert(k, value);
            }
        }
    }
    match mint(&state, &tenant, req) {
        Ok(v) => (no_store(), Json(v)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Non-standard: rotate the signing key (shared by every issuer). The previous keys stay in the
/// JWKS so already-issued tokens keep verifying.
pub async fn api_rotate_keys(State(state): State<AppState>, tenant: Tenant) -> Response {
    let keys = state.keys.clone();
    match tokio::task::spawn_blocking(move || keys.rotate()).await {
        Ok(Ok(rotation)) => (
            no_store(),
            Json(json!({
                "kid": rotation.kid,
                "retired_kids": rotation.retired_kids,
                "jwks_uri": tenant.url("/jwks"),
            })),
        )
            .into_response(),
        Ok(Err(e)) => {
            OAuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("key rotation failed: {e:#}"))
                .into_response()
        }
        Err(e) => {
            OAuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("key rotation panicked: {e}"))
                .into_response()
        }
    }
}

/// A duration as seconds (`3600`) or text (`"1h"`, `"31d"`, `"-5m"`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum DurationValue {
    Seconds(i64),
    Text(String),
}

impl DurationValue {
    fn seconds(&self) -> Result<i64, String> {
        match self {
            DurationValue::Seconds(s) => Ok(*s),
            DurationValue::Text(t) => crate::util::parse_duration(t),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClockRequest {
    /// Set the offset from real time.
    pub offset: Option<DurationValue>,
    /// Move the clock by this much (negative moves it back).
    pub advance: Option<DurationValue>,
    /// Go back to real time.
    pub reset: bool,
}

/// Offsets beyond this are almost certainly typos, and would overflow timestamp arithmetic.
const MAX_CLOCK_OFFSET: i64 = 100 * 365 * 86_400;

fn clock_json(state: &AppState) -> Value {
    let offset = state.clock().offset();
    json!({
        "now": state.now(),
        "offset": offset,
        "offset_text": crate::util::format_duration(offset),
        "real_now": crate::util::wall_clock(),
    })
}

/// Non-standard: the server clock and its offset from real time.
pub async fn api_clock(State(state): State<AppState>) -> Response {
    (no_store(), Json(clock_json(&state))).into_response()
}

/// Non-standard: shift the server clock (`offset`, `advance` or `reset`). Shared by every issuer.
pub async fn api_clock_set(State(state): State<AppState>, Json(req): Json<ClockRequest>) -> Response {
    let invalid = |msg: String| OAuthError::invalid_request(msg).into_response();
    let parse = |v: &DurationValue, field: &str| v.seconds().map_err(|e| format!("{field}: {e}"));
    let target = match (&req.offset, &req.advance, req.reset) {
        (Some(v), None, false) => parse(v, "offset"),
        (None, Some(v), false) => parse(v, "advance").map(|by| state.clock().offset().saturating_add(by)),
        (None, None, true) => Ok(0),
        _ => Err("send exactly one of offset, advance or reset".into()),
    };
    let offset = match target {
        Ok(o) if o.abs() <= MAX_CLOCK_OFFSET => o,
        Ok(_) => return invalid("clock offset must be within 100 years of real time".into()),
        Err(e) => return invalid(e),
    };
    state.clock().set_offset(offset);
    tracing::info!("clock offset set to {}", crate::util::format_duration(offset));
    (no_store(), Json(clock_json(&state))).into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RequestsQuery {
    pub client_id: Option<String>,
    pub errors: Option<bool>,
    pub after: Option<u64>,
    pub limit: Option<usize>,
}

/// Non-standard: recent requests to every issuer, newest first (see `crate::inspector`).
pub async fn api_requests(State(state): State<AppState>, Query(q): Query<RequestsQuery>) -> Response {
    let filter = crate::inspector::Filter {
        client_id: q.client_id.filter(|c| !c.is_empty()),
        errors_only: q.errors.unwrap_or(false),
        after: q.after,
        limit: q.limit,
    };
    let body = json!({
        "entries": state.inspector.list(&filter),
        // Lets a poller notice a restart: ids start again from 1.
        "latest_id": state.inspector.latest_id(),
        "capacity": crate::inspector::CAPACITY,
    });
    (no_store(), Json(body)).into_response()
}

pub async fn api_requests_clear(State(state): State<AppState>) -> StatusCode {
    state.inspector.clear();
    StatusCode::NO_CONTENT
}

/// The request inspector's page.
pub async fn requests_page(tenant: Tenant) -> Response {
    app_page(&tenant, "Requests")
}

/// Non-standard: the armed faults (see `crate::faults`).
pub async fn api_faults(State(state): State<AppState>) -> Response {
    (no_store(), Json(state.faults.list())).into_response()
}

/// Non-standard: arm a fault, e.g. `{"endpoint": "token", "error": "invalid_grant"}`.
pub async fn api_faults_add(State(state): State<AppState>, Json(req): Json<crate::faults::FaultRequest>) -> Response {
    match crate::faults::Fault::from_request(req) {
        Ok(fault) => {
            let fault = state.faults.add(fault);
            tracing::info!("fault {} armed for {:?}", fault.id, fault.endpoint);
            (StatusCode::CREATED, no_store(), Json(fault)).into_response()
        }
        Err(e) => OAuthError::invalid_request(e).into_response(),
    }
}

pub async fn api_faults_remove(
    State(state): State<AppState>,
    axum::extract::Path(params): axum::extract::Path<HashMap<String, String>>,
) -> Response {
    let removed = params.get("id").and_then(|id| id.parse().ok()).is_some_and(|id| state.faults.remove(id));
    if removed { StatusCode::NO_CONTENT.into_response() } else { StatusCode::NOT_FOUND.into_response() }
}

pub async fn api_faults_clear(State(state): State<AppState>) -> StatusCode {
    state.faults.clear();
    StatusCode::NO_CONTENT
}

/// Non-standard: active browser sessions on every issuer.
pub async fn api_sessions(State(state): State<AppState>) -> Response {
    let sessions: Vec<Value> = state
        .store
        .entries::<crate::state::Session>(crate::store::Table::Sessions)
        .iter()
        .map(|(sid, session, exp)| {
            let mut json = crate::backchannel::describe(sid, session, *exp);
            // Who it is, for people reading the list, and which clients would be told it ended.
            json["label"] = json!(
                ["email", "name", "preferred_username", "login", "sub"]
                    .iter()
                    .find_map(|k| session.claims.get(*k).map(crate::util::value_to_string))
            );
            json["backchannel_clients"] = json!(
                session
                    .clients
                    .iter()
                    .filter(|c| state.client(c).and_then(|c| c.backchannel_logout_uri).is_some())
                    .collect::<Vec<_>>()
            );
            json
        })
        .collect();
    (no_store(), Json(sessions)).into_response()
}

/// Non-standard: end a session as if the user logged out elsewhere, sending back-channel
/// logout tokens to the clients that used it.
pub async fn api_sessions_end(
    State(state): State<AppState>,
    tenant: Tenant,
    axum::extract::Path(params): axum::extract::Path<HashMap<String, String>>,
) -> Response {
    let sid = params.get("sid").cloned().unwrap_or_default();
    match crate::backchannel::end_session(&state, &sid, &tenant.issuer).await {
        Some(deliveries) => (no_store(), Json(json!({ "sid": sid, "deliveries": deliveries }))).into_response(),
        None => {
            OAuthError::new(StatusCode::NOT_FOUND, "not_found", format!("no active session '{sid}'")).into_response()
        }
    }
}

pub async fn api_presets() -> impl IntoResponse {
    Json(presets::all())
}

/// The declared users, with their claims as this issuer would issue them.
pub async fn api_users(State(state): State<AppState>, tenant: Tenant) -> impl IntoResponse {
    let fallback = tenant.default_preset(&state.config);
    Json(state.config.users.iter().map(|u| u.to_json(fallback)).collect::<Vec<_>>())
}

const FAULT_ENDPOINTS: &[&str] = &[
    "token",
    "authorize",
    "userinfo",
    "jwks",
    "discovery",
    "introspect",
    "revoke",
    "device_authorization",
    "par",
    "register",
    "end_session",
];
const FAULT_ERRORS: &[&str] = &[
    "server_error",
    "temporarily_unavailable",
    "invalid_grant",
    "invalid_client",
    "invalid_token",
    "invalid_request",
    "invalid_scope",
    "unauthorized_client",
    "access_denied",
    "login_required",
    "consent_required",
    "interaction_required",
];

/// Non-standard: what the web UI shows about this issuer: its endpoints, the other issuers, the
/// clock and the armed faults (for the warning banners), and the token generator's defaults.
pub async fn api_info(State(state): State<AppState>, tenant: Tenant) -> Response {
    let u = |p: &str| tenant.url(p);
    let mut endpoints = vec![
        ("Discovery", u("/.well-known/openid-configuration")),
        ("JWKS", u("/jwks")),
        ("Authorization", u("/authorize")),
        ("Token", u("/token")),
        ("UserInfo", u("/userinfo")),
        ("Introspection", u("/introspect")),
        ("Revocation", u("/revoke")),
        ("End session", u("/end_session")),
        ("Device authorization", u("/device_authorization")),
        ("Pushed auth requests", u("/par")),
        ("Client registration", u("/register")),
        ("Dev token API (non-standard)", u("/dev/api/token")),
    ];
    if let Some(p) = tenant.preset {
        for (label, path) in &p.endpoints {
            endpoints.push((label, u(path)));
        }
    }
    let root = Tenant::new(&state.config.issuer, None);
    let mut issuers = vec![json!({
        "id": null,
        "name": "Root issuer",
        "description": "preset chosen at login",
        "issuer": root.issuer,
        "prefix": root.prefix,
    })];
    for p in presets::all() {
        let t = Tenant::new(&state.config.issuer, Some(p));
        issuers.push(json!({
            "id": p.id,
            "name": p.name,
            "description": p.protocol,
            "color": p.color,
            "issuer": t.issuer,
            "prefix": t.prefix,
        }));
    }
    let preset = tenant.default_preset(&state.config);
    let body = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "issuer": tenant.issuer,
        "prefix": tenant.prefix,
        "preset": tenant.preset.map(|p| json!({ "id": p.id, "name": p.name, "color": p.color })),
        "default_preset": preset.id,
        "default_scope": preset.default_scope,
        "access_token_ttl": state.config.access_token_ttl,
        "clock": clock_json(&state),
        "faults_armed": state.faults.list().len(),
        "kid": state.keys.kid(),
        "retired_keys_kept": crate::keys::RETIRED_KEYS_KEPT,
        "endpoints": endpoints.iter().map(|(label, url)| json!({ "label": label, "url": url })).collect::<Vec<_>>(),
        "issuers": issuers,
        "fault_endpoints": FAULT_ENDPOINTS,
        "fault_errors": FAULT_ERRORS,
        "max_fault_delay_ms": crate::faults::MAX_DELAY_MS,
        "requests_capacity": crate::inspector::CAPACITY,
    });
    (no_store(), Json(body)).into_response()
}

/// The token generator's page.
pub async fn page_handler(tenant: Tenant) -> Response {
    app_page(&tenant, "Token generator")
}
