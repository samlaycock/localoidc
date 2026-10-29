//! Non-standard developer endpoints: a token generator page and JSON API.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

use crate::error::{OAuthError, no_store};
use crate::html::{data_script, esc, page};
use crate::keys::decode_unverified;
use crate::presets;
use crate::routes::authorize::{current_session, editor_data};
use crate::state::{AppState, Grant};
use crate::tenant::Tenant;
use crate::tokens::{self, IssueOpts};
use crate::util::{has_scope, merge_claims, now};

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
        auth_time: now(),
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

pub async fn api_presets() -> impl IntoResponse {
    Json(presets::all())
}

/// The declared users, with their claims as this issuer would issue them.
pub async fn api_users(State(state): State<AppState>, tenant: Tenant) -> impl IntoResponse {
    let fallback = tenant.default_preset(&state.config);
    Json(state.config.users.iter().map(|u| u.to_json(fallback)).collect::<Vec<_>>())
}

pub async fn page_handler(State(state): State<AppState>, tenant: Tenant, headers: HeaderMap) -> Response {
    let preset = tenant.default_preset(&state.config);
    let previous = current_session(&state, &tenant, &headers).map(|(_, s)| s);
    let api = tenant.url("/dev/api/token");
    let body = format!(
        r#"<div class="layout dev">
<section class="card editor-card">
  <div class="eyebrow">Token generator</div>
  <h1>Mint tokens for <span class="accent">{issuer}</span></h1>
  <p class="muted">Generate access, ID and refresh tokens without running a login flow. Scripts and tests can use the same thing via <code>POST {api}</code>.</p>
  <div class="opts" id="dev-options">
    <label>client_id<input id="dev-client" value="localoidc-dev"></label>
    <label>Access token audience<input id="dev-audience" placeholder="defaults to client_id"></label>
    <label>Scope<input id="dev-scope" value="{scope}"></label>
    <label>Lifetime (s)<input id="dev-ttl" type="number" value="{ttl}"></label>
    <label>Nonce<input id="dev-nonce" placeholder="optional"></label>
    <div class="checks">
      <label class="check"><input type="checkbox" id="dev-idtoken" checked> ID token</label>
      <label class="check"><input type="checkbox" id="dev-refresh" checked> Refresh token</label>
    </div>
  </div>
  <div id="lo-editor"></div>
  <div class="actions"><button class="btn primary" id="dev-generate" type="button">Generate tokens</button></div>
</section>
<section class="card result" id="dev-result" hidden></section>
<section class="card">
  <div class="eyebrow">Signing key</div>
  <p class="muted">Tokens are signed with key <code id="dev-kid">{kid}</code>. Rotating creates a new key; the previous {kept} stay in the JWKS so tokens already issued keep verifying. Scripts can use <code>POST {rotate}</code>.</p>
  <div class="actions"><button class="btn" id="dev-rotate" type="button">Rotate signing key</button></div>
</section>
</div>
{data}"#,
        issuer = esc(&tenant.issuer),
        api = esc(&api),
        scope = esc(preset.default_scope),
        ttl = state.config.access_token_ttl,
        kid = esc(&state.keys.kid()),
        kept = crate::keys::RETIRED_KEYS_KEPT,
        rotate = esc(&tenant.url("/dev/api/rotate-keys")),
        data = data_script(&editor_data(
            &state,
            &tenant,
            "dev",
            previous.as_ref(),
            None,
            json!({ "api": api, "rotateApi": tenant.url("/dev/api/rotate-keys") }),
        )),
    );
    (StatusCode::OK, page(&tenant, "Token generator", &body)).into_response()
}
