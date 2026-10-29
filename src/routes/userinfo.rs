//! UserInfo, token introspection (RFC 7662) and revocation (RFC 7009).

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::error::{no_store, OAuthError};
use crate::state::{AppState, Grant};
use crate::store::Table;
use crate::tokens::{self, Kind};
use crate::util::{merged_params, non_empty};

/// Bearer token from the Authorization header (`Bearer`, or GitHub-style `token`),
/// falling back to an `access_token` query/body parameter.
pub fn bearer(headers: &HeaderMap, params: &HashMap<String, String>) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            let (scheme, token) = h.split_once(' ')?;
            matches!(scheme.to_ascii_lowercase().as_str(), "bearer" | "token").then(|| token.trim().to_string())
        })
        .or_else(|| non_empty(params, "access_token"))
}

/// Resolve the grant behind an access token presented to a resource endpoint.
pub fn authorize_bearer(state: &AppState, headers: &HeaderMap, params: &HashMap<String, String>) -> Result<Grant, OAuthError> {
    let token = bearer(headers, params).ok_or_else(|| OAuthError::invalid_token("missing access token"))?;
    let verified = tokens::verify(state, &token)
        .filter(|v| v.kind == Kind::Access)
        .ok_or_else(|| OAuthError::invalid_token("access token is invalid, expired or revoked"))?;
    Ok(verified.grant)
}

pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = merged_params(query.as_deref(), &body);
    match authorize_bearer(&state, &headers, &params) {
        Ok(grant) => (no_store(), Json(Value::Object(tokens::userinfo_claims(&grant)))).into_response(),
        Err(e) => e.into_response(),
    }
}

pub async fn introspect(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let params = crate::util::parse_form(&body);
    if let Err(e) = crate::routes::token::authenticate_client(&state, &headers, &params) {
        return e.into_response();
    }
    let Some(token) = non_empty(&params, "token") else {
        return OAuthError::invalid_request("token is required").into_response();
    };
    let Some(v) = tokens::verify(&state, &token) else {
        return (no_store(), Json(json!({ "active": false }))).into_response();
    };
    let mut out = serde_json::Map::new();
    out.insert("active".into(), json!(true));
    for (k, val) in &v.claims {
        if k != "grant" {
            out.insert(k.clone(), val.clone());
        }
    }
    out.entry("sub").or_insert_with(|| json!(v.grant.sub()));
    out.entry("client_id").or_insert_with(|| json!(v.grant.client_id));
    out.entry("scope").or_insert_with(|| json!(v.grant.scope));
    out.insert("exp".into(), json!(v.exp));
    out.insert("iat".into(), json!(v.iat));
    out.insert("token_type".into(), json!(if v.kind == Kind::Access { "Bearer" } else { v.kind.hint() }));
    if let Some(username) = ["preferred_username", "login", "username", "email"]
        .iter()
        .find_map(|k| v.grant.claims.get(*k).and_then(Value::as_str))
    {
        out.insert("username".into(), json!(username));
    }
    (no_store(), Json(Value::Object(out))).into_response()
}

pub async fn revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let params = crate::util::parse_form(&body);
    if let Err(e) = crate::routes::token::authenticate_client(&state, &headers, &params) {
        return e.into_response();
    }
    let Some(token) = non_empty(&params, "token") else {
        return OAuthError::invalid_request("token is required").into_response();
    };
    if !state.store.remove(Table::Opaque, &token)
        && let Some(v) = tokens::verify(&state, &token)
            && let Some(jti) = v.jti {
                state.store.put(Table::Revoked, &jti, &v.exp, Some(v.exp));
            }
    // RFC 7009: respond 200 even for unknown tokens.
    (no_store(), "").into_response()
}
