//! Token endpoint: authorization_code, refresh_token, client_credentials, password,
//! device_code and token-exchange grants.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

use crate::error::{no_store, OAuthError};
use crate::keys::decode_unverified;
use crate::presets;
use crate::state::{AppState, CodeEntry, DeviceEntry, DeviceStatus, Grant};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::tokens::{self, IssueOpts, Kind};
use crate::util::{b64_std_decode, has_scope, merged_params, non_empty, now, parse_claims_object, sha256_b64, value_to_string};

pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Identify (and, for registered confidential clients, authenticate) the calling client.
pub fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Option<String>, OAuthError> {
    let mut id = None;
    let mut secret = None;
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic ").or_else(|| h.strip_prefix("basic ")))
    {
        let decoded = b64_std_decode(basic)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| OAuthError::invalid_client("malformed Basic authorization header"))?;
        let (u, p) = decoded.split_once(':').unwrap_or((&decoded, ""));
        let decode = |s: &str| url::form_urlencoded::parse(format!("x={s}").as_bytes()).next().map(|(_, v)| v.into_owned());
        id = decode(u);
        secret = decode(p);
    }
    if id.is_none() {
        id = non_empty(params, "client_id");
        secret = non_empty(params, "client_secret");
    }
    // private_key_jwt / client_secret_jwt: accepted without verifying the assertion.
    let assertion = non_empty(params, "client_assertion");
    if id.is_none()
        && let Some(Value::Object(claims)) = assertion.as_deref().and_then(decode_unverified) {
            id = claims.get("iss").or_else(|| claims.get("sub")).map(value_to_string);
        }
    let Some(id) = id else { return Ok(None) };

    match state.client(&id) {
        Some(client) => {
            if let Some(expected) = client.client_secret.filter(|s| !s.is_empty())
                && assertion.is_none() && secret.as_deref() != Some(expected.as_str()) {
                    return Err(OAuthError::invalid_client("client authentication failed"));
                }
        }
        None if state.config.strict_clients => {
            return Err(OAuthError::invalid_client(format!("unknown client '{id}'")));
        }
        None => {}
    }
    Ok(Some(id))
}

pub async fn token(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = merged_params(query.as_deref(), &body);
    match handle_token(&state, &tenant, &headers, &params) {
        Ok(v) => (no_store(), Json(v)).into_response(),
        Err(e) => e.into_response(),
    }
}

pub fn handle_token(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let client_id = authenticate_client(state, headers, params)?;
    // GitHub and Facebook omit grant_type on code exchange.
    let grant_type = non_empty(params, "grant_type").or_else(|| params.contains_key("code").then(|| "authorization_code".into()));
    match grant_type.as_deref() {
        Some("authorization_code") => authorization_code(state, tenant, client_id, params),
        Some("refresh_token") => refresh(state, tenant, client_id, params),
        Some("client_credentials") => client_credentials(state, tenant, client_id, params),
        Some("password") => password(state, tenant, client_id, params),
        Some(DEVICE_GRANT) => device_code(state, tenant, client_id, params),
        Some(TOKEN_EXCHANGE_GRANT) => token_exchange(state, tenant, client_id, params),
        Some(other) => Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("unsupported grant_type '{other}'"),
        )),
        None => Err(OAuthError::invalid_request("grant_type is required")),
    }
}

fn require(params: &HashMap<String, String>, key: &str) -> Result<String, OAuthError> {
    non_empty(params, key).ok_or_else(|| OAuthError::invalid_request(format!("{key} is required")))
}

fn audience(params: &HashMap<String, String>) -> Vec<String> {
    ["resource", "audience"]
        .iter()
        .filter_map(|k| non_empty(params, k))
        .flat_map(|v| v.split_whitespace().map(String::from).collect::<Vec<_>>())
        .collect()
}

fn dev_claims(params: &HashMap<String, String>, key: &str) -> Result<Map<String, Value>, OAuthError> {
    parse_claims_object(params.get(key).map(String::as_str).unwrap_or(""))
        .map_err(|e| OAuthError::invalid_request(format!("{key}: {e}")))
}

fn opts_for(state: &AppState, grant: &Grant) -> IssueOpts {
    IssueOpts {
        id_token: has_scope(&grant.scope, "openid"),
        refresh_token: tokens::wants_refresh(state, &grant.scope),
        include_nonce: true,
        ttl: None,
    }
}

fn authorization_code(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let code = require(params, "code")?;
    // Mark the code used atomically. Redeeming it again revokes everything the first
    // redemption issued (RFC 6749 §4.1.2).
    let (first_use, entry) = state
        .store
        .update(Table::Codes, &code, |e: &mut CodeEntry| (!std::mem::replace(&mut e.used, true), e.clone()))
        .ok_or_else(|| OAuthError::invalid_grant("authorization code is invalid"))?;
    if !first_use {
        for token in &entry.issued {
            tokens::revoke(state, token);
        }
        state.store.remove(Table::Codes, &code);
        return Err(OAuthError::invalid_grant("authorization code has already been used; tokens issued from it were revoked"));
    }
    if entry.exp <= now() {
        return Err(OAuthError::invalid_grant("authorization code has expired"));
    }
    if entry.tenant != tenant.key() {
        return Err(OAuthError::invalid_grant("authorization code was issued by a different issuer"));
    }
    if client_id.as_ref().is_some_and(|c| *c != entry.grant.client_id) {
        return Err(OAuthError::invalid_grant("authorization code was issued to a different client"));
    }
    if non_empty(params, "redirect_uri").is_some_and(|r| r != entry.redirect_uri) {
        return Err(OAuthError::invalid_grant("redirect_uri does not match the authorization request"));
    }
    if let Some(challenge) = &entry.code_challenge {
        let verifier = non_empty(params, "code_verifier").ok_or_else(|| OAuthError::invalid_grant("code_verifier is required"))?;
        let computed = match entry.code_challenge_method.as_deref() {
            Some("S256") => sha256_b64(&verifier),
            _ => verifier,
        };
        if &computed != challenge {
            return Err(OAuthError::invalid_grant("PKCE verification failed"));
        }
    }
    let grant = entry.grant;
    let issued = tokens::issue(state, tenant, &grant, &opts_for(state, &grant));
    let tokens: Vec<String> = std::iter::once(issued.access_token.clone()).chain(issued.refresh_token.clone()).collect();
    state.store.update(Table::Codes, &code, |e: &mut CodeEntry| e.issued = tokens);
    Ok(issued.to_json())
}

fn refresh(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let token = require(params, "refresh_token")?;
    let verified = tokens::verify(state, &token)
        .filter(|v| v.kind == Kind::Refresh)
        .ok_or_else(|| OAuthError::invalid_grant("refresh token is invalid, expired or revoked"))?;
    let mut grant = verified.grant;
    if client_id.as_ref().is_some_and(|c| *c != grant.client_id) {
        return Err(OAuthError::invalid_grant("refresh token was issued to a different client"));
    }
    if let Some(requested) = non_empty(params, "scope") {
        if let Some(extra) = requested.split_whitespace().find(|s| !has_scope(&grant.scope, s)) {
            return Err(OAuthError::new(StatusCode::BAD_REQUEST, "invalid_scope", format!("scope '{extra}' was not originally granted")));
        }
        grant.scope = requested;
    }
    let opts = IssueOpts { include_nonce: false, ..opts_for(state, &grant) };
    Ok(tokens::issue(state, tenant, &grant, &opts).to_json())
}

fn client_credentials(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let client_id = client_id.ok_or_else(|| OAuthError::invalid_client("client authentication is required"))?;
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(client_id));
    crate::util::merge_claims(&mut claims, &dev_claims(params, "dev_claims")?);
    let grant = Grant {
        client_id,
        scope: params.get("scope").cloned().unwrap_or_default(),
        preset: "generic".into(),
        claims,
        access_claims: dev_claims(params, "dev_access_claims")?,
        nonce: None,
        auth_time: 0,
        sid: None,
        audience: audience(params),
        acr: None,
        requested_claims: Default::default(),
    };
    let opts = IssueOpts { id_token: false, refresh_token: false, ..Default::default() };
    Ok(tokens::issue(state, tenant, &grant, &opts).to_json())
}

fn password(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let username = require(params, "username")?;
    let preset = non_empty(params, "dev_preset")
        .and_then(|p| presets::get(&p))
        .unwrap_or_else(|| tenant.default_preset(&state.config));
    let mut claims = preset.default_claims();
    preset.apply_login_hint(&mut claims, &username);
    crate::util::merge_claims(&mut claims, &dev_claims(params, "dev_claims")?);
    preset.ensure_sub(&mut claims);
    let grant = Grant {
        client_id: client_id.unwrap_or_else(|| "localoidc-dev".into()),
        scope: params.get("scope").cloned().unwrap_or_else(|| preset.default_scope.into()),
        preset: preset.id.into(),
        claims,
        access_claims: dev_claims(params, "dev_access_claims")?,
        nonce: None,
        auth_time: now(),
        sid: None,
        audience: audience(params),
        acr: None,
        requested_claims: Default::default(),
    };
    Ok(tokens::issue(state, tenant, &grant, &opts_for(state, &grant)).to_json())
}

fn device_code(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let device_code = require(params, "device_code")?;
    enum Poll {
        Expired,
        WrongClient,
        SlowDown,
        Pending,
        Denied,
        Approved(Box<Grant>),
    }
    let t = now();
    // Read-modify-write in one transaction so concurrent polls see consistent slow_down state.
    let poll = state
        .store
        .update(Table::Devices, &device_code, |entry: &mut DeviceEntry| {
            if entry.exp <= t {
                return Poll::Expired;
            }
            if client_id.as_ref().is_some_and(|c| *c != entry.client_id) {
                return Poll::WrongClient;
            }
            match &entry.status {
                DeviceStatus::Pending => {
                    let too_fast = t - entry.last_poll < entry.interval;
                    entry.last_poll = t;
                    if too_fast {
                        entry.interval += 5;
                        Poll::SlowDown
                    } else {
                        Poll::Pending
                    }
                }
                DeviceStatus::Denied => Poll::Denied,
                DeviceStatus::Approved(grant) => Poll::Approved(grant.clone()),
            }
        })
        .ok_or_else(|| OAuthError::invalid_grant("unknown device_code"))?;
    let err = |error, description| Err(OAuthError::new(StatusCode::BAD_REQUEST, error, description));
    match poll {
        Poll::WrongClient => Err(OAuthError::invalid_grant("device_code was issued to a different client")),
        Poll::SlowDown => err("slow_down", "polling too frequently"),
        Poll::Pending => err("authorization_pending", "the user has not yet approved the request"),
        Poll::Expired => {
            state.store.remove(Table::Devices, &device_code);
            err("expired_token", "the device code has expired")
        }
        Poll::Denied => {
            state.store.remove(Table::Devices, &device_code);
            err("access_denied", "the user denied the request")
        }
        Poll::Approved(grant) => {
            // Only the poller that actually removes the row gets the tokens.
            if !state.store.remove(Table::Devices, &device_code) {
                return Err(OAuthError::invalid_grant("device_code has already been used"));
            }
            Ok(tokens::issue(state, tenant, &grant, &opts_for(state, &grant)).to_json())
        }
    }
}

fn token_exchange(
    state: &AppState,
    tenant: &Tenant,
    client_id: Option<String>,
    params: &HashMap<String, String>,
) -> Result<Value, OAuthError> {
    let subject = require(params, "subject_token")?;
    let verified = tokens::verify(state, &subject)
        .ok_or_else(|| OAuthError::invalid_grant("subject_token is invalid, expired or revoked"))?;
    let mut grant = verified.grant;
    if let Some(c) = client_id {
        grant.client_id = c;
    }
    let aud = audience(params);
    if !aud.is_empty() {
        grant.audience = aud;
    }
    if let Some(scope) = non_empty(params, "scope") {
        grant.scope = scope;
    }
    crate::util::merge_claims(&mut grant.access_claims, &dev_claims(params, "dev_access_claims")?);
    let (access_token, expires_in) = tokens::access_token(state, tenant, &grant, None);
    Ok(json!({
        "access_token": access_token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": grant.scope,
    }))
}
