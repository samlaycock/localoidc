//! Authorization endpoint, login UI, PAR and response delivery.

use std::collections::{BTreeSet, HashMap};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::{Map, Value, json};

use crate::error::{OAuthError, no_store};
use crate::html::{data_script, error_page, esc, form_post, page};
use crate::keys::{decode_header_unverified, decode_unverified, verify_rs256_with_jwks};
use crate::presets;
use crate::state::{AppState, AuthRequest, CodeEntry, Grant, Session};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::tokens;
use crate::util::{
    has_scope, merged_params, non_empty, parse_claims_object, parse_form, random_string, value_to_string,
};

pub const PAR_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

const RESPONSE_TYPES: &[&str] =
    &["code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token", "none"];

pub fn normalize_response_type(rt: &str) -> String {
    let set: BTreeSet<&str> = rt.split_whitespace().collect();
    // Canonical order: code, id_token, token, none.
    ["code", "id_token", "token", "none"].into_iter().filter(|t| set.contains(t)).collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

pub fn current_session(state: &AppState, tenant: &Tenant, headers: &HeaderMap) -> Option<(String, Session)> {
    let sid = cookie_value(headers, &tenant.cookie_name())?;
    let session = state.store.get::<Session>(Table::Sessions, &sid)?;
    Some((sid, session))
}

fn session_cookie(tenant: &Tenant, sid: &str, max_age: i64) -> String {
    format!("{}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}", tenant.cookie_name())
}

pub fn clear_session_cookie(tenant: &Tenant) -> String {
    format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", tenant.cookie_name())
}

// ---------------------------------------------------------------------------
// Response delivery
// ---------------------------------------------------------------------------

fn deliver(redirect_uri: &str, mode: &str, params: Vec<(String, String)>) -> Response {
    if mode == "form_post" {
        return form_post(redirect_uri, &params).into_response();
    }
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "invalid redirect_uri").into_response();
    };
    if mode == "fragment" {
        let fragment = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&params).finish();
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().extend_pairs(&params);
    }
    Redirect::to(url.as_str()).into_response()
}

fn redirect_error(
    tenant: &Tenant,
    redirect_uri: &str,
    mode: &str,
    state_param: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    let mut params =
        vec![("error".to_string(), error.to_string()), ("error_description".to_string(), description.to_string())];
    if let Some(s) = state_param {
        params.push(("state".into(), s.into()));
    }
    params.push(("iss".into(), tenant.issuer.clone()));
    deliver(redirect_uri, mode, params)
}

fn auth_error(tenant: &Tenant, req: &AuthRequest, error: &str, description: &str) -> Response {
    redirect_error(tenant, &req.redirect_uri, &req.response_mode, req.state.as_deref(), error, description)
}

// ---------------------------------------------------------------------------
// /authorize
// ---------------------------------------------------------------------------

pub async fn authorize(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = merged_params(query.as_deref(), &body);
    handle_authorize(&state, &tenant, &headers, params).await
}

pub async fn handle_authorize(
    state: &AppState,
    tenant: &Tenant,
    headers: &HeaderMap,
    mut params: HashMap<String, String>,
) -> Response {
    let bad = |title: &str, detail: &str| error_page(tenant, StatusCode::BAD_REQUEST, title, detail);

    // request_uri: a pushed authorization request (RFC 9126) or a request object by reference (RFC 9101 §5.2).
    if let Some(uri) = non_empty(&params, "request_uri") {
        if let Some(id) = uri.strip_prefix(PAR_PREFIX) {
            let Some(pushed) = state.store.get::<HashMap<String, String>>(Table::Par, id) else {
                return bad("Unknown request_uri", "The pushed authorization request was not found or has expired.");
            };
            if params.get("client_id").is_some_and(|c| Some(c) != pushed.get("client_id")) {
                return bad("client_id mismatch", "client_id does not match the pushed authorization request.");
            }
            params = pushed;
        } else if uri.starts_with("https://") || uri.starts_with("http://") {
            match crate::fetch::text(&uri).await {
                Ok(jwt) => {
                    params.remove("request_uri");
                    params.insert("request".into(), jwt.trim().to_string());
                }
                Err(e) => return bad("Unable to fetch request_uri", &e),
            }
        } else {
            return bad("Unsupported request_uri", "request_uri must be an http(s) URL or come from the PAR endpoint.");
        }
    }

    // Request objects (RFC 9101). RS256 objects are verified when the client has registered keys;
    // other algorithms, and clients without keys, are accepted unverified.
    if let Some(request) = non_empty(&params, "request") {
        let (Some(header), Some(Value::Object(payload))) =
            (decode_header_unverified(&request), decode_unverified(&request))
        else {
            return bad("Invalid request object", "The request object is not a decodable JWT.");
        };
        let inner_client = payload.get("client_id").map(value_to_string);
        if let (Some(outer), Some(inner)) = (non_empty(&params, "client_id"), &inner_client)
            && outer != *inner
        {
            return bad("client_id mismatch", "client_id in the request object does not match the request.");
        }
        let alg = header["alg"].as_str().unwrap_or("none");
        let client = non_empty(&params, "client_id").or(inner_client).and_then(|c| state.client(&c));
        if alg != "none"
            && let Some(client) = client
        {
            let jwks = match (client.jwks, client.jwks_uri) {
                (Some(jwks), _) => Some(jwks),
                (None, Some(uri)) => match crate::fetch::json(&uri).await {
                    Ok(jwks) => Some(jwks),
                    Err(e) => return bad("Unable to fetch client jwks_uri", &e),
                },
                (None, None) => None,
            };
            if let Some(jwks) = jwks {
                if alg != "RS256" {
                    return bad(
                        "Unsupported request object algorithm",
                        &format!("'{alg}' request objects are not supported; use RS256 or none."),
                    );
                }
                if verify_rs256_with_jwks(&request, &jwks).is_none() {
                    return bad(
                        "Invalid request object",
                        "The request object signature does not verify against the client's registered keys.",
                    );
                }
            }
        }
        for (k, v) in payload {
            if !matches!(k.as_str(), "iss" | "aud" | "exp" | "iat" | "nbf" | "jti") {
                params.insert(k, value_to_string(&v));
            }
        }
    }

    let Some(client_id) = non_empty(&params, "client_id") else {
        return bad("Missing client_id", "The authorization request did not include a client_id.");
    };
    let client = state.client(&client_id);
    if client.is_none() && state.config.strict_clients {
        return bad("Unknown client", &format!("Client '{client_id}' is not registered (strict mode)."));
    }

    let redirect_uri = match non_empty(&params, "redirect_uri") {
        Some(r) => {
            if let Some(c) = &client
                && !c.redirect_uris.is_empty()
                && !c.redirect_uris.contains(&r)
            {
                return bad("Invalid redirect_uri", &format!("'{r}' is not registered for client '{client_id}'."));
            }
            r
        }
        None => match client.as_ref().map(|c| c.redirect_uris.as_slice()) {
            Some([only]) => only.clone(),
            _ => return bad("Missing redirect_uri", "The authorization request did not include a redirect_uri."),
        },
    };
    if url::Url::parse(&redirect_uri).is_err() {
        return bad("Invalid redirect_uri", &format!("'{redirect_uri}' is not an absolute URL."));
    }

    let state_param = non_empty(&params, "state");
    // OAuth2-only providers (GitHub, Facebook, Discord) don't require response_type.
    let rt_default = if tenant.preset.is_some_and(|p| p.protocol == "oauth2") { "code" } else { "" };
    let response_type = normalize_response_type(params.get("response_type").map(String::as_str).unwrap_or(rt_default));
    let implicitish = response_type.contains("token");
    let default_mode = if implicitish { "fragment" } else { "query" };
    let mode = params.get("response_mode").cloned().unwrap_or_else(|| default_mode.into());
    let fail = |error: &str, description: &str| {
        let mode =
            if ["query", "fragment", "form_post"].contains(&mode.as_str()) { mode.as_str() } else { default_mode };
        redirect_error(tenant, &redirect_uri, mode, state_param.as_deref(), error, description)
    };

    if !["query", "fragment", "form_post"].contains(&mode.as_str()) {
        return fail("invalid_request", &format!("unsupported response_mode '{mode}'"));
    }
    if !RESPONSE_TYPES.contains(&response_type.as_str()) {
        let raw = params.get("response_type").cloned().unwrap_or_default();
        return fail("unsupported_response_type", &format!("unsupported response_type '{raw}'"));
    }
    if mode == "query" && implicitish {
        return fail("invalid_request", "response_mode=query is not allowed when tokens are returned");
    }
    let scope = params.get("scope").cloned().unwrap_or_default();
    let wants_id_token = response_type.split(' ').any(|t| t == "id_token");
    if wants_id_token && !has_scope(&scope, "openid") {
        return fail("invalid_scope", "the openid scope is required when requesting an id_token");
    }
    let nonce = non_empty(&params, "nonce");
    if wants_id_token && nonce.is_none() {
        return fail("invalid_request", "nonce is required for implicit and hybrid flows");
    }
    let code_challenge = non_empty(&params, "code_challenge");
    let code_challenge_method =
        code_challenge.as_ref().map(|_| non_empty(&params, "code_challenge_method").unwrap_or_else(|| "plain".into()));
    if let Some(m) = &code_challenge_method
        && m != "S256"
        && m != "plain"
    {
        return fail("invalid_request", "code_challenge_method must be S256 or plain");
    }
    let prompt: Vec<String> =
        params.get("prompt").map(|p| p.split_whitespace().map(String::from).collect()).unwrap_or_default();
    if prompt.iter().any(|p| p == "none") && prompt.len() > 1 {
        return fail("invalid_request", "prompt=none cannot be combined with other values");
    }
    let max_age = params.get("max_age").and_then(|m| m.parse::<i64>().ok());
    let audience: Vec<String> = ["resource", "audience"]
        .iter()
        .filter_map(|k| non_empty(&params, k))
        .flat_map(|v| v.split_whitespace().map(String::from).collect::<Vec<_>>())
        .collect();
    let requested_claims = match non_empty(&params, "claims") {
        Some(raw) => match crate::state::RequestedClaims::parse(&raw) {
            Ok(c) => c,
            Err(e) => return fail("invalid_request", &e),
        },
        None => Default::default(),
    };

    let req = AuthRequest {
        id: uuid::Uuid::new_v4().to_string(),
        created: state.now(),
        tenant: tenant.key().to_string(),
        client_id,
        redirect_uri: redirect_uri.clone(),
        response_type,
        response_mode: mode.clone(),
        scope,
        state: state_param.clone(),
        nonce,
        code_challenge,
        code_challenge_method,
        prompt,
        max_age,
        login_hint: non_empty(&params, "login_hint"),
        acr_values: non_empty(&params, "acr_values"),
        audience,
        requested_claims,
    };

    let default_preset = tenant.default_preset(&state.config);

    // Non-standard: `dev_user` (a declared user) and/or `dev_claims` (JSON or base64url JSON) sign
    // in immediately, for automated tests. `dev_claims` are merged over the user's claims.
    let dev_user = non_empty(&params, "dev_user");
    let dev_claims = non_empty(&params, "dev_claims");
    if dev_user.is_some() || dev_claims.is_some() {
        let overrides = match dev_claims.as_deref().map(parse_claims_object).transpose() {
            Ok(m) => m.unwrap_or_default(),
            Err(e) => return fail("invalid_request", &format!("dev_claims: {e}")),
        };
        let explicit = non_empty(&params, "dev_preset").and_then(|p| presets::get(&p));
        let (preset, mut claims, access) = match dev_user {
            Some(id) => match state.config.user(&id) {
                Some(user) => user.resolve(explicit, default_preset),
                None => return fail("invalid_request", &format!("dev_user: unknown user '{id}'")),
            },
            None => {
                let preset = explicit.unwrap_or(default_preset);
                let mut claims = preset.default_claims();
                if let Some(hint) = &req.login_hint {
                    preset.apply_login_hint(&mut claims, hint);
                }
                (preset, claims, Map::new())
            }
        };
        preset.apply_overrides(&mut claims, &overrides);
        return complete(state, tenant, &req, preset.id, claims, access, None);
    }

    let session = current_session(state, tenant, headers);
    let session_fresh = |s: &Session| req.max_age.is_none_or(|max| state.now() - s.auth_time <= max);
    let force_login = req.prompt.iter().any(|p| p == "login");

    if req.prompt.iter().any(|p| p == "none") {
        return match session {
            Some((sid, s)) if session_fresh(&s) => {
                complete(state, tenant, &req, &s.preset, s.claims, s.access_claims, Some((sid, s.auth_time)))
            }
            _ => auth_error(tenant, &req, "login_required", "no active session"),
        };
    }

    if state.config.auto_login && !force_login {
        return match session {
            Some((sid, s)) if session_fresh(&s) => {
                complete(state, tenant, &req, &s.preset, s.claims, s.access_claims, Some((sid, s.auth_time)))
            }
            _ => {
                // A login_hint naming a declared user (by id or email) signs in as that user.
                let user = req.login_hint.as_deref().and_then(|h| state.config.user_for_login(h));
                let (preset, claims, access) = match user {
                    Some(user) => user.resolve(None, default_preset),
                    None => {
                        let mut claims = default_preset.default_claims();
                        if let Some(hint) = &req.login_hint {
                            default_preset.apply_login_hint(&mut claims, hint);
                        }
                        (default_preset, claims, Map::new())
                    }
                };
                complete(state, tenant, &req, preset.id, claims, access, None)
            }
        };
    }

    // Pending logins stay valid for an hour (and across restarts).
    state.store.put(Table::Pending, &req.id, &req, Some(req.created + 3600));
    let client_name = state.client(&req.client_id).and_then(|c| c.client_name);
    render_login(state, tenant, &req, client_name.as_deref(), session.map(|(_, s)| s))
}

/// Issue the authorization response for an authenticated user.
fn complete(
    state: &AppState,
    tenant: &Tenant,
    req: &AuthRequest,
    preset: &str,
    claims: Map<String, Value>,
    access_claims: Map<String, Value>,
    existing: Option<(String, i64)>,
) -> Response {
    let (sid, auth_time) = existing.unwrap_or_else(|| (uuid::Uuid::new_v4().to_string(), state.now()));
    state.store.put(
        Table::Sessions,
        &sid,
        &Session { preset: preset.into(), claims: claims.clone(), access_claims: access_claims.clone(), auth_time },
        Some(state.now() + state.config.refresh_token_ttl),
    );

    let grant = Grant {
        client_id: req.client_id.clone(),
        scope: req.scope.clone(),
        preset: preset.into(),
        claims,
        access_claims,
        nonce: req.nonce.clone(),
        auth_time,
        sid: Some(sid.clone()),
        audience: req.audience.clone(),
        acr: req.acr_values.as_ref().and_then(|a| a.split_whitespace().next().map(String::from)),
        requested_claims: req.requested_claims.clone(),
    };

    let mut out: Vec<(String, String)> = vec![];
    let code = req.has_type("code").then(|| {
        let code = random_string(43);
        let exp = state.now() + state.config.code_ttl;
        let entry = CodeEntry {
            grant: grant.clone(),
            tenant: tenant.key().into(),
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge.clone(),
            code_challenge_method: req.code_challenge_method.clone(),
            exp,
            used: false,
            issued: vec![],
        };
        state.store.put(Table::Codes, &code, &entry, Some(exp));
        code
    });
    let access = req.has_type("token").then(|| {
        let (token, expires_in) = tokens::access_token(state, tenant, &grant, None);
        out.push(("access_token".into(), token.clone()));
        out.push(("token_type".into(), "Bearer".into()));
        out.push(("expires_in".into(), expires_in.to_string()));
        if !grant.scope.is_empty() {
            out.push(("scope".into(), grant.scope.clone()));
        }
        token
    });
    if req.has_type("id_token") {
        let id = tokens::id_token(state, tenant, &grant, access.as_deref(), code.as_deref(), true, None);
        out.push(("id_token".into(), id));
    }
    if let Some(code) = code {
        out.insert(0, ("code".into(), code));
    }
    if let Some(s) = &req.state {
        out.push(("state".into(), s.clone()));
    }
    out.push(("iss".into(), tenant.issuer.clone()));

    let mut resp = deliver(&req.redirect_uri, &req.response_mode, out);
    if let Ok(v) = HeaderValue::from_str(&session_cookie(tenant, &sid, state.config.refresh_token_ttl)) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

// ---------------------------------------------------------------------------
// Login UI
// ---------------------------------------------------------------------------

pub fn editor_data(
    state: &AppState,
    tenant: &Tenant,
    mode: &str,
    previous: Option<&Session>,
    login_hint: Option<&str>,
    extra: Value,
) -> Value {
    let mut data = json!({
        "mode": mode,
        "issuer": tenant.issuer,
        "prefix": tenant.prefix,
        "presets": presets::all(),
        "defaultPreset": tenant.default_preset(&state.config).id,
        "tenantPreset": tenant.preset.map(|p| p.id),
        "previous": previous.map(|s| json!({ "preset": s.preset, "claims": s.claims, "access_claims": s.access_claims })),
        "loginHint": login_hint,
        "users": state.config.users.iter().map(|u| u.to_json(tenant.default_preset(&state.config))).collect::<Vec<_>>(),
    });
    if let (Value::Object(d), Value::Object(e)) = (&mut data, extra) {
        d.extend(e);
    }
    data
}

fn kv(label: &str, value: &str) -> String {
    format!("<dt>{}</dt><dd>{}</dd>", esc(label), value)
}

fn code(v: &str) -> String {
    format!("<code>{}</code>", esc(v))
}

fn render_login(
    state: &AppState,
    tenant: &Tenant,
    req: &AuthRequest,
    client_name: Option<&str>,
    previous: Option<Session>,
) -> Response {
    let scopes: String =
        req.scope.split_whitespace().map(|s| format!(r#"<span class="chip">{}</span>"#, esc(s))).collect();
    let mut details = vec![
        kv("client_id", &code(&req.client_id)),
        kv("redirect_uri", &code(&req.redirect_uri)),
        kv("response_type", &code(&req.response_type)),
        kv("response_mode", &code(&req.response_mode)),
        kv("scope", if scopes.is_empty() { "<em>none</em>" } else { &scopes }),
    ];
    if let Some(s) = &req.state {
        details.push(kv("state", &code(s)));
    }
    if let Some(n) = &req.nonce {
        details.push(kv("nonce", &code(n)));
    }
    details.push(kv(
        "PKCE",
        &match (&req.code_challenge, &req.code_challenge_method) {
            (Some(_), Some(m)) => format!(r#"<span class="chip ok">{}</span>"#, esc(m)),
            _ => r#"<span class="chip muted">not used</span>"#.into(),
        },
    ));
    if !req.prompt.is_empty() {
        details.push(kv("prompt", &code(&req.prompt.join(" "))));
    }
    if let Some(h) = &req.login_hint {
        details.push(kv("login_hint", &code(h)));
    }
    if !req.audience.is_empty() {
        details.push(kv("audience", &code(&req.audience.join(" "))));
    }
    details.push(kv("issuer", &code(&tenant.issuer)));

    let title = client_name.unwrap_or(&req.client_id);
    let body = format!(
        r#"<div class="layout">
<aside class="card request">
  <div class="eyebrow">Authorization request</div>
  <h1>Sign in to <span class="accent">{title}</span></h1>
  <div class="chips">{scopes}</div>
  <details class="request-details"><summary>Request details</summary><dl class="kv">{details}</dl></details>
</aside>
<form class="card editor-card" method="post" action="{action}" id="lo-form">
  <input type="hidden" name="req" value="{req_id}">
  <input type="hidden" name="preset">
  <input type="hidden" name="claims">
  <input type="hidden" name="access_claims">
  <div id="lo-editor"></div>
  <div class="actions">
    <button class="btn primary" type="submit" name="action" value="approve">Sign in</button>
    <button class="btn ghost" type="submit" name="action" value="deny">Deny access</button>
  </div>
</form>
</div>
{data}"#,
        title = esc(title),
        scopes =
            if scopes.is_empty() { r#"<span class="chip muted">no scopes</span>"#.to_string() } else { scopes.clone() },
        details = details.join(""),
        action = tenant.path("/login"),
        req_id = esc(&req.id),
        data =
            data_script(&editor_data(state, tenant, "login", previous.as_ref(), req.login_hint.as_deref(), json!({}))),
    );
    page(tenant, "Sign in", &body).into_response()
}

/// (preset, identity claims, access-token-only claims) submitted from the claims editor.
pub type Submission = (&'static presets::Preset, Map<String, Value>, Map<String, Value>);

/// Parse the claim editor's hidden fields.
pub fn editor_submission(
    form: &HashMap<String, String>,
    fallback_preset: &'static presets::Preset,
) -> Result<Submission, String> {
    let preset = form.get("preset").and_then(|p| presets::get(p)).unwrap_or(fallback_preset);
    let mut claims = match form.get("claims").filter(|c| !c.trim().is_empty()) {
        Some(raw) => parse_claims_object(raw).map_err(|e| format!("claims: {e}"))?,
        None => preset.default_claims(),
    };
    preset.ensure_sub(&mut claims);
    let access = parse_claims_object(form.get("access_claims").map(String::as_str).unwrap_or(""))
        .map_err(|e| format!("access token claims: {e}"))?;
    Ok((preset, claims, access))
}

pub async fn login(State(state): State<AppState>, tenant: Tenant, headers: HeaderMap, body: Bytes) -> Response {
    let form = parse_form(&body);
    let req_id = form.get("req").cloned().unwrap_or_default();
    let Some(req) = state.store.take::<AuthRequest>(Table::Pending, &req_id) else {
        return error_page(
            &tenant,
            StatusCode::BAD_REQUEST,
            "Login request expired",
            "This sign-in request is no longer valid. Restart the login from your application.",
        );
    };
    if form.get("action").map(String::as_str) == Some("deny") {
        return auth_error(&tenant, &req, "access_denied", "the user denied the request");
    }
    let (preset, claims, access) = match editor_submission(&form, tenant.default_preset(&state.config)) {
        Ok(v) => v,
        Err(e) => return error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid claims", &e),
    };
    // Re-use the existing session id so `sid` stays stable across logins in the same browser.
    // Submitting the claims editor during a live session isn't a re-authentication, so the
    // original auth_time is kept unless prompt=login or max_age demanded a fresh login.
    let reauth = req.prompt.iter().any(|p| p == "login");
    let existing = current_session(&state, &tenant, &headers).map(|(sid, s)| {
        let expired = req.max_age.is_some_and(|max| state.now() - s.auth_time > max);
        let auth_time = if reauth || expired { state.now() } else { s.auth_time };
        (sid, auth_time)
    });
    complete(&state, &tenant, &req, preset.id, claims, access, existing)
}

// ---------------------------------------------------------------------------
// Pushed authorization requests (RFC 9126)
// ---------------------------------------------------------------------------

pub async fn par(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let mut params = parse_form(&body);
    let client_id = match crate::routes::token::authenticate_client(&state, &headers, &params) {
        Ok(Some(id)) => id,
        Ok(None) => return OAuthError::invalid_request("client_id is required").into_response(),
        Err(e) => return e.into_response(),
    };
    params.insert("client_id".into(), client_id);
    params.remove("client_secret");
    params.remove("client_assertion");
    params.remove("client_assertion_type");
    if params.contains_key("request_uri") {
        return OAuthError::invalid_request("request_uri is not allowed in a pushed request").into_response();
    }
    let id = random_string(32);
    let expires_in = 90;
    state.store.put(Table::Par, &id, &params, Some(state.now() + expires_in));
    (
        StatusCode::CREATED,
        no_store(),
        Json(json!({ "request_uri": format!("{PAR_PREFIX}{id}"), "expires_in": expires_in })),
    )
        .into_response()
}
