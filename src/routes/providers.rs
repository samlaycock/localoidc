//! Provider-specific endpoint aliases and API shapes, mounted under `/p/<preset>`.

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::{Map, Value, json};

use crate::error::{OAuthError, no_store};
use crate::routes::{authorize, discovery, logout, token, userinfo};
use crate::state::{AppState, Grant};
use crate::tenant::Tenant;
use crate::tokens;
use crate::util::{merged_params, non_empty};

pub fn routes() -> Router<AppState> {
    Router::new()
        // Google
        .route("/o/oauth2/v2/auth", any(authorize::authorize))
        .route("/oauth2/v3/userinfo", any(userinfo::userinfo))
        .route("/tokeninfo", any(tokeninfo))
        // GitHub
        .route("/login/oauth/authorize", any(authorize::authorize))
        .route("/login/oauth/access_token", any(github_token))
        .route("/user", get(provider_user))
        .route("/user/emails", get(github_emails))
        // Microsoft
        .route("/oauth2/v2.0/authorize", any(authorize::authorize))
        .route("/oauth2/v2.0/token", any(token::token))
        .route("/oauth2/v2.0/logout", any(logout::end_session))
        // Facebook (versioned and unversioned Graph paths); `/v1.0/me` doubles as Microsoft Graph.
        .route("/dialog/oauth", any(authorize::authorize))
        .route("/{version}/dialog/oauth", any(authorize::authorize))
        .route("/oauth/access_token", any(token::token))
        .route("/{version}/oauth/access_token", any(token::token))
        .route("/me", get(provider_user))
        .route("/{version}/me", get(provider_user))
        // Apple
        .route("/auth/authorize", any(authorize::authorize))
        .route("/auth/token", any(token::token))
        .route("/auth/keys", get(discovery::jwks))
        // Auth0 / GitLab
        .route("/oauth/authorize", any(authorize::authorize))
        .route("/oauth/token", any(token::token))
        .route("/oauth/userinfo", any(userinfo::userinfo))
        .route("/api/v4/user", get(provider_user))
        // Okta
        .route("/v1/authorize", any(authorize::authorize))
        .route("/v1/token", any(token::token))
        .route("/v1/userinfo", any(userinfo::userinfo))
        .route("/v1/keys", get(discovery::jwks))
        .route("/v1/introspect", any(userinfo::introspect))
        .route("/v1/revoke", any(userinfo::revoke))
        .route("/v1/logout", any(logout::end_session))
        // Keycloak
        .route("/protocol/openid-connect/auth", any(authorize::authorize))
        .route("/protocol/openid-connect/token", any(token::token))
        .route("/protocol/openid-connect/userinfo", any(userinfo::userinfo))
        .route("/protocol/openid-connect/certs", get(discovery::jwks))
        .route("/protocol/openid-connect/logout", any(logout::end_session))
        .route("/protocol/openid-connect/token/introspect", any(userinfo::introspect))
        .route("/protocol/openid-connect/revoke", any(userinfo::revoke))
        // Discord / Cognito
        .route("/oauth2/authorize", any(authorize::authorize))
        .route("/oauth2/token", any(token::token))
        .route("/api/oauth2/token", any(token::token))
        .route("/oauth2/userInfo", any(userinfo::userinfo))
        .route("/api/users/@me", get(provider_user))
        .route("/logout", any(logout::end_session))
}

fn claim<'a>(grant: &'a Grant, key: &str) -> &'a Value {
    grant.claims.get(key).unwrap_or(&Value::Null)
}

/// The "current user" REST resource in the shape the emulated provider returns it.
pub async fn provider_user(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = merged_params(query.as_deref(), b"");
    let grant = match userinfo::authorize_bearer(&state, &headers, &params) {
        Ok(g) => g,
        Err(e) => return e.into_response(),
    };
    let preset = tenant.preset.map(|p| p.id).unwrap_or(grant.preset.as_str());
    let body = match preset {
        "github" | "discord" => {
            let mut m: Map<String, Value> = grant.claims.clone();
            m.remove("sub");
            Value::Object(m)
        }
        "facebook" => {
            let fields = non_empty(&params, "fields").unwrap_or_else(|| "id,name".into());
            let mut m = Map::new();
            for f in fields.split(',').map(str::trim).filter(|f| !f.is_empty()) {
                // Ignore Graph field modifiers like picture.type(large).
                let key = f.split(['.', '{']).next().unwrap_or(f);
                if let Some(v) = grant.claims.get(key) {
                    m.insert(key.into(), v.clone());
                }
            }
            Value::Object(m)
        }
        "microsoft" => json!({
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
            "id": grant.claims.get("oid").cloned().unwrap_or_else(|| json!(grant.sub())),
            "displayName": claim(&grant, "name"),
            "givenName": claim(&grant, "given_name"),
            "surname": claim(&grant, "family_name"),
            "mail": claim(&grant, "email"),
            "userPrincipalName": grant.claims.get("preferred_username").or(grant.claims.get("email")),
            "jobTitle": null,
            "businessPhones": [],
        }),
        "gitlab" => json!({
            "id": grant.sub().parse::<i64>().map(Value::from).unwrap_or_else(|_| json!(grant.sub())),
            "username": grant.claims.get("preferred_username").or(grant.claims.get("nickname")),
            "name": claim(&grant, "name"),
            "email": claim(&grant, "email"),
            "avatar_url": claim(&grant, "picture"),
            "web_url": claim(&grant, "profile"),
            "state": "active",
        }),
        _ => Value::Object(tokens::userinfo_claims(&state, &grant)),
    };
    (no_store(), Json(body)).into_response()
}

pub async fn github_emails(State(state): State<AppState>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    let params = merged_params(query.as_deref(), b"");
    match userinfo::authorize_bearer(&state, &headers, &params) {
        Ok(grant) => {
            let emails: Vec<Value> = grant
                .claims
                .get("email")
                .and_then(Value::as_str)
                .map(|e| vec![json!({ "email": e, "primary": true, "verified": true, "visibility": "public" })])
                .unwrap_or_default();
            Json(emails).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// GitHub's token endpoint: form-encoded responses unless JSON is requested, and errors with HTTP 200.
pub async fn github_token(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = merged_params(query.as_deref(), &body);
    let wants_json = headers.get(header::ACCEPT).and_then(|h| h.to_str().ok()).is_some_and(|a| a.contains("json"));
    let value = match token::handle_token(&state, &tenant, &headers, &params) {
        Ok(mut v) => {
            v["token_type"] = json!("bearer");
            v
        }
        Err(e) => e.body(),
    };
    if wants_json {
        return (no_store(), Json(value)).into_response();
    }
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    if let Value::Object(m) = &value {
        for (k, v) in m {
            ser.append_pair(k, &crate::util::value_to_string(v));
        }
    }
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/x-www-form-urlencoded; charset=utf-8")], ser.finish())
        .into_response()
}

/// Google's tokeninfo: validates an `id_token` or `access_token` and returns its claims.
pub async fn tokeninfo(State(state): State<AppState>, RawQuery(query): RawQuery, body: Bytes) -> Response {
    let params = merged_params(query.as_deref(), &body);
    let Some(token) = non_empty(&params, "id_token").or_else(|| non_empty(&params, "access_token")) else {
        return OAuthError::invalid_request("id_token or access_token is required").into_response();
    };
    match tokens::verify(&state, &token) {
        Some(v) => {
            let mut out = v.claims.clone();
            out.remove("grant");
            out.insert("expires_in".into(), json!(v.exp - state.now()));
            out.entry("sub").or_insert_with(|| json!(v.grant.sub()));
            // Google returns all values as strings.
            let stringly: Map<String, Value> =
                out.into_iter().map(|(k, v)| (k, json!(crate::util::value_to_string(&v)))).collect();
            Json(Value::Object(stringly)).into_response()
        }
        None => OAuthError::new(StatusCode::BAD_REQUEST, "invalid_token", "Invalid Value").into_response(),
    }
}
