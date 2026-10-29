//! Dynamic client registration (RFC 7591).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::error::{OAuthError, no_store};
use crate::state::{AppState, Client};
use crate::store::Table;
use crate::util::{now, random_string};

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

pub async fn register(State(state): State<AppState>, Json(meta): Json<Value>) -> Response {
    let Value::Object(mut meta) = meta else {
        return OAuthError::new(StatusCode::BAD_REQUEST, "invalid_client_metadata", "expected a JSON object")
            .into_response();
    };
    let redirect_uris = strings(meta.get("redirect_uris").unwrap_or(&Value::Null));
    if let Some(bad) = redirect_uris.iter().find(|u| url::Url::parse(u).is_err()) {
        return OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            format!("'{bad}' is not an absolute URL"),
        )
        .into_response();
    }
    if let Some(bad) = redirect_uris.iter().find(|u| u.contains('#')) {
        return OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            format!("'{bad}' must not contain a fragment"),
        )
        .into_response();
    }
    let userinfo_alg = meta.get("userinfo_signed_response_alg").and_then(Value::as_str).map(String::from);
    if userinfo_alg.as_deref().is_some_and(|a| a != "RS256" && a != "none") {
        return OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "userinfo_signed_response_alg must be RS256 (or none)",
        )
        .into_response();
    }
    let auth_method =
        meta.get("token_endpoint_auth_method").and_then(Value::as_str).unwrap_or("client_secret_basic").to_string();
    let client = Client {
        client_id: uuid::Uuid::new_v4().to_string(),
        client_secret: (auth_method != "none").then(|| random_string(48)),
        redirect_uris,
        post_logout_redirect_uris: strings(meta.get("post_logout_redirect_uris").unwrap_or(&Value::Null)),
        client_name: meta.get("client_name").and_then(Value::as_str).map(String::from),
        token_endpoint_auth_method: Some(auth_method.clone()),
        jwks: meta.get("jwks").cloned(),
        jwks_uri: meta.get("jwks_uri").and_then(Value::as_str).map(String::from),
        userinfo_signed_response_alg: userinfo_alg,
    };

    meta.insert("client_id".into(), json!(client.client_id));
    meta.insert("client_id_issued_at".into(), json!(now()));
    meta.insert("token_endpoint_auth_method".into(), json!(auth_method));
    if let Some(secret) = &client.client_secret {
        meta.insert("client_secret".into(), json!(secret));
        meta.insert("client_secret_expires_at".into(), json!(0));
    }
    meta.entry("grant_types").or_insert_with(|| json!(["authorization_code", "refresh_token"]));
    meta.entry("response_types").or_insert_with(|| json!(["code"]));

    state.store.put(Table::Clients, &client.client_id, &client, None);
    (StatusCode::CREATED, no_store(), Json(Value::Object(meta))).into_response()
}
