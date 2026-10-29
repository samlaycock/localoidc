//! RP-initiated logout.

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::Value;

use crate::html::{error_page, message_page};
use crate::keys::decode_unverified;
use crate::routes::authorize::{clear_session_cookie, cookie_value};
use crate::state::AppState;
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{merged_params, non_empty, value_to_string};

pub async fn end_session(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = merged_params(query.as_deref(), &body);
    let hint_aud = non_empty(&params, "id_token_hint")
        .and_then(|t| decode_unverified(&t))
        .and_then(|c| c.get("aud").cloned())
        .map(|aud| match aud {
            Value::Array(a) => a.first().map(value_to_string).unwrap_or_default(),
            v => value_to_string(&v),
        });
    let client_id = non_empty(&params, "client_id").or(hint_aud);

    if let Some(sid) = cookie_value(&headers, &tenant.cookie_name()) {
        state.store.remove(Table::Sessions, &sid);
    }

    let mut resp = match non_empty(&params, "post_logout_redirect_uri") {
        Some(uri) => {
            let client = client_id.and_then(|c| state.client(&c));
            if client.is_some_and(|c| !c.post_logout_redirect_uris.is_empty() && !c.post_logout_redirect_uris.contains(&uri)) {
                return error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid post_logout_redirect_uri", &uri);
            }
            match url::Url::parse(&uri) {
                Ok(mut url) => {
                    if let Some(s) = non_empty(&params, "state") {
                        url.query_pairs_mut().append_pair("state", &s);
                    }
                    Redirect::to(url.as_str()).into_response()
                }
                Err(_) => return error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid post_logout_redirect_uri", &uri),
            }
        }
        None => message_page(&tenant, "Signed out", "Your localoidc session has ended. You can close this tab."),
    };
    if let Ok(v) = HeaderValue::from_str(&clear_session_cookie(&tenant)) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}
