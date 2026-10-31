//! RP-initiated logout.

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde_json::Value;

use crate::html::{error_page, message_page};
use crate::routes::authorize::{clear_session_cookie, cookie_value};
use crate::state::AppState;
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
    let bad = |detail: &str| error_page(&tenant, StatusCode::BAD_REQUEST, "Logout request rejected", detail);

    // The hint's signature must be ours; expiry is ignored (RP-Initiated Logout 1.0 §2: the OP
    // should accept expired ID tokens as hints).
    let hint = match non_empty(&params, "id_token_hint") {
        Some(token) => match state.keys.verify(&token) {
            Some((_, Value::Object(claims)))
                if claims.get("iss").and_then(Value::as_str) == Some(tenant.issuer.as_str()) =>
            {
                Some(claims)
            }
            _ => return bad("id_token_hint could not be validated: it was not issued by this server."),
        },
        None => None,
    };
    let hint_aud = hint.as_ref().and_then(|c| c.get("aud")).map(|aud| match aud {
        Value::Array(a) => a.first().map(value_to_string).unwrap_or_default(),
        v => value_to_string(v),
    });
    if let (Some(client_id), Some(aud)) = (non_empty(&params, "client_id"), &hint_aud)
        && client_id != *aud
    {
        return bad("id_token_hint was not issued to the given client_id.");
    }
    let client_id = non_empty(&params, "client_id").or(hint_aud);

    let redirect = match non_empty(&params, "post_logout_redirect_uri") {
        Some(uri) => {
            match client_id.as_deref().map(|c| (c, state.client(c))) {
                // Registered clients: the hint and a registered URI are required (§3).
                Some((_, Some(client))) => {
                    if hint.is_none() {
                        return bad("post_logout_redirect_uri can only be used together with id_token_hint.");
                    }
                    if !client.post_logout_redirect_uris.is_empty() && !client.post_logout_redirect_uris.contains(&uri)
                    {
                        return bad(&format!("post_logout_redirect_uri '{uri}' is not registered for this client."));
                    }
                }
                // Unregistered clients are trusted in the default lenient mode, as long as we know who they are.
                Some((_, None)) if !state.config.strict_clients => {}
                _ => return bad("post_logout_redirect_uri requires an id_token_hint identifying a registered client."),
            }
            match url::Url::parse(&uri) {
                Ok(mut url) => {
                    if let Some(s) = non_empty(&params, "state") {
                        url.query_pairs_mut().append_pair("state", &s);
                    }
                    Some(url)
                }
                Err(_) => return bad(&format!("post_logout_redirect_uri '{uri}' is not a valid URL.")),
            }
        }
        None => None,
    };

    // End the browser's session, or the one named by the hint if there's no cookie, and send
    // back-channel logout tokens to the clients that used it.
    let sid = cookie_value(&headers, &tenant.cookie_name())
        .or_else(|| hint.as_ref().and_then(|c| c.get("sid")).and_then(Value::as_str).map(String::from));
    if let Some(sid) = sid {
        crate::backchannel::end_session(&state, &sid, &tenant.issuer).await;
    }
    let mut resp = match redirect {
        Some(url) => Redirect::to(url.as_str()).into_response(),
        None => message_page(&tenant, "Signed out", "Your localoidc session has ended. You can close this tab."),
    };
    if let Ok(v) = HeaderValue::from_str(&clear_session_cookie(&tenant)) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}
