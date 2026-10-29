//! Device authorization grant (RFC 8628).

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

use crate::error::{no_store, OAuthError};
use crate::html::{data_script, error_page, esc, message_page, page};
use crate::routes::authorize::{current_session, editor_data, editor_submission};
use crate::routes::token::authenticate_client;
use crate::state::{AppState, DeviceEntry, DeviceStatus, Grant};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{non_empty, now, parse_form, random_string};

const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn user_code() -> String {
    let mut rng = rand::thread_rng();
    let mut code: String = (0..8).map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())] as char).collect();
    code.insert(4, '-');
    code
}

fn normalize_user_code(code: &str) -> String {
    let raw: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect();
    if raw.len() == 8 { format!("{}-{}", &raw[..4], &raw[4..]) } else { raw }
}

pub async fn device_authorization(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = parse_form(&body);
    let client_id = match authenticate_client(&state, &headers, &params) {
        Ok(Some(id)) => id,
        Ok(None) => return OAuthError::invalid_request("client_id is required").into_response(),
        Err(e) => return e.into_response(),
    };
    let entry = DeviceEntry {
        device_code: random_string(40),
        user_code: user_code(),
        tenant: tenant.key().into(),
        client_id,
        scope: params.get("scope").cloned().unwrap_or_default(),
        audience: ["resource", "audience"].iter().filter_map(|k| non_empty(&params, k)).collect(),
        exp: now() + 600,
        interval: 5,
        last_poll: 0,
        status: DeviceStatus::Pending,
    };
    let verification_uri = tenant.url("/device");
    let body = json!({
        "device_code": entry.device_code,
        "user_code": entry.user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{verification_uri}?user_code={}", entry.user_code),
        "expires_in": 600,
        "interval": entry.interval,
    });
    // Keep the row a little past expiry so pollers get `expired_token` rather than `invalid_grant`.
    state.store.put(Table::Devices, &entry.device_code, &entry, Some(entry.exp + 300));
    (no_store(), Json(body)).into_response()
}

fn find_by_user_code(state: &AppState, tenant: &Tenant, code: &str) -> Option<DeviceEntry> {
    let code = normalize_user_code(code);
    state
        .store
        .list::<DeviceEntry>(Table::Devices)
        .into_iter()
        .find(|d| d.user_code == code && d.tenant == tenant.key() && d.exp > now() && matches!(d.status, DeviceStatus::Pending))
}

#[derive(Deserialize)]
pub struct DeviceQuery {
    user_code: Option<String>,
}

pub async fn device_page(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Response {
    let entered = q.user_code.unwrap_or_default();
    let entry = (!entered.is_empty()).then(|| find_by_user_code(&state, &tenant, &entered)).flatten();
    let Some(entry) = entry else {
        let error = if entered.is_empty() {
            String::new()
        } else {
            format!(r#"<p class="notice error">Code <code>{}</code> is invalid or has expired.</p>"#, esc(&entered))
        };
        let body = format!(
            r#"<section class="card narrow">
  <div class="eyebrow">Device sign-in</div>
  <h1>Enter the code shown on your device</h1>
  {error}
  <form method="get" action="{action}" class="device-code-form">
    <input name="user_code" placeholder="XXXX-XXXX" autocomplete="off" autofocus required>
    <button class="btn primary" type="submit">Continue</button>
  </form>
</section>"#,
            action = tenant.path("/device"),
        );
        return page(&tenant, "Device sign-in", &body).into_response();
    };

    let scopes: String = entry
        .scope
        .split_whitespace()
        .map(|s| format!(r#"<span class="chip">{}</span>"#, esc(s)))
        .collect();
    let previous = current_session(&state, &tenant, &headers).map(|(_, s)| s);
    let body = format!(
        r#"<div class="layout">
<aside class="card request">
  <div class="eyebrow">Device authorization</div>
  <h1>Approve <span class="accent">{client}</span></h1>
  <dl class="kv">
    <dt>user_code</dt><dd><code class="big">{code}</code></dd>
    <dt>client_id</dt><dd><code>{client}</code></dd>
    <dt>scope</dt><dd>{scopes}</dd>
    <dt>issuer</dt><dd><code>{issuer}</code></dd>
  </dl>
</aside>
<form class="card editor-card" method="post" action="{action}" id="lo-form">
  <input type="hidden" name="user_code" value="{code}">
  <input type="hidden" name="preset">
  <input type="hidden" name="claims">
  <input type="hidden" name="access_claims">
  <div id="lo-editor"></div>
  <div class="actions">
    <button class="btn primary" type="submit" name="action" value="approve">Approve device</button>
    <button class="btn ghost" type="submit" name="action" value="deny">Deny</button>
  </div>
</form>
</div>
{data}"#,
        client = esc(&entry.client_id),
        code = esc(&entry.user_code),
        issuer = esc(&tenant.issuer),
        action = tenant.path("/device"),
        data = data_script(&editor_data(&state, &tenant, "device", previous.as_ref(), None, json!({}))),
    );
    page(&tenant, "Approve device", &body).into_response()
}

pub async fn device_submit(State(state): State<AppState>, tenant: Tenant, body: Bytes) -> Response {
    let form = parse_form(&body);
    let code = form.get("user_code").cloned().unwrap_or_default();
    let Some(entry) = find_by_user_code(&state, &tenant, &code) else {
        return error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid code", "That device code is invalid or has expired.");
    };
    let status = if form.get("action").map(String::as_str) == Some("deny") {
        DeviceStatus::Denied
    } else {
        let (preset, claims, access_claims) = match editor_submission(&form, tenant.default_preset(&state.config)) {
            Ok(v) => v,
            Err(e) => return error_page(&tenant, StatusCode::BAD_REQUEST, "Invalid claims", &e),
        };
        DeviceStatus::Approved(Box::new(Grant {
            client_id: entry.client_id.clone(),
            scope: entry.scope.clone(),
            preset: preset.id.into(),
            claims,
            access_claims,
            nonce: None,
            auth_time: now(),
            sid: None,
            audience: entry.audience.clone(),
            acr: None,
            requested_claims: Default::default(),
        }))
    };
    let denied = matches!(status, DeviceStatus::Denied);
    state.store.update(Table::Devices, &entry.device_code, |d: &mut DeviceEntry| d.status = status);
    if denied {
        message_page(&tenant, "Device denied", "The device will not be signed in. You can close this tab.")
    } else {
        message_page(&tenant, "Device approved", "Return to your device — it will finish signing in shortly.")
    }
}
