//! Device authorization grant (RFC 8628).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

use crate::error::{OAuthError, no_store};
use crate::html::{BUTTON, INPUT, PRIMARY_BUTTON, error_page, esc, message_page, shell, titled_card};
use crate::routes::authorize::{current_session, editor_data, editor_submission};
use crate::routes::token::authenticate_client;
use crate::state::{AppState, DeviceEntry, DeviceStatus, Grant};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{non_empty, parse_form, random_string};

const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

fn user_code() -> String {
    let mut rng = rand::thread_rng();
    let mut code: String =
        (0..8).map(|_| USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())] as char).collect();
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
        exp: state.now() + 600,
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
    state.store.list::<DeviceEntry>(Table::Devices).into_iter().find(|d| {
        d.user_code == code
            && d.tenant == tenant.key()
            && d.exp > state.now()
            && matches!(d.status, DeviceStatus::Pending)
    })
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
    let action = tenant.path("/device");
    let Some(entry) = entry else {
        let invalid = (!entered.is_empty()).then_some(entered.as_str());
        let view = json!({ "kind": "device-code", "action": action, "invalid_code": invalid });
        let error = invalid.map(|code| {
            format!(
                r#"<p style="color:var(--destructive);font-size:.875rem">Code {} is invalid or has expired.</p>"#,
                esc(code)
            )
        });
        let form = format!(
            r#"{error}<form method="get" action="{action}" style="display:flex;gap:.5rem;margin-top:1rem">
<input name="user_code" placeholder="XXXX-XXXX" autocomplete="off" autofocus required aria-label="Code" {INPUT}>
<button type="submit" {PRIMARY_BUTTON}>Continue</button>
</form>"#,
            error = error.unwrap_or_default(),
            action = esc(&action),
        );
        let fallback = titled_card("Device sign-in", "Enter the code shown on your device", "", &form);
        return shell(&tenant, StatusCode::OK, "Device sign-in", view, &fallback);
    };

    let previous = current_session(&state, &tenant, &headers).map(|(_, s)| s);
    let view = json!({
        "kind": "device",
        "action": action,
        "user_code": entry.user_code,
        "client_id": entry.client_id,
        "scope": entry.scope,
        "editor": editor_data(&state, &tenant, "device", previous.as_ref(), None, json!({})),
    });
    // Without JavaScript, approving uses the preset's default claims.
    let form = format!(
        r#"<form method="post" action="{action}" style="display:flex;gap:.5rem;margin-top:1rem">
<input type="hidden" name="user_code" value="{code}">
<button type="submit" name="action" value="approve" {PRIMARY_BUTTON}>Approve device</button>
<button type="submit" name="action" value="deny" {BUTTON}>Deny</button>
</form>"#,
        action = esc(&action),
        code = esc(&entry.user_code),
    );
    let fallback = titled_card(
        "Device authorization",
        &format!("Approve {}", entry.client_id),
        &format!(
            "Code {} · scope: {}. Approving uses the default claims; the claims editor needs JavaScript.",
            entry.user_code, entry.scope
        ),
        &form,
    );
    shell(&tenant, StatusCode::OK, "Approve device", view, &fallback)
}

pub async fn device_submit(State(state): State<AppState>, tenant: Tenant, body: Bytes) -> Response {
    let form = parse_form(&body);
    let code = form.get("user_code").cloned().unwrap_or_default();
    let Some(entry) = find_by_user_code(&state, &tenant, &code) else {
        return error_page(
            &tenant,
            StatusCode::BAD_REQUEST,
            "Invalid code",
            "That device code is invalid or has expired.",
        );
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
            auth_time: state.now(),
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
