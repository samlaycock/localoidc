//! OIDC Back-Channel Logout 1.0: when a session ends, POST a signed logout token to every
//! client that used it and registered a `backchannel_logout_uri`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::inspector::{Entry, mask, now_ms};
use crate::state::{AppState, Session};
use crate::store::Table;
use crate::util::value_to_string;

pub const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// How long a client gets to accept a logout token.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Logout tokens are only valid briefly (§2.4 recommends a short lifetime).
const TOKEN_TTL: i64 = 120;

#[derive(Debug, Clone, Serialize)]
pub struct Delivery {
    pub client_id: String,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The revocation-table key that marks a session as ended, for its refresh tokens.
pub fn ended_key(sid: &str) -> String {
    format!("sid:{sid}")
}

/// End a session: forget it, stop its refresh tokens working (unless they were issued for
/// `offline_access`) and send logout tokens to its clients. `None` if there was no such session.
pub async fn end_session(state: &AppState, sid: &str, fallback_issuer: &str) -> Option<Vec<Delivery>> {
    let session = state.store.take::<Session>(Table::Sessions, sid)?;
    state.store.put(
        Table::Revoked,
        &ended_key(sid),
        &json!(state.now()),
        Some(state.now() + state.config.refresh_token_ttl),
    );
    let issuer = if session.issuer.is_empty() { fallback_issuer.to_string() } else { session.issuer.clone() };
    let sub = session.claims.get("sub").map(value_to_string).unwrap_or_default();
    let tasks: Vec<_> = session
        .clients
        .iter()
        .filter_map(|client_id| {
            let uri = state.client(client_id)?.backchannel_logout_uri?;
            let (state, issuer, sub, sid, client_id) =
                (state.clone(), issuer.clone(), sub.clone(), sid.to_string(), client_id.clone());
            Some(tokio::spawn(async move { deliver(&state, &issuer, &client_id, &uri, &sub, &sid).await }))
        })
        .collect();
    let mut deliveries = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(delivery) = task.await {
            deliveries.push(delivery);
        }
    }
    Some(deliveries)
}

pub fn logout_token(state: &AppState, issuer: &str, client_id: &str, sub: &str, sid: &str) -> String {
    let iat = state.now();
    let claims = json!({
        "iss": issuer,
        "aud": client_id,
        "iat": iat,
        "exp": iat + TOKEN_TTL,
        "jti": uuid::Uuid::new_v4().to_string(),
        "sub": sub,
        "sid": sid,
        "events": { EVENT: {} },
    });
    state.keys.sign("logout+jwt", &claims)
}

async fn deliver(state: &AppState, issuer: &str, client_id: &str, uri: &str, sub: &str, sid: &str) -> Delivery {
    let token = logout_token(state, issuer, client_id, sub, sid);
    let (at, started) = (now_ms(), Instant::now());
    let result = crate::fetch::post_form(uri, &[("logout_token", &token)], TIMEOUT).await;
    let (status, error) = match result {
        Ok(status) if (200..300).contains(&status) => (Some(status), None),
        Ok(status) => (Some(status), Some(format!("{uri} answered {status}"))),
        Err(e) => (None, Some(e)),
    };
    match &error {
        Some(e) => tracing::warn!("back-channel logout to {client_id} failed: {e}"),
        None => tracing::info!("back-channel logout delivered to {client_id}"),
    }

    let issuer_key = issuer.rsplit_once("/p/").map(|(_, preset)| preset).unwrap_or("root");
    state.inspector.record(Entry {
        id: 0,
        at,
        duration_ms: started.elapsed().as_millis() as u64,
        method: "POST".into(),
        path: uri.to_string(),
        issuer: issuer_key.to_string(),
        endpoint: uri.to_string(),
        category: "flow",
        client_id: Some(client_id.to_string()),
        params: BTreeMap::from([("logout_token".to_string(), mask("logout_token", &token))]),
        authorization: None,
        status: status.unwrap_or(0),
        error: error.as_ref().map(|_| "logout_delivery_failed".to_string()),
        error_description: error.clone(),
        outcome: if error.is_none() { "back-channel logout delivered".into() } else { "logout_delivery_failed".into() },
        redirect: None,
        outgoing: true,
    });
    Delivery { client_id: client_id.to_string(), uri: uri.to_string(), status, error }
}

/// A session as listed by `/dev/api/sessions`.
pub fn describe(sid: &str, session: &Session, expires_at: Option<i64>) -> Value {
    json!({
        "sid": sid,
        "issuer": session.issuer,
        "sub": session.claims.get("sub"),
        "preset": session.preset,
        "clients": session.clients,
        "auth_time": session.auth_time,
        "expires_at": expires_at,
    })
}
