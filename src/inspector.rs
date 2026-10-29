//! Request inspector: a middleware that records recent requests (masked) so `/dev/requests` and
//! `/dev/api/requests` can show what an app sent and why a request was rejected.
//!
//! Error reasons come from the three places responses are rejected (`OAuthError`, errors
//! redirected back to the client and HTML error pages), which attach an [`ErrorNote`] to the
//! response. JSON, plain-text and form-encoded response bodies are read as well.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

use crate::state::AppState;
use crate::util::{b64_std_decode, parse_form, value_to_string};

/// How many requests are kept.
pub const CAPACITY: usize = 500;
/// The same limit axum applies to request bodies by default.
const MAX_BODY: usize = 2 * 1024 * 1024;
/// Larger request bodies are passed on but not parsed for the record.
const MAX_RECORDED_BODY: usize = 64 * 1024;

/// Attached to a response that rejects a request, so the inspector can show why.
#[derive(Debug, Clone)]
pub struct ErrorNote {
    pub error: String,
    pub description: String,
}

impl ErrorNote {
    pub fn attach(response: &mut Response, error: impl Into<String>, description: impl Into<String>) {
        response.extensions_mut().insert(ErrorNote { error: error.into(), description: description.into() });
    }
}

/// Attached to a `response_mode=form_post` response: the parameters posted to the client.
#[derive(Debug, Clone)]
pub struct FormPostNote(pub Vec<String>);

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: u64,
    /// Real time, in Unix milliseconds.
    pub at: i64,
    pub duration_ms: u64,
    pub method: String,
    pub path: String,
    /// `root` or the preset of a `/p/<preset>` issuer.
    pub issuer: String,
    /// The path within the issuer, e.g. `/token`.
    pub endpoint: String,
    /// `flow`, or `metadata` (discovery, JWKS) and `dev` (localoidc's own tools), which the
    /// page hides by default.
    pub category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Query, form and JSON body parameters, masked.
    pub params: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// A one-line summary, e.g. `tokens: access_token, id_token` or the error code.
    pub outcome: String,
    /// Where a redirect or form post went (without its parameters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

impl Entry {
    pub fn failed(&self) -> bool {
        self.error.is_some() || self.status >= 400
    }
}

#[derive(Debug, Default)]
pub struct Inspector {
    inner: Mutex<Log>,
}

#[derive(Debug, Default)]
struct Log {
    next_id: u64,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Default)]
pub struct Filter {
    pub client_id: Option<String>,
    pub errors_only: bool,
    /// Only entries newer than this id.
    pub after: Option<u64>,
    pub limit: Option<usize>,
}

impl Inspector {
    pub fn record(&self, mut entry: Entry) {
        let mut log = self.inner.lock().unwrap();
        log.next_id += 1;
        entry.id = log.next_id;
        log.entries.push_back(entry);
        if log.entries.len() > CAPACITY {
            log.entries.pop_front();
        }
    }

    /// Matching entries, newest first.
    pub fn list(&self, filter: &Filter) -> Vec<Entry> {
        let log = self.inner.lock().unwrap();
        log.entries
            .iter()
            .rev()
            .filter(|e| filter.after.is_none_or(|after| e.id > after))
            .filter(|e| filter.client_id.as_ref().is_none_or(|c| e.client_id.as_ref() == Some(c)))
            .filter(|e| !filter.errors_only || e.failed())
            .take(filter.limit.unwrap_or(CAPACITY))
            .cloned()
            .collect()
    }

    /// The id of the newest entry ever recorded (0 if none); clearing doesn't reset it.
    pub fn latest_id(&self) -> u64 {
        self.inner.lock().unwrap().next_id
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }
}

/// Paths that are never recorded: static assets, health checks and the inspector itself.
fn ignored(path: &str) -> bool {
    let within = strip_issuer(path).1;
    path.starts_with("/assets/")
        || path == "/health"
        || path == "/favicon.ico"
        || within == "/dev/requests"
        || within == "/dev/api/requests"
}

/// (`root` or the preset id, path within the issuer).
fn strip_issuer(path: &str) -> (&str, &str) {
    match path.strip_prefix("/p/") {
        Some(rest) => match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        },
        None => ("root", path),
    }
}

fn category(endpoint: &str) -> &'static str {
    if endpoint.starts_with("/.well-known/")
        || endpoint == "/jwks"
        || endpoint.ends_with("/keys")
        || endpoint.ends_with("/certs")
    {
        "metadata"
    } else if endpoint == "/dev" || endpoint.starts_with("/dev/") {
        "dev"
    } else {
        "flow"
    }
}

const SECRETS: &[&str] = &["client_secret", "password", "client_assertion"];
const TOKENS: &[&str] = &[
    "code",
    "code_verifier",
    "refresh_token",
    "access_token",
    "id_token",
    "id_token_hint",
    "token",
    "subject_token",
    "actor_token",
    "device_code",
];

/// Mask a parameter for display: secrets entirely, tokens down to a prefix you can match on.
pub fn mask(key: &str, value: &str) -> String {
    if SECRETS.contains(&key) {
        return "•••".into();
    }
    if TOKENS.contains(&key) {
        return shorten(value);
    }
    if value.chars().count() > 300 {
        return format!("{}… ({} chars)", value.chars().take(300).collect::<String>(), value.chars().count());
    }
    value.to_string()
}

fn shorten(token: &str) -> String {
    if token.chars().count() <= 8 {
        "•••".into()
    } else {
        format!("{}…", token.chars().take(8).collect::<String>())
    }
}

/// (what to show for the Authorization header, the client it identifies).
fn describe_authorization(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let Some(raw) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) else {
        return (None, None);
    };
    let (scheme, value) = raw.split_once(' ').unwrap_or((raw, ""));
    match scheme.to_ascii_lowercase().as_str() {
        "basic" => {
            // The client id is form-encoded inside the credentials (RFC 6749 2.3.1).
            let client = b64_std_decode(value)
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|s| s.split_once(':').map(|(u, _)| u.to_string()))
                .and_then(|u| {
                    url::form_urlencoded::parse(format!("x={u}").as_bytes()).next().map(|(_, v)| v.into_owned())
                });
            let shown = match &client {
                Some(c) => format!("Basic {c}:•••"),
                None => "Basic •••".into(),
            };
            (Some(shown), client)
        }
        "bearer" | "dpop" => {
            // JWT access tokens name their client; opaque ones don't.
            let client = crate::keys::decode_unverified(value).and_then(|c| {
                c.get("client_id").or_else(|| c.get("azp")).or_else(|| c.get("cid")).map(value_to_string)
            });
            (Some(format!("{scheme} {}", shorten(value))), client)
        }
        _ => (Some(format!("{scheme} •••")), None),
    }
}

fn content_type(headers: &HeaderMap) -> String {
    headers.get(header::CONTENT_TYPE).and_then(|h| h.to_str().ok()).unwrap_or_default().to_ascii_lowercase()
}

/// Request parameters from the query and a form or JSON body.
fn request_params(query: &str, content_type: &str, body: &[u8]) -> BTreeMap<String, String> {
    let mut params: BTreeMap<String, String> = parse_form(query.as_bytes()).into_iter().collect();
    if body.len() > MAX_RECORDED_BODY {
        params.insert("(body)".into(), format!("{} bytes, not recorded", body.len()));
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        params.extend(parse_form(body));
    } else if content_type.contains("json")
        && let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body)
    {
        params.extend(map.iter().map(|(k, v)| (k.clone(), value_to_string(v))));
    }
    params
}

/// Parameters carried by a redirect: the query and fragment of its Location.
fn redirect_params(location: &str) -> Option<(String, BTreeMap<String, String>)> {
    let url = url::Url::parse(location).ok()?;
    let mut params: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    if let Some(fragment) = url.fragment() {
        params.extend(parse_form(fragment.as_bytes()));
    }
    let target = format!("{}{}", url.origin().ascii_serialization(), url.path());
    Some((target, params))
}

/// Parameter names a client receives, without the bookkeeping ones.
fn delivered<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    keys.map(String::as_str).filter(|k| !matches!(*k, "iss" | "state" | "session_state")).collect()
}

/// Error code and description (if any) and a summary of the response body.
fn body_outcome(content_type: &str, body: &[u8]) -> (Option<(String, String)>, Option<String>) {
    let fields: BTreeMap<String, String> = if content_type.contains("json") {
        match serde_json::from_slice::<Value>(body) {
            Ok(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), value_to_string(v))).collect(),
            _ => return (None, None),
        }
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        parse_form(body).into_iter().collect()
    } else if content_type.starts_with("text/html") {
        // Pages are summarised by their title, e.g. "page: Sign in".
        let html = String::from_utf8_lossy(body);
        let title = html.split_once("<title>").and_then(|(_, rest)| rest.split_once("</title>")).map(|(t, _)| t);
        return (None, title.map(|t| format!("page: {}", t.trim_end_matches(" · localoidc"))));
    } else if content_type.starts_with("text/plain") {
        let text = String::from_utf8_lossy(body).chars().take(300).collect::<String>();
        return (None, Some(text));
    } else {
        return (None, None);
    };
    if let Some(error) = fields.get("error") {
        let description = fields.get("error_description").cloned().unwrap_or_default();
        return (Some((error.clone(), description)), None);
    }
    let tokens: Vec<&str> = ["access_token", "id_token", "refresh_token", "device_code"]
        .into_iter()
        .filter(|k| fields.contains_key(*k))
        .collect();
    (None, (!tokens.is_empty()).then(|| format!("tokens: {}", tokens.join(", "))))
}

/// Record every request (except [`ignored`] paths) into the inspector.
pub async fn record(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if ignored(&path) {
        return next.run(request).await;
    }
    let started = Instant::now();
    let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or_default();
    let method = request.method().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    let request_type = content_type(request.headers());
    let (authorization, auth_client) = describe_authorization(request.headers());

    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let raw_params = request_params(&query, &request_type, &body);
    let response = next.run(Request::from_parts(parts, Body::from(body))).await;

    let (parts, body) = response.into_parts();
    let response_type = content_type(&parts.headers);
    let readable = ["json", "text/plain", "text/html", "application/x-www-form-urlencoded"]
        .iter()
        .any(|t| response_type.contains(t));
    let (body, response_body): (Body, Option<Bytes>) = if readable {
        match to_bytes(body, MAX_BODY).await {
            Ok(bytes) => (Body::from(bytes.clone()), Some(bytes)),
            Err(_) => (Body::empty(), None),
        }
    } else {
        (body, None)
    };

    let status = parts.status;
    let mut error = parts.extensions.get::<ErrorNote>().map(|n| (n.error.clone(), n.description.clone()));
    let mut redirect = None;
    let mut summary = None;
    if let Some(location) = parts.headers.get(header::LOCATION).and_then(|h| h.to_str().ok()) {
        if let Some((target, params)) = redirect_params(location) {
            if error.is_none()
                && let Some(e) = params.get("error")
            {
                error = Some((e.clone(), params.get("error_description").cloned().unwrap_or_default()));
            }
            let keys = delivered(params.keys());
            summary =
                Some(if keys.is_empty() { "redirect".into() } else { format!("redirect with {}", keys.join(", ")) });
            redirect = Some(target);
        } else {
            summary = Some(format!("redirect to {location}"));
        }
    }
    if let Some(FormPostNote(keys)) = parts.extensions.get::<FormPostNote>() {
        summary = Some(format!("form_post with {}", delivered(keys.iter()).join(", ")));
    }
    if let Some(bytes) = &response_body {
        let (body_error, body_summary) = body_outcome(&response_type, bytes);
        error = error.or(body_error);
        summary = summary.or(body_summary);
    }

    let (issuer, endpoint) = strip_issuer(&path);
    let client_id = raw_params.get("client_id").cloned().filter(|c| !c.is_empty()).or(auth_client);
    let outcome = match (&error, summary) {
        (Some((code, _)), _) => code.clone(),
        (None, Some(s)) => s,
        (None, None) => status.canonical_reason().unwrap_or("").to_string(),
    };
    state.inspector.record(Entry {
        id: 0,
        at,
        duration_ms: started.elapsed().as_millis() as u64,
        method,
        path: path.clone(),
        issuer: issuer.to_string(),
        endpoint: endpoint.to_string(),
        category: category(endpoint),
        client_id,
        params: raw_params.iter().map(|(k, v)| (k.clone(), mask(k, v))).collect(),
        authorization,
        status: status.as_u16(),
        error_description: error.as_ref().map(|(_, d)| d.clone()).filter(|d| !d.is_empty()),
        error: error.map(|(code, _)| code),
        outcome,
        redirect,
    });
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(client: &str, status: u16) -> Entry {
        Entry {
            id: 0,
            at: 0,
            duration_ms: 0,
            method: "POST".into(),
            path: "/token".into(),
            issuer: "root".into(),
            endpoint: "/token".into(),
            category: "flow",
            client_id: Some(client.into()),
            params: BTreeMap::new(),
            authorization: None,
            status,
            error: None,
            error_description: None,
            outcome: String::new(),
            redirect: None,
        }
    }

    #[test]
    fn keeps_the_newest_entries_and_filters() {
        let inspector = Inspector::default();
        for i in 0..CAPACITY + 10 {
            inspector.record(entry(if i % 2 == 0 { "a" } else { "b" }, if i % 3 == 0 { 400 } else { 200 }));
        }
        let all = inspector.list(&Filter::default());
        assert_eq!(all.len(), CAPACITY);
        assert_eq!((all[0].id, all[CAPACITY - 1].id), (CAPACITY as u64 + 10, 11));
        let newer = inspector.list(&Filter { after: Some(CAPACITY as u64 + 7), ..Default::default() });
        assert_eq!(newer.iter().map(|e| e.id).collect::<Vec<_>>(), [510, 509, 508]);
        assert!(
            inspector
                .list(&Filter { client_id: Some("a".into()), ..Default::default() })
                .iter()
                .all(|e| e.client_id.as_deref() == Some("a"))
        );
        assert!(inspector.list(&Filter { errors_only: true, ..Default::default() }).iter().all(|e| e.status == 400));
        assert_eq!(inspector.list(&Filter { limit: Some(5), ..Default::default() }).len(), 5);
        inspector.clear();
        assert!(inspector.list(&Filter::default()).is_empty());
    }

    #[test]
    fn masks_secrets_and_shortens_tokens() {
        assert_eq!(mask("client_secret", "hunter2"), "•••");
        assert_eq!(mask("code", "AcsWFvywdFzRMZaMZKgitnfVaiYNGXW4W1KhSWVwSiE"), "AcsWFvyw…");
        assert_eq!(mask("code", "short"), "•••");
        assert_eq!(mask("scope", "openid email"), "openid email");
        assert!(mask("request", &"x".repeat(400)).ends_with("(400 chars)"));
    }

    #[test]
    fn splits_issuer_paths() {
        assert_eq!(strip_issuer("/token"), ("root", "/token"));
        assert_eq!(strip_issuer("/p/google/o/oauth2/v2/auth"), ("google", "/o/oauth2/v2/auth"));
        assert_eq!(strip_issuer("/p/google"), ("google", "/"));
        assert_eq!(category("/.well-known/openid-configuration"), "metadata");
        assert_eq!(category("/v1/keys"), "metadata");
        assert_eq!(category("/dev/api/token"), "dev");
        assert_eq!(category("/token"), "flow");
        assert!(ignored("/p/okta/dev/api/requests") && ignored("/assets/app.js") && !ignored("/dev/api/token"));
    }
}
