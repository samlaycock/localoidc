use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::Rng;
use rand::distributions::Alphanumeric;
use rsa::sha2::{Digest, Sha256};
use serde_json::Value;

pub fn b64(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

pub fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s.trim()).ok()
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

pub fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn sha256_b64(input: &str) -> String {
    b64(Sha256::digest(input.as_bytes()))
}

/// Left-most half of the SHA-256 hash, base64url encoded (`at_hash`, `c_hash`).
pub fn half_hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    b64(&digest[..16])
}

pub fn parse_form(bytes: &[u8]) -> HashMap<String, String> {
    url::form_urlencoded::parse(bytes).into_owned().collect()
}

/// Merge query string and (form-encoded) body parameters; body wins.
pub fn merged_params(query: Option<&str>, body: &[u8]) -> HashMap<String, String> {
    let mut params = parse_form(query.unwrap_or_default().as_bytes());
    params.extend(parse_form(body));
    params
}

pub fn has_scope(scope: &str, wanted: &str) -> bool {
    scope.split_whitespace().any(|s| s == wanted)
}

pub fn non_empty(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params.get(key).filter(|v| !v.is_empty()).cloned()
}

/// Render a JSON value as a plain string (strings unquoted).
pub fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Parse a user supplied claims document. Accepts raw JSON or base64url-encoded JSON.
pub fn parse_claims_object(raw: &str) -> Result<serde_json::Map<String, Value>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Default::default());
    }
    let parsed: Value = serde_json::from_str(raw)
        .or_else(|e| {
            b64_decode(raw)
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or_else(|| format!("invalid JSON: {e}"))
        })?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err("claims must be a JSON object".into()),
    }
}

/// Merge `overrides` into `base`; a `null` override removes the claim.
pub fn merge_claims(base: &mut serde_json::Map<String, Value>, overrides: &serde_json::Map<String, Value>) {
    for (k, v) in overrides {
        if v.is_null() {
            base.remove(k);
        } else {
            base.insert(k.clone(), v.clone());
        }
    }
}
