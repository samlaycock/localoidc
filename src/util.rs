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

/// Real time in Unix seconds. Anything that should follow the simulated clock (token
/// timestamps, expiry checks) uses `AppState::now()` instead.
pub fn wall_clock() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

const UNITS: [(char, i64); 5] = [('w', 604_800), ('d', 86_400), ('h', 3_600), ('m', 60), ('s', 1)];

/// Parse a duration in seconds: `90`, `90s`, `15m`, `2h`, `31d`, `1w` or combinations such as
/// `1d12h`. A leading `-` makes it negative.
pub fn parse_duration(raw: &str) -> Result<i64, String> {
    let raw = raw.trim();
    let (sign, body) = match raw.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, raw.strip_prefix('+').unwrap_or(raw)),
    };
    let invalid = || format!("invalid duration '{raw}' (use seconds, or e.g. 15m, 2h, 31d, 1d12h)");
    if !body.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(invalid());
    }
    if let Ok(secs) = body.parse::<i64>() {
        return Ok(sign * secs);
    }
    let (mut total, mut digits) = (0i64, String::new());
    for c in body.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = UNITS.iter().find(|(u, _)| *u == c).ok_or_else(invalid)?.1;
        let n: i64 = digits.parse().map_err(|_| invalid())?;
        total = n.checked_mul(unit).and_then(|v| total.checked_add(v)).ok_or_else(invalid)?;
        digits.clear();
    }
    if !digits.is_empty() || body.is_empty() {
        return Err(invalid());
    }
    Ok(sign * total)
}

/// Format seconds the way `parse_duration` reads them, e.g. `+1d2h`, `-15m`, `0s`.
pub fn format_duration(secs: i64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let mut rest = secs.unsigned_abs() as i64;
    let mut out = String::from(if secs < 0 { "-" } else { "+" });
    // Days are the largest unit shown: "+31d" reads better than "+4w3d".
    for (unit, size) in UNITS.into_iter().skip(1) {
        if rest >= size {
            out.push_str(&format!("{}{unit}", rest / size));
            rest %= size;
        }
    }
    out
}

pub fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
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
    let parsed: Value = serde_json::from_str(raw).or_else(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("-90"), Ok(-90));
        assert_eq!(parse_duration("15m"), Ok(900));
        assert_eq!(parse_duration("+1d12h"), Ok(129_600));
        assert_eq!(parse_duration("-31d"), Ok(-2_678_400));
        assert_eq!(parse_duration("1w"), Ok(604_800));
        for bad in ["", "d", "5x", "1d5", "--1", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(129_600), "+1d12h");
        assert_eq!(format_duration(-61), "-1m1s");
        assert_eq!(format_duration(31 * 86_400), "+31d");
        assert_eq!(parse_duration(&format_duration(-2_678_400)), Ok(-2_678_400));
    }
}
