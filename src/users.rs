//! Users declared in `localoidc.toml`: named identities shared by the login UI, the dev API,
//! the CLI and automated logins.

use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::presets::{self, Preset};
use crate::util::merge_claims;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Handle used by `dev_user`, `--user` and the dev API's `user`.
    pub id: String,
    /// Shown in the login UI's picker (defaults to the user's email/name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Preset whose claim shape is used; otherwise the issuer's default preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Identity claims, merged over the preset defaults.
    #[serde(default)]
    pub claims: Map<String, Value>,
    /// Claims placed only in the access token.
    #[serde(default)]
    pub access_claims: Map<String, Value>,
    /// Merge `claims` over the preset defaults (default true).
    #[serde(default = "yes")]
    pub defaults: bool,
    /// When set, the `password` grant requires it for this user.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
}

fn yes() -> bool {
    true
}

impl User {
    /// The preset (an explicit one, then the user's own, then `fallback`), identity claims and
    /// access-token-only claims to sign this user in with.
    pub fn resolve(
        &self,
        explicit: Option<&'static Preset>,
        fallback: &'static Preset,
    ) -> (&'static Preset, Map<String, Value>, Map<String, Value>) {
        let preset = explicit.or_else(|| self.preset.as_deref().and_then(presets::get)).unwrap_or(fallback);
        let mut claims = if self.defaults { preset.default_claims() } else { Map::new() };
        // The preset's example subject is shared by everyone, so give each user their own stable
        // one, shaped like the provider's. Presets that derive `sub` from another claim (GitHub's
        // `id`, ...) get that claim instead and re-derive `sub` from it.
        let key = preset.sub_from.unwrap_or("sub");
        if !self.claims.contains_key(key) {
            let template = preset.fields.iter().find(|f| f.name == key).map(|f| f.default.clone());
            claims.insert(key.into(), stable_like(&template.unwrap_or_else(|| json!("user-1234")), &self.id));
        }
        if preset.sub_from.is_some() && !self.claims.contains_key("sub") {
            claims.remove("sub");
        }
        merge_claims(&mut claims, &self.claims);
        preset.ensure_sub(&mut claims);
        (preset, claims, self.access_claims.clone())
    }

    /// Does a `login_hint` or `username` refer to this user (its id or email)?
    pub fn matches(&self, login: &str) -> bool {
        self.id == login
            || self.claims.get("email").and_then(Value::as_str).is_some_and(|e| e.eq_ignore_ascii_case(login))
    }

    /// The user as shown to the login UI and `/dev/api/users`.
    pub fn to_json(&self, fallback: &'static Preset) -> Value {
        let (preset, claims, access) = self.resolve(None, fallback);
        json!({
            "id": self.id,
            "label": self.label,
            "preset": preset.id,
            "claims": claims,
            "access": access,
        })
    }
}

pub fn validate(users: &[User]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for user in users {
        if user.id.trim().is_empty() {
            anyhow::bail!("every [[users]] entry needs an id");
        }
        if !seen.insert(user.id.as_str()) {
            anyhow::bail!("duplicate user id '{}'", user.id);
        }
        if let Some(p) = &user.preset
            && presets::get(p).is_none()
        {
            anyhow::bail!("user '{}': unknown preset '{p}'", user.id);
        }
    }
    Ok(())
}

/// A value shaped like `template` but derived from `seed`, so it is stable across restarts and
/// distinct per seed. Numbers keep their digit count. Strings are split on `-._|:`; digit runs
/// stay digits, hex runs stay hex, long opaque runs keep each character's class, and short words
/// (`user`, `auth0`) are kept as they are.
fn stable_like(template: &Value, seed: &str) -> Value {
    let mut stream = (0u32..).flat_map(|i| Sha256::digest(format!("{seed}:{i}")));
    let mut next = move |n: u8| stream.next().unwrap_or_default() % n;
    match template {
        Value::Number(n) => {
            let len = n.to_string().len().clamp(1, 18);
            let digits: String =
                (0..len).map(|i| (b'0' + if i == 0 { 1 + next(9) } else { next(10) }) as char).collect();
            json!(digits.parse::<i64>().unwrap_or_default())
        }
        Value::String(s) => {
            let mut out = String::with_capacity(s.len());
            for segment in s.split_inclusive(['-', '.', '_', '|', ':']) {
                let (word, sep) = match segment.char_indices().last() {
                    Some((i, c)) if "-._|:".contains(c) => segment.split_at(i),
                    _ => (segment, ""),
                };
                let reshape = word.chars().all(|c| c.is_ascii_hexdigit()) || word.len() >= 16;
                for c in word.chars() {
                    out.push(match c {
                        _ if !reshape => c,
                        '0'..='9' => (b'0' + next(10)) as char,
                        _ if word.chars().all(|c| c.is_ascii_hexdigit()) => {
                            let h = b"0123456789abcdef"[next(16) as usize] as char;
                            if c.is_ascii_uppercase() { h.to_ascii_uppercase() } else { h }
                        }
                        'a'..='z' => (b'a' + next(26)) as char,
                        'A'..='Z' => (b'A' + next(26)) as char,
                        _ => c,
                    });
                }
                out.push_str(sep);
            }
            json!(out)
        }
        _ => json!(format!("user-{seed}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_like_keeps_the_shape() {
        let google = stable_like(&json!("109876543210987654321"), "alice");
        assert_eq!(google, stable_like(&json!("109876543210987654321"), "alice"));
        assert_ne!(google, stable_like(&json!("109876543210987654321"), "bob"));
        assert!(google.as_str().unwrap().chars().all(|c| c.is_ascii_digit()) && google.as_str().unwrap().len() == 21);

        let generic = stable_like(&json!("user-1234"), "alice");
        assert!(generic.as_str().unwrap().starts_with("user-"));
        assert_ne!(generic, json!("user-1234"));

        let auth0 = stable_like(&json!("auth0|64f1c0ffee0000000000abcd"), "alice");
        assert!(auth0.as_str().unwrap().starts_with("auth0|"));
        assert_eq!(auth0.as_str().unwrap().len(), 30);

        let uuid = stable_like(&json!("f3b4c2a1-1234-4cde-9abc-0123456789ab"), "alice").as_str().unwrap().to_string();
        assert_eq!(uuid.len(), 36);
        assert!(uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));

        let id = stable_like(&json!(1234567), "alice");
        assert_eq!(id.as_i64().unwrap().to_string().len(), 7);
    }
}
