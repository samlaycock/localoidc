//! Token issuance and verification.

use serde_json::{Map, Value, json};

use crate::config::RefreshPolicy;
use crate::presets;
use crate::state::{AppState, Grant, OpaqueToken};
use crate::store::Table;
use crate::tenant::Tenant;
use crate::util::{half_hash, has_scope, random_string};

/// Claims managed by the server (stripped when reconstructing an identity from a token).
pub const REGISTERED: &[&str] = &[
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "auth_time",
    "nonce",
    "sid",
    "at_hash",
    "c_hash",
    "s_hash",
    "client_id",
    "scope",
    "acr",
    "grant",
];

#[derive(Default)]
pub struct IssueOpts {
    pub id_token: bool,
    pub refresh_token: bool,
    pub include_nonce: bool,
    /// Lifetime override for access and ID tokens.
    pub ttl: Option<i64>,
}

pub struct Issued {
    pub access_token: String,
    pub expires_in: i64,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: String,
}

impl Issued {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
        });
        if !self.scope.is_empty() {
            v["scope"] = json!(self.scope);
        }
        if let Some(t) = &self.id_token {
            v["id_token"] = json!(t);
        }
        if let Some(t) = &self.refresh_token {
            v["refresh_token"] = json!(t);
        }
        v
    }
}

pub fn wants_refresh(state: &AppState, scope: &str) -> bool {
    match state.config.refresh_tokens {
        RefreshPolicy::Always => true,
        RefreshPolicy::OfflineAccess => has_scope(scope, "offline_access"),
        RefreshPolicy::Never => false,
    }
}

pub fn issue(state: &AppState, tenant: &Tenant, grant: &Grant, opts: &IssueOpts) -> Issued {
    let (access_token, expires_in) = access_token(state, tenant, grant, opts.ttl);
    let id_token =
        opts.id_token.then(|| id_token(state, tenant, grant, Some(&access_token), None, opts.include_nonce, opts.ttl));
    let refresh_token = opts.refresh_token.then(|| refresh_token(state, tenant, grant));
    Issued { access_token, expires_in, id_token, refresh_token, scope: grant.scope.clone() }
}

fn audience_value(grant: &Grant) -> Value {
    match grant.audience.as_slice() {
        [] => json!(grant.client_id),
        [one] => json!(one),
        many => json!(many),
    }
}

fn insert_all(target: &mut Map<String, Value>, source: &Value) {
    if let Value::Object(map) = source {
        for (k, v) in map {
            target.insert(k.clone(), v.clone());
        }
    }
}

/// Provider-specific access token claims that depend on the grant.
fn preset_access_claims(preset: &str, grant: &Grant) -> Map<String, Value> {
    let mut m = Map::new();
    let scopes: Vec<&str> = grant.scope.split_whitespace().collect();
    match preset {
        "microsoft" => {
            m.insert("azp".into(), json!(grant.client_id));
            m.insert("scp".into(), json!(scopes.join(" ")));
        }
        "okta" => {
            m.insert("cid".into(), json!(grant.client_id));
            m.insert("uid".into(), json!(grant.sub()));
            m.insert("scp".into(), json!(scopes));
        }
        "keycloak" | "auth0" | "google" => {
            m.insert("azp".into(), json!(grant.client_id));
        }
        "cognito" => {
            if let Some(u) = grant.claims.get("cognito:username") {
                m.insert("username".into(), u.clone());
            }
        }
        _ => {}
    }
    m
}

pub fn access_token(state: &AppState, tenant: &Tenant, grant: &Grant, ttl: Option<i64>) -> (String, i64) {
    let ttl = ttl.unwrap_or(state.config.access_token_ttl);
    let iat = state.now();
    let exp = iat + ttl;
    let preset = presets::get_or_generic(&grant.preset);

    if let Some(prefix) = preset.access_token_prefix {
        let token = format!("{prefix}{}", random_string(36));
        state.store.put(Table::Opaque, &token, &OpaqueToken { grant: grant.clone(), iat, exp }, Some(exp));
        return (token, ttl);
    }

    let jti = uuid::Uuid::new_v4().to_string();
    let mut c = Map::new();
    c.insert("iss".into(), json!(tenant.issuer));
    c.insert("sub".into(), json!(grant.sub()));
    c.insert("aud".into(), audience_value(grant));
    c.insert("client_id".into(), json!(grant.client_id));
    if !grant.scope.is_empty() {
        c.insert("scope".into(), json!(grant.scope));
    }
    c.insert("iat".into(), json!(iat));
    c.insert("nbf".into(), json!(iat));
    c.insert("exp".into(), json!(exp));
    c.insert("jti".into(), json!(jti));
    if grant.auth_time > 0 {
        c.insert("auth_time".into(), json!(grant.auth_time));
    }
    if let Some(sid) = &grant.sid {
        c.insert("sid".into(), json!(sid));
    }
    insert_all(&mut c, &preset.access_token_extra);
    c.extend(preset_access_claims(preset.id, grant));
    if state.config.access_token_identity_claims {
        c.extend(grant.claims.clone());
    }
    c.extend(grant.access_claims.clone());

    state.store.put(Table::Grants, &jti, grant, Some(exp));
    (state.keys.sign("at+jwt", &Value::Object(c)), ttl)
}

pub fn id_token(
    state: &AppState,
    tenant: &Tenant,
    grant: &Grant,
    access_token: Option<&str>,
    code: Option<&str>,
    include_nonce: bool,
    ttl: Option<i64>,
) -> String {
    let iat = state.now();
    let preset = presets::get_or_generic(&grant.preset);
    let mut c = Map::new();
    c.insert("iss".into(), json!(tenant.issuer));
    c.insert("sub".into(), json!(grant.sub()));
    c.insert("aud".into(), json!(grant.client_id));
    c.insert("azp".into(), json!(grant.client_id));
    c.insert("iat".into(), json!(iat));
    c.insert("exp".into(), json!(iat + ttl.unwrap_or(state.config.id_token_ttl)));
    if grant.auth_time > 0 {
        c.insert("auth_time".into(), json!(grant.auth_time));
    }
    if include_nonce && let Some(nonce) = &grant.nonce {
        c.insert("nonce".into(), json!(nonce));
    }
    if let Some(sid) = &grant.sid {
        c.insert("sid".into(), json!(sid));
    }
    if let Some(acr) = &grant.acr {
        c.insert("acr".into(), json!(acr));
    }
    if let Some(at) = access_token {
        c.insert("at_hash".into(), json!(half_hash(at)));
    }
    if let Some(code) = code {
        c.insert("c_hash".into(), json!(half_hash(code)));
    }
    insert_all(&mut c, &preset.id_token_extra);
    if !state.config.claims_by_scope {
        // User-supplied claims win, including registered ones (handy for negative testing).
        c.extend(grant.claims.clone());
    } else {
        // OIDC Core 5.4: scope claims go in the ID token only for response_type=id_token (no
        // access token is ever issued); otherwise the client fetches them from userinfo.
        // Claims explicitly requested for the ID token (5.5) are always included.
        let scope_claims = access_token.is_none() && code.is_none();
        c.extend(released_claims(state, grant, scope_claims, &grant.requested_claims.id_token));
    }
    state.keys.sign("JWT", &Value::Object(c))
}

pub fn refresh_token(state: &AppState, tenant: &Tenant, grant: &Grant) -> String {
    let iat = state.now();
    let claims = json!({
        "iss": tenant.issuer,
        "sub": grant.sub(),
        "aud": tenant.issuer,
        "client_id": grant.client_id,
        "scope": grant.scope,
        "iat": iat,
        "exp": iat + state.config.refresh_token_ttl,
        "jti": uuid::Uuid::new_v4().to_string(),
        "grant": grant,
    });
    state.keys.sign("rt+jwt", &claims)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Access,
    Refresh,
    Id,
}

impl Kind {
    pub fn hint(self) -> &'static str {
        match self {
            Kind::Access => "access_token",
            Kind::Refresh => "refresh_token",
            Kind::Id => "id_token",
        }
    }
}

pub struct Verified {
    pub kind: Kind,
    pub claims: Map<String, Value>,
    pub grant: Grant,
    pub exp: i64,
    pub iat: i64,
    pub jti: Option<String>,
}

/// Validate one of our tokens (JWT or opaque): signature, expiry and revocation.
pub fn verify(state: &AppState, token: &str) -> Option<Verified> {
    let t = state.now();
    if let Some(o) = state.store.get::<OpaqueToken>(Table::Opaque, token) {
        let mut claims = o.grant.claims.clone();
        claims.insert("client_id".into(), json!(o.grant.client_id));
        claims.insert("scope".into(), json!(o.grant.scope));
        return Some(Verified { kind: Kind::Access, claims, grant: o.grant, exp: o.exp, iat: o.iat, jti: None });
    }

    let (header, claims) = state.keys.verify(token)?;
    let Value::Object(claims) = claims else { return None };
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(i64::MAX);
    if exp <= t {
        return None;
    }
    let jti = claims.get("jti").and_then(Value::as_str).map(String::from);
    if let Some(jti) = &jti
        && state.store.contains(Table::Revoked, jti)
    {
        return None;
    }
    let kind = match header["typ"].as_str() {
        Some("at+jwt") => Kind::Access,
        Some("rt+jwt") => Kind::Refresh,
        _ => Kind::Id,
    };
    let grant = match kind {
        Kind::Refresh => serde_json::from_value(claims.get("grant")?.clone()).ok()?,
        Kind::Access => jti
            .as_ref()
            .and_then(|j| state.store.get::<Grant>(Table::Grants, j))
            .unwrap_or_else(|| grant_from_claims(&claims)),
        Kind::Id => grant_from_claims(&claims),
    };
    let iat = claims.get("iat").and_then(Value::as_i64).unwrap_or_default();
    Some(Verified { kind, claims, grant, exp, iat, jti })
}

/// Revoke an opaque or JWT token issued by this server. Unknown tokens are ignored.
pub fn revoke(state: &AppState, token: &str) {
    if state.store.remove(Table::Opaque, token) {
        return;
    }
    if let Some(v) = verify(state, token)
        && let Some(jti) = v.jti
    {
        state.store.put(Table::Revoked, &jti, &v.exp, Some(v.exp));
    }
}

/// Best-effort reconstruction of a grant from a token's claims (e.g. after a restart).
pub fn grant_from_claims(claims: &Map<String, Value>) -> Grant {
    let client_id = claims
        .get("client_id")
        .or_else(|| claims.get("azp"))
        .or_else(|| claims.get("aud"))
        .map(|v| match v {
            Value::Array(a) => a.first().map(crate::util::value_to_string).unwrap_or_default(),
            v => crate::util::value_to_string(v),
        })
        .unwrap_or_default();
    let identity =
        claims.iter().filter(|(k, _)| !REGISTERED.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    Grant {
        client_id,
        scope: claims.get("scope").and_then(Value::as_str).unwrap_or_default().to_string(),
        preset: "generic".into(),
        claims: identity,
        access_claims: Map::new(),
        nonce: None,
        auth_time: claims.get("auth_time").and_then(Value::as_i64).unwrap_or_default(),
        sid: claims.get("sid").and_then(Value::as_str).map(String::from),
        audience: vec![],
        acr: None,
        requested_claims: Default::default(),
    }
}

/// Standard claims released by each OIDC scope (OIDC Core 5.4).
const SCOPE_CLAIMS: &[(&str, &[&str])] = &[
    (
        "profile",
        &[
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
    ),
    ("email", &["email", "email_verified"]),
    ("address", &["address"]),
    ("phone", &["phone_number", "phone_number_verified"]),
];

/// Identity claims released to the ID token / userinfo. With `claims_by_scope` only the standard
/// claims allowed by the granted scopes (when `by_scope`) plus explicitly `requested` ones are
/// released; everything else stays in the access token.
pub fn released_claims(state: &AppState, grant: &Grant, by_scope: bool, requested: &[String]) -> Map<String, Value> {
    if !state.config.claims_by_scope {
        return grant.claims.clone();
    }
    grant
        .claims
        .iter()
        .filter(|(k, _)| {
            requested.contains(k)
                || (by_scope
                    && SCOPE_CLAIMS
                        .iter()
                        .any(|(scope, claims)| has_scope(&grant.scope, scope) && claims.contains(&k.as_str())))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Claims to expose from userinfo: released identity claims with `sub` first.
pub fn userinfo_claims(state: &AppState, grant: &Grant) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("sub".into(), json!(grant.sub()));
    for (k, v) in released_claims(state, grant, true, &grant.requested_claims.userinfo) {
        if k != "sub" {
            out.insert(k, v);
        }
    }
    out
}
