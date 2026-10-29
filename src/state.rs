use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::clock::Clock;
use crate::config::Config;
use crate::keys::Keys;
use crate::store::{Store, Table};
use crate::util::value_to_string;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<Keys>,
    pub store: Arc<Store>,
}

impl AppState {
    /// Opens `<data_dir>/state.db`, or an in-memory SQLite database when there is no data dir.
    pub fn new(config: Config, keys: Arc<Keys>) -> anyhow::Result<Self> {
        let db = config.data_dir.as_ref().map(|d| d.join("state.db"));
        let store = Store::open(db.as_deref(), Clock::new(config.clock_offset))?;
        // Clients from the config file always win over stale copies in the database.
        for client in &config.clients {
            store.put(Table::Clients, &client.client_id, client, None);
        }
        Ok(Self { config: Arc::new(config), keys, store: Arc::new(store) })
    }

    /// The server's clock, shifted by the configured or API-set offset.
    pub fn clock(&self) -> &Clock {
        self.store.clock()
    }

    /// Now, by the server's (possibly shifted) clock, in Unix seconds.
    pub fn now(&self) -> i64 {
        self.store.clock().now()
    }

    pub fn client(&self, client_id: &str) -> Option<Client> {
        self.store.get(Table::Clients, client_id)
    }

    /// Drop expired codes, tokens, sessions and device grants.
    pub fn purge_expired(&self) {
        self.store.purge_expired();
    }
}

/// A registered client. Unknown clients are accepted unless `strict_clients` is on.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Client {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// Client keys, used to verify RS256 request objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// `RS256` to receive userinfo as a signed JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
}

/// Everything needed to (re)issue tokens for an authenticated user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub client_id: String,
    pub scope: String,
    pub preset: String,
    /// Identity claims (ID token + userinfo).
    pub claims: Map<String, Value>,
    /// Extra claims only placed in access tokens.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub access_claims: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default)]
    pub auth_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Claims explicitly requested with the `claims` request parameter (OIDC Core 5.5).
    #[serde(default, skip_serializing_if = "RequestedClaims::is_empty")]
    pub requested_claims: RequestedClaims,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestedClaims {
    #[serde(default)]
    pub id_token: Vec<String>,
    #[serde(default)]
    pub userinfo: Vec<String>,
}

impl RequestedClaims {
    pub fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty()
    }

    /// Parse the names out of a `claims` request parameter; invalid JSON is an error.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(raw).map_err(|e| format!("claims parameter is not valid JSON: {e}"))?;
        let names =
            |key: &str| v.get(key).and_then(Value::as_object).map(|o| o.keys().cloned().collect()).unwrap_or_default();
        Ok(Self { id_token: names("id_token"), userinfo: names("userinfo") })
    }
}

impl Grant {
    pub fn sub(&self) -> String {
        self.claims.get("sub").map(value_to_string).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub id: String,
    pub created: i64,
    pub tenant: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub response_mode: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Vec<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
    pub audience: Vec<String>,
    #[serde(default)]
    pub requested_claims: RequestedClaims,
}

impl AuthRequest {
    pub fn has_type(&self, t: &str) -> bool {
        self.response_type.split_whitespace().any(|x| x == t)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEntry {
    pub grant: Grant,
    pub tenant: String,
    pub redirect_uri: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub exp: i64,
    /// Set on first redemption; a second redemption revokes `issued`.
    #[serde(default)]
    pub used: bool,
    #[serde(default)]
    pub issued: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueToken {
    pub grant: Grant,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub preset: String,
    pub claims: Map<String, Value>,
    pub access_claims: Map<String, Value>,
    pub auth_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceStatus {
    Pending,
    Approved(Box<Grant>),
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEntry {
    pub device_code: String,
    pub user_code: String,
    pub tenant: String,
    pub client_id: String,
    pub scope: String,
    pub audience: Vec<String>,
    pub exp: i64,
    pub interval: i64,
    pub last_poll: i64,
    pub status: DeviceStatus,
}
