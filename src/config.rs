use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;

use crate::state::Client;
use crate::users::User;

#[derive(Parser, Debug)]
#[command(name = "localoidc", version, about = "A local OpenID Connect / OAuth 2.0 provider for offline development")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub server: ServerArgs,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the server (default).
    Serve,
    /// Mint tokens directly from the command line, signed with the server's persisted key.
    Token(Box<TokenArgs>),
    /// List the available provider presets.
    Presets,
    /// List the users declared in the config file.
    Users,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ServerArgs {
    /// Path to a TOML config file (defaults to ./localoidc.toml if present).
    #[arg(long, env = "LOCALOIDC_CONFIG", global = true)]
    pub config: Option<PathBuf>,
    /// Interface to bind.
    #[arg(long, env = "LOCALOIDC_HOST", global = true)]
    pub host: Option<String>,
    /// Port to listen on.
    #[arg(long, short, env = "LOCALOIDC_PORT", global = true)]
    pub port: Option<u16>,
    /// Public issuer URL (default http://localhost:<port>).
    #[arg(long, env = "LOCALOIDC_ISSUER", global = true)]
    pub issuer: Option<String>,
    /// Derive the issuer from each request's Host header instead of a fixed URL.
    #[arg(long, global = true)]
    pub dynamic_issuer: bool,
    /// Skip the login UI and sign in immediately with preset defaults.
    #[arg(long, env = "LOCALOIDC_AUTO_LOGIN", global = true)]
    pub auto_login: bool,
    /// Only accept clients declared in the config file or registered dynamically.
    #[arg(long, global = true)]
    pub strict_clients: bool,
    /// Provider preset used on the root issuer (generic, google, github, ...).
    #[arg(long, env = "LOCALOIDC_DEFAULT_PRESET", global = true)]
    pub default_preset: Option<String>,
    /// Directory where the signing key is persisted (default ~/.localoidc).
    #[arg(long, env = "LOCALOIDC_DATA_DIR", global = true)]
    pub data_dir: Option<PathBuf>,
    /// Generate a throwaway signing key on every start.
    #[arg(long, global = true)]
    pub ephemeral_keys: bool,
    #[arg(long, global = true)]
    pub access_token_ttl: Option<i64>,
    #[arg(long, global = true)]
    pub id_token_ttl: Option<i64>,
    #[arg(long, global = true)]
    pub refresh_token_ttl: Option<i64>,
    /// When to issue refresh tokens.
    #[arg(long, value_enum, global = true)]
    pub refresh_tokens: Option<RefreshPolicy>,
}

#[derive(Args, Debug, Clone)]
pub struct TokenArgs {
    /// Declared user (from `[[users]]` in the config file) to mint tokens for.
    #[arg(long)]
    pub user: Option<String>,
    /// Provider preset whose default claims are used.
    #[arg(long)]
    pub preset: Option<String>,
    /// Issue from a preset tenant issuer (/p/<preset>) instead of the root issuer.
    #[arg(long)]
    pub tenant: Option<String>,
    #[arg(long, default_value = "localoidc-dev")]
    pub client_id: String,
    #[arg(long)]
    pub scope: Option<String>,
    #[arg(long)]
    pub audience: Vec<String>,
    /// Claim override, KEY=VALUE (VALUE parsed as JSON when possible). Repeatable.
    #[arg(long = "claim", short = 'c')]
    pub claims: Vec<String>,
    /// Claims JSON object merged over the preset defaults.
    #[arg(long = "claims")]
    pub claims_json: Option<String>,
    /// Access-token-only claim, KEY=VALUE. Repeatable.
    #[arg(long = "access-claim")]
    pub access_claims: Vec<String>,
    #[arg(long)]
    pub expires_in: Option<i64>,
    /// What to print.
    #[arg(long, value_enum, default_value = "json")]
    pub format: TokenFormat,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFormat {
    Json,
    Access,
    Id,
    Refresh,
}

#[derive(ValueEnum, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RefreshPolicy {
    /// Always issue refresh tokens.
    #[default]
    Always,
    /// Only when the `offline_access` scope is requested.
    OfflineAccess,
    Never,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    issuer: Option<String>,
    dynamic_issuer: Option<bool>,
    auto_login: Option<bool>,
    strict_clients: Option<bool>,
    default_preset: Option<String>,
    data_dir: Option<PathBuf>,
    ephemeral_keys: Option<bool>,
    access_token_ttl: Option<i64>,
    id_token_ttl: Option<i64>,
    refresh_token_ttl: Option<i64>,
    code_ttl: Option<i64>,
    refresh_tokens: Option<RefreshPolicy>,
    access_token_identity_claims: Option<bool>,
    claims_by_scope: Option<bool>,
    clients: Vec<Client>,
    users: Vec<User>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub issuer: String,
    pub dynamic_issuer: bool,
    pub auto_login: bool,
    pub strict_clients: bool,
    pub default_preset: String,
    pub data_dir: Option<PathBuf>,
    pub ephemeral_keys: bool,
    pub access_token_ttl: i64,
    pub id_token_ttl: i64,
    pub refresh_token_ttl: i64,
    pub code_ttl: i64,
    pub refresh_tokens: RefreshPolicy,
    /// Copy identity claims (email, name, roles, ...) into JWT access tokens.
    pub access_token_identity_claims: bool,
    /// Spec-strict claim release: the ID token and userinfo only carry the standard claims
    /// allowed by the requested scopes (profile, email, address, phone). Off by default so
    /// every claim set in the UI/API shows up everywhere.
    pub claims_by_scope: bool,
    pub clients: Vec<Client>,
    /// Named identities from `[[users]]`.
    pub users: Vec<User>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 9400,
            issuer: "http://localhost:9400".into(),
            dynamic_issuer: false,
            auto_login: false,
            strict_clients: false,
            default_preset: "generic".into(),
            data_dir: None,
            ephemeral_keys: false,
            access_token_ttl: 3600,
            id_token_ttl: 3600,
            refresh_token_ttl: 60 * 60 * 24 * 30,
            code_ttl: 300,
            refresh_tokens: RefreshPolicy::Always,
            access_token_identity_claims: true,
            claims_by_scope: false,
            clients: vec![],
            users: vec![],
        }
    }
}

impl Config {
    pub fn load(args: &ServerArgs) -> anyhow::Result<Self> {
        let path = args.config.clone().or_else(|| {
            let p = PathBuf::from("localoidc.toml");
            p.exists().then_some(p)
        });
        let file: FileConfig = match &path {
            Some(p) => {
                let raw = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
                toml::from_str(&raw).with_context(|| format!("parsing {}", p.display()))?
            }
            None => FileConfig::default(),
        };

        let d = Config::default();
        let port = args.port.or(file.port).unwrap_or(d.port);
        let issuer = args
            .issuer
            .clone()
            .or(file.issuer)
            .unwrap_or_else(|| format!("http://localhost:{port}"))
            .trim_end_matches('/')
            .to_string();
        let default_preset = args.default_preset.clone().or(file.default_preset).unwrap_or(d.default_preset);
        if crate::presets::get(&default_preset).is_none() {
            anyhow::bail!("unknown default preset '{default_preset}'");
        }
        crate::users::validate(&file.users)?;
        let data_dir = args
            .data_dir
            .clone()
            .or(file.data_dir)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".localoidc")));

        Ok(Self {
            host: args.host.clone().or(file.host).unwrap_or(d.host),
            port,
            issuer,
            dynamic_issuer: args.dynamic_issuer || file.dynamic_issuer.unwrap_or(false),
            auto_login: args.auto_login || file.auto_login.unwrap_or(false),
            strict_clients: args.strict_clients || file.strict_clients.unwrap_or(false),
            default_preset,
            data_dir,
            ephemeral_keys: args.ephemeral_keys || file.ephemeral_keys.unwrap_or(false),
            access_token_ttl: args.access_token_ttl.or(file.access_token_ttl).unwrap_or(d.access_token_ttl),
            id_token_ttl: args.id_token_ttl.or(file.id_token_ttl).unwrap_or(d.id_token_ttl),
            refresh_token_ttl: args.refresh_token_ttl.or(file.refresh_token_ttl).unwrap_or(d.refresh_token_ttl),
            code_ttl: file.code_ttl.unwrap_or(d.code_ttl),
            refresh_tokens: args.refresh_tokens.or(file.refresh_tokens).unwrap_or_default(),
            access_token_identity_claims: file.access_token_identity_claims.unwrap_or(true),
            claims_by_scope: file.claims_by_scope.unwrap_or(false),
            clients: file.clients,
            users: file.users,
        })
    }

    pub fn user(&self, id: &str) -> Option<&User> {
        self.users.iter().find(|u| u.id == id)
    }

    /// The user a `login_hint` or `username` refers to, by id or email.
    pub fn user_for_login(&self, login: &str) -> Option<&User> {
        self.users.iter().find(|u| u.matches(login))
    }
}
