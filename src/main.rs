use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use serde_json::{Map, Value};
use tracing_subscriber::EnvFilter;

use localoidc::config::{Cli, Command, Config, TokenArgs, TokenFormat};
use localoidc::routes::dev::{mint, DevTokenRequest, OneOrMany};
use localoidc::tenant::Tenant;
use localoidc::{load_keys, presets, router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Token(args)) => token(&cli.server, *args),
        Some(Command::Presets) => {
            for p in presets::all() {
                println!("{:<10} {:<20} {:<7} {}", p.id, p.name, p.protocol, p.description);
            }
            Ok(())
        }
        Some(Command::Serve) | None => serve(&cli.server).await,
    }
}

async fn serve(args: &localoidc::config::ServerArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "localoidc=info,tower_http=info".into()))
        .init();

    let config = Config::load(args)?;
    let keys = load_keys(&config)?;
    let addr = format!("{}:{}", config.host, config.port);
    let issuer = config.issuer.clone();
    let db = config.data_dir.as_ref().map(|d| d.join("state.db"));
    let state = AppState::new(config, keys)?;

    let janitor = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            janitor.purge_expired();
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("binding {addr}"))?;
    tracing::info!("localoidc listening on http://{addr}");
    tracing::info!("issuer:          {issuer}");
    if let Some(db) = db {
        tracing::info!("state:           {}", db.display());
    }
    tracing::info!("discovery:       {issuer}/.well-known/openid-configuration");
    tracing::info!("token generator: {issuer}/dev");
    tracing::info!("provider issuers: {issuer}/p/<{}>", presets::all().iter().map(|p| p.id).collect::<Vec<_>>().join("|"));
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn parse_pairs(pairs: &[String]) -> anyhow::Result<Map<String, Value>> {
    let mut map = Map::new();
    for pair in pairs {
        let (k, v) = pair.split_once('=').with_context(|| format!("expected KEY=VALUE, got '{pair}'"))?;
        let value = match serde_json::from_str::<Value>(v) {
            Ok(parsed) if k != "sub" => parsed,
            _ => Value::String(v.to_string()),
        };
        map.insert(k.to_string(), value);
    }
    Ok(map)
}

fn token(server: &localoidc::config::ServerArgs, args: TokenArgs) -> anyhow::Result<()> {
    let config = Config::load(server)?;
    let keys = load_keys(&config)?;
    let tenant_preset = match &args.tenant {
        Some(id) => Some(presets::get(id).with_context(|| format!("unknown preset '{id}'"))?),
        None => None,
    };
    let tenant = Tenant::new(&config.issuer, tenant_preset);
    let state = AppState::new(config, keys)?;

    let mut claims = match &args.claims_json {
        Some(raw) => localoidc::util::parse_claims_object(raw).map_err(anyhow::Error::msg)?,
        None => Map::new(),
    };
    claims.extend(parse_pairs(&args.claims)?);
    let req = DevTokenRequest {
        preset: args.preset.or(args.tenant),
        client_id: Some(args.client_id),
        audience: (!args.audience.is_empty()).then_some(OneOrMany::Many(args.audience)),
        scope: args.scope,
        claims,
        access_token_claims: parse_pairs(&args.access_claims)?,
        expires_in: args.expires_in,
        ..Default::default()
    };
    let out = mint(&state, &tenant, req).map_err(|e| anyhow::anyhow!("{}: {}", e.error, e.description))?;
    let field = |k: &str| out.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    match args.format {
        TokenFormat::Json => println!("{}", serde_json::to_string_pretty(&out)?),
        TokenFormat::Access => println!("{}", field("access_token")),
        TokenFormat::Id => println!("{}", field("id_token")),
        TokenFormat::Refresh => println!("{}", field("refresh_token")),
    }
    Ok(())
}
