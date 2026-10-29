use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use localoidc::config::{Cli, Config};
use localoidc::{AppState, load_keys, presets, router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve(&Cli::parse().server).await
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
    tracing::info!(
        "provider issuers: {issuer}/p/<{}>",
        presets::all().iter().map(|p| p.id).collect::<Vec<_>>().join("|")
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
