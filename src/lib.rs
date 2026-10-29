pub mod config;
pub mod error;
pub mod fetch;
pub mod html;
pub mod keys;
pub mod presets;
pub mod routes;
pub mod state;
pub mod store;
pub mod tenant;
pub mod tokens;
pub mod util;

use std::sync::Arc;

use anyhow::Context;

pub use routes::router;
pub use state::AppState;

/// Load or create the signing key according to the config.
pub fn load_keys(config: &config::Config) -> anyhow::Result<Arc<keys::Keys>> {
    let keys = match (&config.data_dir, config.ephemeral_keys) {
        (Some(dir), false) => keys::Keys::load_or_create(dir)
            .with_context(|| format!("loading signing key from {}", dir.display()))?,
        _ => keys::Keys::generate()?,
    };
    Ok(Arc::new(keys))
}
