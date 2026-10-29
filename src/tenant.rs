use axum::extract::{FromRequestParts, OriginalUri};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::Config;
use crate::presets::{self, Preset};
use crate::state::AppState;

/// An issuer: either the root issuer, or a provider-emulating tenant mounted at `/p/<preset>`.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub preset: Option<&'static Preset>,
    pub issuer: String,
    /// Path prefix for links (e.g. "" or "/p/google").
    pub prefix: String,
    /// The server clock's offset when the request arrived, so pages can warn about it.
    pub clock_offset: i64,
    /// How many faults were armed when the request arrived, so pages can warn about them.
    pub faults_armed: usize,
}

impl Tenant {
    pub fn new(base: &str, preset: Option<&'static Preset>) -> Self {
        let base = base.trim_end_matches('/');
        let issuer = match preset {
            Some(p) => format!("{base}/p/{}", p.id),
            None => base.to_string(),
        };
        let prefix = url::Url::parse(&issuer).map(|u| u.path().trim_end_matches('/').to_string()).unwrap_or_default();
        Self { preset, issuer, prefix, clock_offset: 0, faults_armed: 0 }
    }

    pub fn key(&self) -> &'static str {
        self.preset.map(|p| p.id).unwrap_or("root")
    }

    pub fn default_preset(&self, config: &Config) -> &'static Preset {
        self.preset.unwrap_or_else(|| presets::get_or_generic(&config.default_preset))
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }

    pub fn path(&self, path: &str) -> String {
        format!("{}{}", self.prefix, path)
    }

    pub fn cookie_name(&self) -> String {
        format!("localoidc_sid_{}", self.key())
    }
}

impl FromRequestParts<AppState> for Tenant {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map(|u| u.0.path().to_owned())
            .unwrap_or_else(|| parts.uri.path().to_owned());

        let base = if state.config.dynamic_issuer {
            let host = parts
                .headers
                .get("x-forwarded-host")
                .or_else(|| parts.headers.get(header::HOST))
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            let proto = parts.headers.get("x-forwarded-proto").and_then(|h| h.to_str().ok()).unwrap_or("http");
            format!("{proto}://{host}")
        } else {
            state.config.issuer.clone()
        };

        let preset = match path.strip_prefix("/p/") {
            Some(rest) => {
                let id = rest.split('/').next().unwrap_or_default();
                match presets::get(id) {
                    Some(p) => Some(p),
                    None => {
                        return Err((StatusCode::NOT_FOUND, format!("unknown provider preset '{id}'")).into_response());
                    }
                }
            }
            None => None,
        };
        Ok(Tenant {
            clock_offset: state.clock().offset(),
            faults_armed: state.faults.list().len(),
            ..Tenant::new(&base, preset)
        })
    }
}
