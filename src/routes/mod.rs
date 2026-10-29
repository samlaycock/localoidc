pub mod authorize;
pub mod dev;
pub mod device;
pub mod discovery;
pub mod logout;
pub mod pages;
pub mod providers;
pub mod register;
pub mod token;
pub mod userinfo;

use axum::routing::{any, get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Standard endpoints, served at the root issuer and under every `/p/<preset>` issuer.
fn issuer_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::index))
        .route("/callback", get(pages::callback))
        .route("/.well-known/openid-configuration", get(discovery::openid_configuration))
        .route("/.well-known/oauth-authorization-server", get(discovery::openid_configuration))
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .route("/jwks", get(discovery::jwks))
        .route("/authorize", get(authorize::authorize).post(authorize::authorize))
        .route("/login", post(authorize::login))
        .route("/par", post(authorize::par))
        .route("/token", post(token::token))
        .route("/userinfo", get(userinfo::userinfo).post(userinfo::userinfo))
        .route("/introspect", post(userinfo::introspect))
        .route("/revoke", post(userinfo::revoke))
        .route("/end_session", any(logout::end_session))
        .route("/device_authorization", post(device::device_authorization))
        .route("/device", get(device::device_page).post(device::device_submit))
        .route("/register", post(register::register))
        .route("/dev", get(dev::page_handler))
        .route("/dev/api/token", get(dev::api_token_get).post(dev::api_token_post))
        .route("/dev/api/presets", get(dev::api_presets))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(issuer_routes())
        .nest("/p/{preset}", issuer_routes().merge(providers::routes()))
        .route("/assets/app.css", get(pages::css))
        .route("/assets/app.js", get(pages::js))
        .route("/health", get(|| async { "ok" }))
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
