//! The dev tools' pages: the web UI's app routes them and loads their data from `/dev/api/*`.

use axum::response::Response;

use crate::html::app_page;
use crate::tenant::Tenant;

/// The issuer's overview: its endpoints and the other issuers.
pub async fn index(tenant: Tenant) -> Response {
    app_page(&tenant, "Home")
}

/// Built-in redirect target, so logins can be tried without an app. The page shows the
/// authorization response's parameters.
pub async fn callback(tenant: Tenant) -> Response {
    app_page(&tenant, "Callback")
}
