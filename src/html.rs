//! The web UI's pages. The UI is a React app in `ui/`, built into `ui/dist` (which is committed)
//! and compiled in; debug builds read `ui/dist` from disk, so a rebuilt UI shows on reload.
//!
//! The dev tools (`/`, `/dev`, `/dev/requests`, `/callback`) are pages of the app that load
//! their data from the `/dev/api/*` endpoints. The protocol's pages (sign-in, device approval,
//! sign-out and errors) are decided here: the server sends the app's page with a description of
//! what to show, plus a plain HTML version that works without JavaScript, for headless browsers
//! such as the conformance suite's.

use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde_json::{Value, json};

use crate::tenant::Tenant;

#[derive(rust_embed::RustEmbed)]
#[folder = "ui/dist/"]
pub struct Dist;

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The app's page for `tenant`. `view` says which protocol page to show (`null` for the dev
/// tools, whose pages the app routes itself); `fallback` is the page's content until the app
/// starts, and all of it where JavaScript doesn't run.
pub fn shell(tenant: &Tenant, status: StatusCode, title: &str, view: Value, fallback: &str) -> Response {
    let Some(index) = Dist::get("index.html") else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "localoidc was built without its web UI (ui/dist)").into_response();
    };
    let cache = if view.is_null() { "no-cache" } else { "no-store" };
    let data = json!({ "issuer": tenant.issuer, "prefix": tenant.prefix, "view": view });
    // `<` can't end the script element when escaped, and JSON reads `<` back as `<`.
    let script = format!(
        r#"<script type="application/json" id="lo-page">{}</script>"#,
        data.to_string().replace('<', "\\u003c")
    );
    let html = String::from_utf8_lossy(&index.data)
        .replacen("<title>localoidc</title>", &format!("<title>{} · localoidc</title>", esc(title)), 1)
        .replacen("</head>", &format!("{script}\n  </head>"), 1)
        .replacen(r#"<div id="root"></div>"#, &format!(r#"<div id="root">{fallback}</div>"#), 1);
    (status, [(header::CACHE_CONTROL, cache)], Html(html)).into_response()
}

/// A page of the dev tools: the app routes it.
pub fn app_page(tenant: &Tenant) -> Response {
    let note = format!(
        r#"<noscript>{}</noscript>"#,
        card(&format!(
            r#"<h1 {H1}>localoidc's pages need JavaScript</h1><p {MUTED}>The protocol endpoints and the JSON APIs work without it, for example <code>{}</code>.</p>"#,
            esc(&tenant.url("/dev/api/token"))
        ))
    );
    shell(tenant, StatusCode::OK, "localoidc", Value::Null, &note)
}

// The pages' plain HTML versions use the theme's colours (CSS variables), so they look like the
// app does for the moment before it starts.
const H1: &str = r#"style="margin:.25rem 0 .75rem;font-size:1.25rem;font-weight:600""#;
const MUTED: &str = r#"style="color:var(--muted-foreground);font-size:.875rem;line-height:1.5""#;
const EYEBROW: &str = r#"style="color:var(--muted-foreground);font-size:.75rem;font-weight:500""#;
pub const PRIMARY_BUTTON: &str = r#"style="background:var(--primary);color:var(--primary-foreground);border:0;border-radius:calc(var(--radius) - 2px);padding:.5rem .875rem;font:inherit;font-size:.875rem;font-weight:500;cursor:pointer""#;
pub const BUTTON: &str = r#"style="background:transparent;color:inherit;border:1px solid var(--border);border-radius:calc(var(--radius) - 2px);padding:.5rem .875rem;font:inherit;font-size:.875rem;font-weight:500;cursor:pointer""#;
pub const INPUT: &str = r#"style="background:transparent;color:inherit;border:1px solid var(--input);border-radius:calc(var(--radius) - 2px);padding:.5rem .75rem;font:inherit;font-size:.875rem""#;

/// A centred card for a page's plain HTML version.
pub fn card(inner: &str) -> String {
    format!(
        r#"<main style="max-width:36rem;margin:4rem auto;padding:0 1rem;font-family:var(--font-sans,system-ui,sans-serif)"><section style="border:1px solid var(--border);border-radius:var(--radius);background:var(--card);color:var(--card-foreground);padding:1.5rem">{inner}</section></main>"#
    )
}

/// A titled card: an eyebrow line, a heading and a paragraph, then `extra`.
pub fn titled_card(eyebrow: &str, title: &str, detail: &str, extra: &str) -> String {
    card(&format!(
        r#"<div {EYEBROW}>{}</div><h1 {H1}>{}</h1><p {MUTED}>{}</p>{extra}"#,
        esc(eyebrow),
        esc(title),
        esc(detail)
    ))
}

pub fn error_page(tenant: &Tenant, status: StatusCode, title: &str, detail: &str) -> Response {
    let view = json!({ "kind": "error", "status": status.as_u16(), "title": title, "detail": detail });
    let fallback = titled_card(&format!("Error {}", status.as_u16()), title, detail, "");
    let mut resp = shell(tenant, status, title, view, &fallback);
    crate::inspector::ErrorNote::attach(&mut resp, title, detail);
    resp
}

pub fn message_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let view = json!({ "kind": "message", "title": title, "detail": detail });
    shell(tenant, StatusCode::OK, title, view, &titled_card("localoidc", title, detail, ""))
}

/// Auto-submitting form for `response_mode=form_post`.
pub fn form_post(action: &str, params: &[(String, String)]) -> Html<String> {
    let inputs: String =
        params.iter().map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, esc(k), esc(v))).collect();
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Submitting…</title></head>
<body onload="document.forms[0].submit()"><form method="post" action="{}">{inputs}
<noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
        esc(action)
    ))
}

/// One of the app's files: hashed assets never change, everything else is revalidated.
pub fn asset(path: &str) -> Response {
    if path.split('/').any(|part| part == "..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(file) = Dist::get(path) else { return StatusCode::NOT_FOUND.into_response() };
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    let content_type = match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    };
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, cache)], file.data).into_response()
}
