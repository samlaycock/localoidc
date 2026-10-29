use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde_json::Value;

use crate::tenant::Tenant;

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

pub fn page(tenant: &Tenant, title: &str, body: &str) -> Html<String> {
    let p = &tenant.prefix;
    let badge = match tenant.preset {
        Some(preset) => format!(
            r#"<span class="tenant-badge" style="--c:{}">emulating {}</span>"#,
            preset.color,
            esc(preset.name)
        ),
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · localoidc</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="{p}/"><span class="logo">◎</span> local<b>oidc</b></a>{badge}
  <nav>
    <a href="{p}/dev">Token generator</a>
    <a href="{p}/.well-known/openid-configuration">Discovery</a>
    <a href="{p}/jwks">JWKS</a>
  </nav>
</header>
<main>
{body}
</main>
<script src="/assets/app.js"></script>
</body>
</html>"#,
        title = esc(title),
    ))
}

/// Embed JSON for the page script.
pub fn data_script(v: &Value) -> String {
    format!(
        r#"<script type="application/json" id="lo-data">{}</script>"#,
        v.to_string().replace("</", "<\\/")
    )
}

pub fn error_page(tenant: &Tenant, status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<section class="card narrow"><div class="eyebrow error">Error {}</div><h1>{}</h1><p>{}</p></section>"#,
        status.as_u16(),
        esc(title),
        esc(detail)
    );
    (status, page(tenant, title, &body)).into_response()
}

pub fn message_page(tenant: &Tenant, title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<section class="card narrow"><div class="eyebrow">localoidc</div><h1>{}</h1><p>{}</p></section>"#,
        esc(title),
        esc(detail)
    );
    page(tenant, title, &body).into_response()
}

/// Auto-submitting form for `response_mode=form_post`.
pub fn form_post(action: &str, params: &[(String, String)]) -> Html<String> {
    let inputs: String = params
        .iter()
        .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, esc(k), esc(v)))
        .collect();
    Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>Submitting…</title></head>
<body onload="document.forms[0].submit()"><form method="post" action="{}">{inputs}
<noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
        esc(action)
    ))
}
