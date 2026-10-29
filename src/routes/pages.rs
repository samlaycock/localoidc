use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::html::{esc, page};
use crate::presets;
use crate::state::AppState;
use crate::tenant::Tenant;

pub async fn css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../../assets/app.css"))
}

pub async fn js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], include_str!("../../assets/app.js"))
}

pub async fn index(State(state): State<AppState>, tenant: Tenant) -> Response {
    let u = |p: &str| tenant.url(p);
    let mut endpoints = vec![
        ("Discovery", u("/.well-known/openid-configuration")),
        ("JWKS", u("/jwks")),
        ("Authorization", u("/authorize")),
        ("Token", u("/token")),
        ("UserInfo", u("/userinfo")),
        ("Introspection", u("/introspect")),
        ("Revocation", u("/revoke")),
        ("End session", u("/end_session")),
        ("Device authorization", u("/device_authorization")),
        ("Pushed auth requests", u("/par")),
        ("Client registration", u("/register")),
        ("Dev token API (non-standard)", u("/dev/api/token")),
    ];
    if let Some(p) = tenant.preset {
        for (label, path) in &p.endpoints {
            endpoints.push((label, u(path)));
        }
    }
    let rows: String = endpoints
        .iter()
        .map(|(label, url)| format!("<tr><td>{}</td><td><code>{}</code></td></tr>", esc(label), esc(url)))
        .collect();

    let root = Tenant::new(&state.config.issuer, None);
    let tenants: String = std::iter::once(format!(
        r#"<a class="tenant" href="{}/" style="--c:#64748b"><b>Root issuer</b><span>preset chosen at login</span><code>{}</code></a>"#,
        root.prefix,
        esc(&root.issuer)
    ))
    .chain(presets::all().iter().map(|p| {
        let t = Tenant::new(&state.config.issuer, Some(p));
        format!(
            r#"<a class="tenant" href="{}" style="--c:{}"><b>{}</b><span>{}</span><code>{}</code></a>"#,
            t.prefix,
            p.color,
            esc(p.name),
            esc(p.protocol),
            esc(&t.issuer)
        )
    }))
    .collect();

    let issuer = esc(&tenant.issuer);
    let dev = esc(&u("/dev/api/token"));
    let body = format!(
        r#"<section class="card hero">
  <div class="eyebrow">Local identity provider</div>
  <h1>Issuer <span class="accent">{issuer}</span></h1>
  <p class="muted">Point your app at this issuer. Any <code>client_id</code>, <code>client_secret</code> and <code>redirect_uri</code> is accepted unless declared in <code>localoidc.toml</code>. Signing in shows a claims editor instead of a password prompt.</p>
  <div class="actions"><a class="btn primary" href="{prefix}/dev">Open token generator</a>
  <a class="btn ghost" href="{prefix}/authorize?client_id=localoidc-demo&amp;redirect_uri={demo}&amp;response_type=code&amp;scope=openid%20profile%20email&amp;state=demo">Try a login</a></div>
</section>
<section class="card">
  <h2>Endpoints</h2>
  <table class="endpoints">{rows}</table>
</section>
<section class="card">
  <h2>Quick start</h2>
  <pre class="code">curl -s '{dev}?email=me@example.com&amp;roles=["admin"]' | jq .
curl -s -X POST {dev} -H 'content-type: application/json' \
  -d '{{"preset":"google","claims":{{"email":"me@example.com","hd":"acme.dev"}}}}'</pre>
</section>
<section class="card">
  <h2>Issuers</h2>
  <p class="muted">Each provider preset is also served as its own issuer, with provider-specific claim shapes and endpoint aliases.</p>
  <div class="tenants">{tenants}</div>
</section>"#,
        prefix = tenant.prefix,
        demo = esc(&url::form_urlencoded::byte_serialize(u("/callback").as_bytes()).collect::<String>()),
    );
    page(&tenant, "Home", &body).into_response()
}

/// Built-in redirect target so logins can be tried without an app.
pub async fn callback(tenant: Tenant, axum::extract::RawQuery(q): axum::extract::RawQuery) -> Response {
    let params = crate::util::parse_form(q.unwrap_or_default().as_bytes());
    let rows: String = params
        .iter()
        .map(|(k, v)| format!("<dt>{}</dt><dd><code class=\"wrap\">{}</code></dd>", esc(k), esc(v)))
        .collect();
    let exchange = params.get("code").map(|code| {
        format!(
            r#"<h2>Exchange the code</h2><pre class="code">curl -s -X POST {token} \
  -d grant_type=authorization_code -d client_id=localoidc-demo \
  -d redirect_uri={cb} -d code={code} | jq .</pre>"#,
            token = esc(&tenant.url("/token")),
            cb = esc(&tenant.url("/callback")),
            code = esc(code),
        )
    });
    let body = format!(
        r#"<section class="card"><div class="eyebrow">Callback</div><h1>Authorization response</h1>
<p class="muted">Fragment parameters (implicit/hybrid flows) are shown below if present.</p>
<dl class="kv">{rows}</dl><dl class="kv" id="fragment"></dl>{exchange}</section>
<script>if(location.hash.length>1){{const d=document.getElementById('fragment');for(const [k,v] of new URLSearchParams(location.hash.slice(1))){{const dt=document.createElement('dt');dt.textContent=k;const dd=document.createElement('dd');const c=document.createElement('code');c.className='wrap';c.textContent=v;dd.append(c);d.append(dt,dd);}}}}</script>"#,
        exchange = exchange.unwrap_or_default(),
    );
    page(&tenant, "Callback", &body).into_response()
}
