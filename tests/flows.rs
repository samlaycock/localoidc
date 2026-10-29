use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use localoidc::config::Config;
use localoidc::keys::{Keys, decode_unverified};
use localoidc::state::Client;
use localoidc::util::sha256_b64;
use localoidc::{AppState, router};

const ISS: &str = "http://localhost:9400";
const CB: &str = "http://app.test/cb";

fn keys() -> Arc<Keys> {
    static KEYS: OnceLock<Arc<Keys>> = OnceLock::new();
    KEYS.get_or_init(|| Arc::new(Keys::generate().unwrap())).clone()
}

fn app_with(config: Config) -> (Router, AppState) {
    let state = AppState::new(config, keys()).unwrap();
    (router(state.clone()), state)
}

fn app() -> Router {
    app_with(Config::default()).0
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn location(&self) -> url::Url {
        url::Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
    }
    fn cookie(&self) -> String {
        self.headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string()
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    Resp { status, headers, body }
}

async fn get(app: &Router, uri: &str) -> Resp {
    send(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

async fn get_with(app: &Router, uri: &str, headers: &[(&str, &str)]) -> Resp {
    let mut b = Request::get(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    send(app, b.body(Body::empty()).unwrap()).await
}

async fn post_form(app: &Router, uri: &str, form: &[(&str, &str)]) -> Resp {
    post_form_with(app, uri, form, &[]).await
}

async fn post_form_with(app: &Router, uri: &str, form: &[(&str, &str)], headers: &[(&str, &str)]) -> Resp {
    let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(form).finish();
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    send(app, b.body(Body::from(body)).unwrap()).await
}

fn claims(token: &str) -> Value {
    decode_unverified(token).expect("JWT")
}

fn query_param(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned())
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Start an authorization request and return the pending request id from the login page.
async fn start_login(app: &Router, prefix: &str, extra: &str) -> String {
    let res = get(
        app,
        &format!("{prefix}/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid%20profile%20email&state=xyz&nonce=n-1{extra}", enc(CB)),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let marker = r#"name="req" value=""#;
    let start = res.body.find(marker).expect("login form") + marker.len();
    res.body[start..start + 36].to_string()
}

#[tokio::test]
async fn discovery_and_jwks() {
    let app = app();
    let d = get(&app, "/.well-known/openid-configuration").await.json();
    assert_eq!(d["issuer"], ISS);
    assert_eq!(d["token_endpoint"], format!("{ISS}/token"));
    assert!(d["code_challenge_methods_supported"].as_array().unwrap().contains(&json!("S256")));

    let g = get(&app, "/p/google/.well-known/openid-configuration").await.json();
    assert_eq!(g["issuer"], format!("{ISS}/p/google"));
    assert!(g["claims_supported"].as_array().unwrap().contains(&json!("hd")));

    let jwks = get(&app, "/jwks").await.json();
    assert_eq!(jwks["keys"][0]["kty"], "RSA");
    assert_eq!(jwks["keys"][0]["kid"], keys().kid());

    assert_eq!(get(&app, "/p/nope/.well-known/openid-configuration").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authorization_code_flow_with_pkce_refresh_introspect_revoke() {
    let app = app();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = sha256_b64(verifier);
    let req = start_login(&app, "", &format!("&code_challenge={challenge}&code_challenge_method=S256")).await;

    let submitted = json!({ "sub": "u-42", "email": "dev@example.com", "https://example.com/tenant": "acme" });
    let res = post_form(
        &app,
        "/login",
        &[
            ("req", &req),
            ("action", "approve"),
            ("preset", "generic"),
            ("claims", &submitted.to_string()),
            ("access_claims", r#"{"permissions":["orders:write"]}"#),
        ],
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let loc = res.location();
    assert!(loc.as_str().starts_with(CB));
    assert_eq!(query_param(&loc, "state").as_deref(), Some("xyz"));
    assert_eq!(query_param(&loc, "iss").as_deref(), Some(ISS));
    let code = query_param(&loc, "code").unwrap();

    // Wrong verifier fails (and burns the code).
    let bad = post_form(
        &app,
        "/token",
        &[("grant_type", "authorization_code"), ("code", &code), ("code_verifier", "nope"), ("client_id", "web")],
    )
    .await;
    assert_eq!(bad.json()["error"], "invalid_grant");

    let req = start_login(&app, "", &format!("&code_challenge={challenge}&code_challenge_method=S256")).await;
    let res = post_form(
        &app,
        "/login",
        &[
            ("req", &req),
            ("action", "approve"),
            ("preset", "generic"),
            ("claims", &submitted.to_string()),
            ("access_claims", r#"{"permissions":["orders:write"]}"#),
        ],
    )
    .await;
    let code = query_param(&res.location(), "code").unwrap();
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", verifier),
        ("client_id", "web"),
        ("redirect_uri", CB),
    ];
    let tok = post_form(&app, "/token", &form).await;
    assert_eq!(tok.status, StatusCode::OK, "{}", tok.body);
    assert_eq!(tok.headers[header::CACHE_CONTROL], "no-store");
    let tok = tok.json();

    let id = claims(tok["id_token"].as_str().unwrap());
    assert_eq!(id["iss"], ISS);
    assert_eq!(id["aud"], "web");
    assert_eq!(id["sub"], "u-42");
    assert_eq!(id["nonce"], "n-1");
    assert_eq!(id["email"], "dev@example.com");
    assert_eq!(id["https://example.com/tenant"], "acme");
    assert!(id["at_hash"].is_string());
    assert!(keys().verify(tok["id_token"].as_str().unwrap()).is_some());

    let at = tok["access_token"].as_str().unwrap();
    let ac = claims(at);
    assert_eq!(ac["permissions"], json!(["orders:write"]));
    assert_eq!(ac["scope"], "openid profile email");
    assert!(id.get("permissions").is_none());

    let ui = get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {at}"))]).await.json();
    assert_eq!(ui["sub"], "u-42");
    assert_eq!(ui["https://example.com/tenant"], "acme");

    let rt = tok["refresh_token"].as_str().unwrap();
    let refreshed = post_form(
        &app,
        "/token",
        &[("grant_type", "refresh_token"), ("refresh_token", rt), ("client_id", "web"), ("scope", "openid email")],
    )
    .await
    .json();
    assert_eq!(refreshed["scope"], "openid email");
    assert_eq!(claims(refreshed["id_token"].as_str().unwrap())["email"], "dev@example.com");
    let widened =
        post_form(&app, "/token", &[("grant_type", "refresh_token"), ("refresh_token", rt), ("scope", "openid admin")])
            .await
            .json();
    assert_eq!(widened["error"], "invalid_scope");

    let intro = post_form(&app, "/introspect", &[("token", at)]).await.json();
    assert_eq!(intro["active"], true);
    assert_eq!(intro["client_id"], "web");
    assert_eq!(post_form(&app, "/revoke", &[("token", at)]).await.status, StatusCode::OK);
    assert_eq!(post_form(&app, "/introspect", &[("token", at)]).await.json()["active"], false);
    let ui = get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {at}"))]).await;
    assert_eq!(ui.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deny_returns_access_denied() {
    let app = app();
    let req = start_login(&app, "", "").await;
    let res = post_form(&app, "/login", &[("req", &req), ("action", "deny")]).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("access_denied"));
    assert_eq!(query_param(&res.location(), "state").as_deref(), Some("xyz"));
}

#[tokio::test]
async fn implicit_form_post_and_validation_errors() {
    let app = app();
    let res = get(
        &app,
        &format!("/authorize?client_id=spa&redirect_uri={}&response_type=id_token%20token&response_mode=form_post&scope=openid&nonce=abc&dev_claims={}", enc(CB), enc(r#"{"email":"x@y.z"}"#)),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains(r#"name="id_token""#) && res.body.contains(r#"name="access_token""#));
    assert!(res.body.contains(&format!(r#"action="{CB}""#)));

    // Missing nonce on implicit flow.
    let res =
        get(&app, &format!("/authorize?client_id=spa&redirect_uri={}&response_type=id_token&scope=openid", enc(CB)))
            .await;
    let frag = res.location().fragment().unwrap().to_string();
    assert!(frag.contains("error=invalid_request"), "{frag}");

    // Unsupported response type.
    let res = get(&app, &format!("/authorize?client_id=spa&redirect_uri={}&response_type=banana", enc(CB))).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("unsupported_response_type"));

    // No redirect_uri: error page rather than redirect.
    assert_eq!(get(&app, "/authorize?client_id=spa&response_type=code").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn hybrid_flow_includes_c_hash() {
    let app = app();
    let res = get(
        &app,
        &format!("/authorize?client_id=h&redirect_uri={}&response_type=code%20id_token&scope=openid&nonce=n&dev_claims=%7B%7D", enc(CB)),
    )
    .await;
    let frag: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(res.location().fragment().unwrap().as_bytes()).into_owned().collect();
    let id = claims(&frag["id_token"]);
    assert_eq!(id["c_hash"], localoidc::util::half_hash(&frag["code"]));
}

#[tokio::test]
async fn prompt_none_uses_session() {
    let app = app();
    let uri = format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&prompt=none", enc(CB));
    let res = get(&app, &uri).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("login_required"));

    let req = start_login(&app, "", "").await;
    let login = post_form(
        &app,
        "/login",
        &[("req", &req), ("action", "approve"), ("preset", "generic"), ("claims", r#"{"sub":"s1"}"#)],
    )
    .await;
    let cookie = login.cookie();
    let res = get_with(&app, &uri, &[("cookie", &cookie)]).await;
    assert!(query_param(&res.location(), "code").is_some(), "{}", res.location());

    // Logout clears it.
    let out = get_with(
        &app,
        &format!("/end_session?client_id=web&post_logout_redirect_uri={}&state=bye", enc(CB)),
        &[("cookie", &cookie)],
    )
    .await;
    assert_eq!(query_param(&out.location(), "state").as_deref(), Some("bye"));
    let res = get_with(&app, &uri, &[("cookie", &cookie)]).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn dev_api_get_and_post() {
    let app = app();
    let res =
        get(&app, "/dev/api/token?email=me@example.com&roles=%5B%22admin%22%5D&sub=007&expires_in=60").await.json();
    let id = &res["id_token_claims"];
    assert_eq!(id["email"], "me@example.com");
    assert_eq!(id["roles"], json!(["admin"]));
    assert_eq!(id["sub"], "007");
    assert_eq!(res["expires_in"], 60);
    assert!(res["refresh_token"].is_string());

    let req = Request::post("/p/google/dev/api/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "claims": { "hd": "acme.dev", "name": null }, "audience": "api://orders", "access_token_claims": { "tier": "gold" } }).to_string(),
        ))
        .unwrap();
    let res = send(&app, req).await.json();
    assert_eq!(res["issuer"], format!("{ISS}/p/google"));
    assert_eq!(res["id_token_claims"]["hd"], "acme.dev");
    assert!(res["id_token_claims"].get("name").is_none());
    assert_eq!(res["id_token_claims"]["sub"], "109876543210987654321");
    assert_eq!(res["access_token_claims"]["aud"], "api://orders");
    assert_eq!(res["access_token_claims"]["tier"], "gold");
}

#[tokio::test]
async fn github_emulation() {
    let app = app();
    let res = get(&app, "/p/github/dev/api/token?scope=openid&login=octo").await.json();
    let at = res["access_token"].as_str().unwrap();
    assert!(at.starts_with("gho_"));
    let user = get_with(&app, "/p/github/user", &[("authorization", &format!("token {at}"))]).await.json();
    assert_eq!(user["login"], "octo");
    assert_eq!(user["id"], 1234567);
    let emails = get_with(&app, "/p/github/user/emails", &[("authorization", &format!("Bearer {at}"))]).await.json();
    assert_eq!(emails[0]["primary"], true);

    // Full code flow through GitHub's paths; token response is form-encoded by default.
    // GitHub clients omit response_type.
    let res = get(
        &app,
        &format!(
            "/p/github/login/oauth/authorize?client_id=gh&redirect_uri={}&scope=read:user&dev_claims=%7B%7D",
            enc(CB)
        ),
    )
    .await;
    let code = query_param(&res.location(), "code").unwrap();
    let tok = post_form(
        &app,
        "/p/github/login/oauth/access_token",
        &[("client_id", "gh"), ("client_secret", "s"), ("code", &code)],
    )
    .await;
    assert!(tok.body.starts_with("access_token=gho_"), "{}", tok.body);
}

#[tokio::test]
async fn facebook_and_microsoft_shapes() {
    let app = app();
    let at = get(&app, "/p/facebook/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string();
    let me = get(&app, &format!("/p/facebook/v19.0/me?fields=id,email&access_token={at}")).await.json();
    assert_eq!(me, json!({ "id": "10223344556677889", "email": "jane@example.com" }));

    let at = get(&app, "/p/microsoft/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string();
    assert_eq!(claims(&at)["ver"], "2.0");
    let me = get_with(&app, "/p/microsoft/v1.0/me", &[("authorization", &format!("Bearer {at}"))]).await.json();
    assert_eq!(me["id"], "00000000-0000-0000-66f3-3332eca7ea81");
}

#[tokio::test]
async fn device_flow() {
    let app = app();
    let d = post_form(&app, "/device_authorization", &[("client_id", "tv"), ("scope", "openid email")]).await.json();
    let device_code = d["device_code"].as_str().unwrap();
    let user_code = d["user_code"].as_str().unwrap();
    assert_eq!(d["verification_uri"], format!("{ISS}/device"));

    let poll = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", "tv"),
    ];
    assert_eq!(post_form(&app, "/token", &poll).await.json()["error"], "authorization_pending");
    assert_eq!(post_form(&app, "/token", &poll).await.json()["error"], "slow_down");

    let page = get(&app, &format!("/device?user_code={}", user_code.to_lowercase().replace('-', ""))).await;
    assert!(page.body.contains("Approve device"));
    let ok = post_form(
        &app,
        "/device",
        &[("user_code", user_code), ("action", "approve"), ("preset", "generic"), ("claims", r#"{"sub":"tv-user"}"#)],
    )
    .await;
    assert!(ok.body.contains("Device approved"));

    let tok = post_form(&app, "/token", &poll).await.json();
    assert_eq!(claims(tok["id_token"].as_str().unwrap())["sub"], "tv-user");
}

#[tokio::test]
async fn client_credentials_password_and_token_exchange() {
    let app = app();
    let cc = post_form(
        &app,
        "/token",
        &[
            ("grant_type", "client_credentials"),
            ("scope", "orders.read"),
            ("audience", "api://orders"),
            ("dev_access_claims", r#"{"tenant":"t1"}"#),
        ],
    )
    .await;
    assert_eq!(cc.json()["error"], "invalid_client");
    let cc = post_form_with(
        &app,
        "/token",
        &[
            ("grant_type", "client_credentials"),
            ("audience", "api://orders"),
            ("dev_access_claims", r#"{"tenant":"t1"}"#),
        ],
        &[("authorization", "Basic c3ZjOnNlY3JldA==")],
    )
    .await
    .json();
    let c = claims(cc["access_token"].as_str().unwrap());
    assert_eq!(c["sub"], "svc");
    assert_eq!(c["aud"], "api://orders");
    assert_eq!(c["tenant"], "t1");
    assert!(cc.get("refresh_token").is_none());

    let pw = post_form(
        &app,
        "/token",
        &[("grant_type", "password"), ("username", "alice@example.com"), ("password", "x"), ("client_id", "cli")],
    )
    .await
    .json();
    assert_eq!(claims(pw["id_token"].as_str().unwrap())["email"], "alice@example.com");

    let ex = post_form(
        &app,
        "/token",
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
            ("subject_token", pw["access_token"].as_str().unwrap()),
            ("audience", "api://downstream"),
        ],
    )
    .await
    .json();
    assert_eq!(claims(ex["access_token"].as_str().unwrap())["aud"], "api://downstream");
}

#[tokio::test]
async fn registered_clients_are_enforced() {
    let config = Config {
        clients: vec![Client {
            client_id: "conf".into(),
            client_secret: Some("s3cret".into()),
            redirect_uris: vec![CB.into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let (app, _) = app_with(config);
    let res = get(&app, "/authorize?client_id=conf&redirect_uri=http://evil.test/&response_type=code").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    let res =
        get(&app, &format!("/authorize?client_id=conf&redirect_uri={}&response_type=code&dev_claims=%7B%7D", enc(CB)))
            .await;
    let code = query_param(&res.location(), "code").unwrap();
    let bad = post_form(
        &app,
        "/token",
        &[("grant_type", "authorization_code"), ("code", &code), ("client_id", "conf"), ("client_secret", "wrong")],
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);

    // Dynamic registration.
    let req = Request::post("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "redirect_uris": [CB], "client_name": "Dyn" }).to_string()))
        .unwrap();
    let reg = send(&app, req).await;
    assert_eq!(reg.status, StatusCode::CREATED);
    assert!(reg.json()["client_secret"].is_string());
}

#[tokio::test]
async fn pushed_authorization_requests() {
    let app = app();
    let par = post_form(
        &app,
        "/par",
        &[
            ("client_id", "web"),
            ("redirect_uri", CB),
            ("response_type", "code"),
            ("scope", "openid"),
            ("dev_claims", "{}"),
            ("state", "p"),
        ],
    )
    .await;
    assert_eq!(par.status, StatusCode::CREATED);
    let uri = par.json()["request_uri"].as_str().unwrap().to_string();
    let res = get(&app, &format!("/authorize?client_id=web&request_uri={}", enc(&uri))).await;
    assert_eq!(query_param(&res.location(), "state").as_deref(), Some("p"));
    assert!(query_param(&res.location(), "code").is_some());
}

#[tokio::test]
async fn auto_login_mode() {
    let (app, _) = app_with(Config { auto_login: true, default_preset: "keycloak".into(), ..Default::default() });
    let res = get(
        &app,
        &format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&login_hint=bob", enc(CB)),
    )
    .await;
    let code = query_param(&res.location(), "code").unwrap();
    let tok = post_form(&app, "/token", &[("grant_type", "authorization_code"), ("code", &code)]).await.json();
    let id = claims(tok["id_token"].as_str().unwrap());
    assert_eq!(id["preferred_username"], "bob");
    assert_eq!(id["typ"], "ID");
}

#[tokio::test]
async fn pages_render() {
    let app = app();
    for uri in ["/", "/dev", "/p/google", "/p/github/dev", "/device", "/assets/app.js", "/assets/app.css"] {
        assert_eq!(get(&app, uri).await.status, StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn state_survives_restart() {
    let dir = std::env::temp_dir().join(format!("localoidc-test-{}", uuid::Uuid::new_v4()));
    let config = || Config { data_dir: Some(dir.clone()), ..Default::default() };

    // First "process": sign in, revoke a token, mint an opaque token, register a client, leave a code unused.
    let (app, _) = app_with(config());
    let req = start_login(&app, "", "").await;
    let login = post_form(
        &app,
        "/login",
        &[("req", &req), ("action", "approve"), ("preset", "generic"), ("claims", r#"{"sub":"persist"}"#)],
    )
    .await;
    let cookie = login.cookie();
    let unused_code = query_param(&login.location(), "code").unwrap();
    let revoked = get(&app, "/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string();
    post_form(&app, "/revoke", &[("token", &revoked)]).await;
    let gho = get(&app, "/p/github/dev/api/token?scope=openid&login=octo").await.json()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let reg = Request::post("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "redirect_uris": [CB] }).to_string()))
        .unwrap();
    let client_id = send(&app, reg).await.json()["client_id"].as_str().unwrap().to_string();
    drop(app);

    // Second "process" on the same database.
    let (app, state) = app_with(config());
    assert!(dir.join("state.db").exists());
    let uri = format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&prompt=none", enc(CB));
    let res = get_with(&app, &uri, &[("cookie", &cookie)]).await;
    assert!(query_param(&res.location(), "code").is_some(), "session lost: {}", res.location());
    assert_eq!(post_form(&app, "/introspect", &[("token", &revoked)]).await.json()["active"], false);
    let user = get_with(&app, "/p/github/user", &[("authorization", &format!("token {gho}"))]).await.json();
    assert_eq!(user["login"], "octo");
    assert!(state.client(&client_id).is_some());
    let tok = post_form(&app, "/token", &[("grant_type", "authorization_code"), ("code", &unused_code)]).await.json();
    assert_eq!(claims(tok["id_token"].as_str().unwrap())["sub"], "persist");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sign in through the login form and exchange the code; returns the token response.
async fn login_and_exchange(app: &Router, client_id: &str, scope: &str, claims_json: &str) -> Value {
    let res = get(
        app,
        &format!("/authorize?client_id={client_id}&redirect_uri={}&response_type=code&scope={}", enc(CB), enc(scope)),
    )
    .await;
    let marker = r#"name="req" value=""#;
    let start = res.body.find(marker).expect("login form") + marker.len();
    let req = res.body[start..start + 36].to_string();
    let login = post_form(
        app,
        "/login",
        &[("req", &req), ("action", "approve"), ("preset", "generic"), ("claims", claims_json)],
    )
    .await;
    let code = query_param(&login.location(), "code").unwrap();
    post_form(app, "/token", &[("grant_type", "authorization_code"), ("code", &code), ("client_id", client_id)])
        .await
        .json()
}

#[tokio::test]
async fn code_reuse_revokes_issued_tokens() {
    let app = app();
    let res = get(
        &app,
        &format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&dev_claims=%7B%7D", enc(CB)),
    )
    .await;
    let code = query_param(&res.location(), "code").unwrap();
    let form = [("grant_type", "authorization_code"), ("code", code.as_str())];
    let tok = post_form(&app, "/token", &form).await.json();
    let at = tok["access_token"].as_str().unwrap();
    assert_eq!(post_form(&app, "/introspect", &[("token", at)]).await.json()["active"], true);

    assert_eq!(post_form(&app, "/token", &form).await.json()["error"], "invalid_grant");
    assert_eq!(post_form(&app, "/introspect", &[("token", at)]).await.json()["active"], false);
    let rt = tok["refresh_token"].as_str().unwrap();
    assert_eq!(
        post_form(&app, "/token", &[("grant_type", "refresh_token"), ("refresh_token", rt)]).await.json()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn claims_by_scope_releases_only_scoped_standard_claims() {
    let full = r#"{"sub":"s","name":"N","email":"e@x.y","email_verified":true,"phone_number":"+1","roles":["admin"]}"#;

    // Default: everything everywhere.
    let tok = login_and_exchange(&app(), "web", "openid", full).await;
    assert_eq!(claims(tok["id_token"].as_str().unwrap())["roles"], json!(["admin"]));

    let (app, _) = app_with(Config { claims_by_scope: true, ..Default::default() });
    let tok = login_and_exchange(&app, "web", "openid email", full).await;
    let id = claims(tok["id_token"].as_str().unwrap());
    // Code flow: scope claims come from userinfo, not the ID token.
    assert!(id.get("email").is_none() && id.get("name").is_none() && id.get("roles").is_none());
    let at = tok["access_token"].as_str().unwrap();
    let ui = get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {at}"))]).await.json();
    assert_eq!(ui, json!({ "sub": "s", "email": "e@x.y", "email_verified": true }));
    // Non-standard claims stay available in the access token.
    assert_eq!(claims(at)["roles"], json!(["admin"]));

    // Implicit id_token-only: scope claims go in the ID token.
    let res = get(
        &app,
        &format!("/authorize?client_id=web&redirect_uri={}&response_type=id_token&scope=openid%20phone&nonce=n&dev_claims={}", enc(CB), enc(full)),
    )
    .await;
    let frag: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(res.location().fragment().unwrap().as_bytes()).into_owned().collect();
    let id = claims(&frag["id_token"]);
    assert_eq!(id["phone_number"], "+1");
    assert!(id.get("email").is_none());
}

#[tokio::test]
async fn relogin_keeps_auth_time_unless_reauthentication_is_required() {
    let app = app();
    let uri = |extra: &str| {
        format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid{extra}", enc(CB))
    };
    let login = |cookie: Option<String>, extra: &'static str| {
        let app = app.clone();
        let uri = uri(extra);
        async move {
            let headers: Vec<(&str, &str)> = cookie.as_deref().map(|c| vec![("cookie", c)]).unwrap_or_default();
            let page = get_with(&app, &uri, &headers).await;
            let marker = r#"name="req" value=""#;
            let start = page.body.find(marker).unwrap() + marker.len();
            let req = page.body[start..start + 36].to_string();
            let mut b = Request::post("/login").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(c) = &cookie {
                b = b.header("cookie", c);
            }
            let body = format!("req={req}&action=approve&preset=generic");
            let res = send(&app, b.body(Body::from(body)).unwrap()).await;
            let code = query_param(&res.location(), "code").unwrap();
            let tok = post_form(&app, "/token", &[("grant_type", "authorization_code"), ("code", &code)]).await.json();
            (res.cookie(), claims(tok["id_token"].as_str().unwrap())["auth_time"].as_i64().unwrap())
        }
    };
    let (cookie, first) = login(None, "").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, again) = login(Some(cookie.clone()), "&max_age=10000").await;
    assert_eq!(again, first);
    let (_, forced) = login(Some(cookie), "&prompt=login").await;
    assert!(forced > first);
}

#[tokio::test]
async fn logout_validates_id_token_hint_for_registered_clients() {
    let config = Config {
        clients: vec![Client {
            client_id: "reg".into(),
            redirect_uris: vec![CB.into()],
            post_logout_redirect_uris: vec!["http://app.test/bye".into()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let (app, _) = app_with(config);
    let tok = login_and_exchange(&app, "reg", "openid", r#"{"sub":"s"}"#).await;
    let hint = tok["id_token"].as_str().unwrap();
    let bye = enc("http://app.test/bye");

    let ok = get(&app, &format!("/end_session?id_token_hint={hint}&post_logout_redirect_uri={bye}&state=x")).await;
    assert_eq!(ok.location().as_str(), "http://app.test/bye?state=x");

    // No hint, unregistered URI, forged hint, hint for another client.
    for uri in [
        format!("/end_session?client_id=reg&post_logout_redirect_uri={bye}"),
        format!("/end_session?id_token_hint={hint}&post_logout_redirect_uri={}", enc("http://evil.test/")),
        format!("/end_session?id_token_hint={}x&post_logout_redirect_uri={bye}", &hint[..hint.len() - 1]),
        format!("/end_session?client_id=other&id_token_hint={hint}&post_logout_redirect_uri={bye}"),
    ] {
        let res = get(&app, &uri).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(res.headers.get(header::LOCATION).is_none());
    }

    // No redirect requested: signed-out page.
    assert!(get(&app, "/end_session").await.body.contains("Signed out"));
}

async fn register(app: &Router, meta: Value) -> Resp {
    let req = Request::post("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(meta.to_string()))
        .unwrap();
    send(app, req).await
}

#[tokio::test]
async fn registration_options_signed_userinfo_and_request_objects() {
    let app = app();
    let bad = register(&app, json!({ "redirect_uris": ["https://app.test/cb#frag"] })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.json()["error"], "invalid_redirect_uri");

    // Signed userinfo.
    let client = register(&app, json!({ "redirect_uris": [CB], "userinfo_signed_response_alg": "RS256" })).await.json();
    let cid = client["client_id"].as_str().unwrap();
    let res = get(&app, &format!("/authorize?client_id={cid}&redirect_uri={}&response_type=code&scope=openid&dev_claims=%7B%22sub%22%3A%22u%22%7D", enc(CB))).await;
    let code = query_param(&res.location(), "code").unwrap();
    let tok = post_form(
        &app,
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", cid),
            ("client_secret", client["client_secret"].as_str().unwrap()),
        ],
    )
    .await
    .json();
    let ui =
        get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {}", tok["access_token"].as_str().unwrap()))])
            .await;
    assert_eq!(ui.headers[header::CONTENT_TYPE], "application/jwt");
    let (_, ui_claims) = keys().verify(&ui.body).expect("signed userinfo");
    assert_eq!(ui_claims["aud"], cid);
    assert_eq!(ui_claims["sub"], "u");

    // RS256 request objects are verified against the client's registered JWKS.
    let client_keys = Keys::generate().unwrap();
    let rp = register(&app, json!({ "redirect_uris": [CB], "jwks": client_keys.jwks() })).await.json();
    let rp_id = rp["client_id"].as_str().unwrap();
    let request = |signer: &Keys| {
        signer.sign("oauth-authz-req+jwt", &json!({
            "client_id": rp_id, "redirect_uri": CB, "response_type": "code", "scope": "openid", "state": "ro", "dev_claims": "{}"
        }))
    };
    let ok = get(&app, &format!("/authorize?client_id={rp_id}&request={}", request(&client_keys))).await;
    assert_eq!(query_param(&ok.location(), "state").as_deref(), Some("ro"));
    let forged = get(&app, &format!("/authorize?client_id={rp_id}&request={}", request(&keys()))).await;
    assert_eq!(forged.status, StatusCode::BAD_REQUEST);
    assert!(forged.body.contains("signature"));
}

#[tokio::test]
async fn claims_parameter_and_hybrid_release_under_claims_by_scope() {
    let (app, _) = app_with(Config { claims_by_scope: true, ..Default::default() });
    let identity = enc(r#"{"sub":"s","name":"N","email":"e@x.y","roles":["r"]}"#);

    // Hybrid code id_token: no scope claims in the front-channel ID token...
    let res = get(&app, &format!(
        "/authorize?client_id=web&redirect_uri={}&response_type=code%20id_token&scope=openid%20email&nonce=n&dev_claims={identity}", enc(CB))).await;
    let frag: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(res.location().fragment().unwrap().as_bytes()).into_owned().collect();
    assert!(claims(&frag["id_token"]).get("email").is_none());

    // ...but explicitly requested claims are released where asked, even without the scope.
    let requested = enc(r#"{"id_token":{"roles":null},"userinfo":{"name":{"essential":true}}}"#);
    let res = get(&app, &format!(
        "/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&claims={requested}&dev_claims={identity}", enc(CB))).await;
    let code = query_param(&res.location(), "code").unwrap();
    let tok = post_form(&app, "/token", &[("grant_type", "authorization_code"), ("code", &code)]).await.json();
    let id = claims(tok["id_token"].as_str().unwrap());
    assert_eq!(id["roles"], json!(["r"]));
    assert!(id.get("name").is_none());
    let at = tok["access_token"].as_str().unwrap();
    let ui = get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {at}"))]).await.json();
    assert_eq!(ui, json!({ "sub": "s", "name": "N" }));

    let bad = get(
        &app,
        &format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&claims=nope", enc(CB)),
    )
    .await;
    assert_eq!(query_param(&bad.location(), "error").as_deref(), Some("invalid_request"));
}

#[tokio::test]
async fn signing_key_rotation() {
    let dir = std::env::temp_dir().join(format!("localoidc-rotate-{}", uuid::Uuid::new_v4()));
    let keys = Arc::new(Keys::load_or_create(&dir).unwrap());
    let state = AppState::new(Config { data_dir: Some(dir.clone()), ..Default::default() }, keys.clone()).unwrap();
    let app = router(state);
    let kid_of = |t: &str| localoidc::keys::decode_header_unverified(t).unwrap()["kid"].as_str().unwrap().to_string();
    let mint = || async { get(&app, "/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string() };
    let userinfo_ok = |t: String| {
        let app = app.clone();
        async move {
            get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {t}"))]).await.status == StatusCode::OK
        }
    };

    let original_kid = keys.kid();
    let old_token = mint().await;

    let rotated = send(&app, Request::post("/dev/api/rotate-keys").body(Body::empty()).unwrap()).await.json();
    let new_kid = rotated["kid"].as_str().unwrap().to_string();
    assert_ne!(new_kid, original_kid);
    assert_eq!(rotated["retired_kids"], json!([original_kid]));

    let jwks = get(&app, "/jwks").await.json();
    let kids: Vec<&str> = jwks["keys"].as_array().unwrap().iter().map(|k| k["kid"].as_str().unwrap()).collect();
    assert_eq!(kids, vec![new_kid.as_str(), original_kid.as_str()]);

    // New tokens use the new key; old tokens still verify.
    assert_eq!(kid_of(&mint().await), new_kid);
    assert!(userinfo_ok(old_token.clone()).await);

    // Keys persist across a restart.
    let reloaded = Keys::load_or_create(&dir).unwrap();
    assert_eq!(reloaded.kid(), new_kid);
    assert_eq!(reloaded.jwks()["keys"].as_array().unwrap().len(), 2);

    // After two more rotations the original key falls out of the ring (2 retired keys kept).
    for _ in 0..2 {
        send(&app, Request::post("/p/google/dev/api/rotate-keys").body(Body::empty()).unwrap()).await;
    }
    assert_eq!(get(&app, "/jwks").await.json()["keys"].as_array().unwrap().len(), 3);
    assert!(!userinfo_ok(old_token).await);
    assert_eq!(std::fs::read_dir(dir.join("retired-keys")).unwrap().count(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

fn users_app(auto_login: bool) -> Router {
    let users = serde_json::from_value(json!([
        {
            "id": "alice",
            "label": "Alice (admin)",
            "preset": "google",
            "claims": { "email": "alice@acme.dev", "roles": ["admin"] },
            "access_claims": { "permissions": ["orders:write"] },
            "password": "s3cret"
        },
        { "id": "bob", "claims": { "sub": "bob-1", "email": "bob@acme.dev" } },
        { "id": "carol", "preset": "github", "claims": { "login": "carol" } }
    ]))
    .unwrap();
    app_with(Config { users, auto_login, ..Default::default() }).0
}

/// Run an implicit `id_token token` request and return the fragment parameters.
async fn implicit(app: &Router, extra: &str) -> std::collections::HashMap<String, String> {
    let res = get(
        app,
        &format!(
            "/authorize?client_id=spa&redirect_uri={}&response_type=id_token%20token&scope=openid&nonce=n{extra}",
            enc(CB)
        ),
    )
    .await;
    url::form_urlencoded::parse(res.location().fragment().unwrap_or_default().as_bytes()).into_owned().collect()
}

#[tokio::test]
async fn declared_users_sign_in_with_dev_user() {
    let app = users_app(false);
    let frag = implicit(&app, "&dev_user=alice").await;
    let id = claims(&frag["id_token"]);
    assert_eq!(id["email"], "alice@acme.dev");
    assert_eq!(id["roles"], json!(["admin"]));
    // A stable subject shaped like Google's, not the preset's shared example.
    let sub = id["sub"].as_str().unwrap();
    assert!(sub.len() == 21 && sub.chars().all(|c| c.is_ascii_digit()), "{sub}");
    assert_ne!(sub, "109876543210987654321");
    assert_eq!(claims(&implicit(&app, "&dev_user=alice").await["id_token"])["sub"], sub);
    assert_eq!(claims(&frag["access_token"])["permissions"], json!(["orders:write"]));

    // dev_claims layer over the user.
    let frag = implicit(&app, &format!("&dev_user=bob&dev_claims={}", enc(r#"{"name":"Robert"}"#))).await;
    let id = claims(&frag["id_token"]);
    assert_eq!((id["sub"].as_str(), id["name"].as_str()), (Some("bob-1"), Some("Robert")));

    // Presets that derive `sub` from another claim get a stable one of those.
    let id = claims(&implicit(&app, "&dev_user=carol").await["id_token"]);
    let gh_id = id["id"].as_i64().unwrap();
    assert_ne!(gh_id, 1234567);
    assert_eq!(id["sub"], gh_id.to_string());

    let frag = implicit(&app, "&dev_user=nobody").await;
    assert_eq!(frag["error"], "invalid_request");
}

#[tokio::test]
async fn declared_users_in_dev_api_and_login_page() {
    let app = users_app(false);
    let req = Request::post("/dev/api/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "user": "alice", "claims": { "name": "Al" }, "access_token_claims": { "tier": "gold" } })
                .to_string(),
        ))
        .unwrap();
    let res = send(&app, req).await.json();
    assert_eq!(res["preset"], "google");
    assert_eq!(res["id_token_claims"]["email"], "alice@acme.dev");
    assert_eq!(res["id_token_claims"]["name"], "Al");
    assert_eq!(res["access_token_claims"]["permissions"], json!(["orders:write"]));
    assert_eq!(res["access_token_claims"]["tier"], "gold");

    let res = get(&app, "/dev/api/token?user=bob").await.json();
    assert_eq!(res["id_token_claims"]["sub"], "bob-1");
    assert_eq!(get(&app, "/dev/api/token?user=nobody").await.status, StatusCode::BAD_REQUEST);

    let users = get(&app, "/p/keycloak/dev/api/users").await.json();
    assert_eq!(users.as_array().unwrap().len(), 3);
    assert_eq!(users[0]["label"], "Alice (admin)");
    assert_eq!(users[1]["preset"], "keycloak");
    assert!(users[0].get("password").is_none());

    let page =
        get(&app, &format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid", enc(CB))).await;
    assert!(page.body.contains(r#""users":[{"#) && page.body.contains("alice@acme.dev"));
    assert!(!page.body.contains("s3cret"));
}

#[tokio::test]
async fn declared_users_with_password_grant_and_auto_login() {
    let app = users_app(true);
    let grant = |username: &'static str, password: &'static str| {
        let app = app.clone();
        async move {
            post_form(
                &app,
                "/token",
                &[
                    ("grant_type", "password"),
                    ("username", username),
                    ("password", password),
                    ("client_id", "cli"),
                    ("scope", "openid"),
                ],
            )
            .await
        }
    };
    let res = grant("alice", "wrong").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json()["error"], "invalid_grant");
    let res = grant("ALICE@acme.dev", "s3cret").await.json();
    assert_eq!(claims(res["id_token"].as_str().unwrap())["email"], "alice@acme.dev");
    // Users without a password accept any; unknown usernames keep the old behaviour.
    let res = grant("bob", "whatever").await.json();
    assert_eq!(claims(res["id_token"].as_str().unwrap())["sub"], "bob-1");
    let res = grant("dave@acme.dev", "x").await.json();
    assert_eq!(claims(res["id_token"].as_str().unwrap())["email"], "dave@acme.dev");

    // --auto-login: a login_hint naming a user signs in as them.
    let id = claims(&implicit(&app, "&login_hint=bob").await["id_token"]);
    assert_eq!(id["email"], "bob@acme.dev");
}

#[test]
fn declared_users_are_validated() {
    let load = |toml: &str| {
        let path = std::env::temp_dir().join(format!("localoidc-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&path, toml).unwrap();
        let args = localoidc::config::ServerArgs { config: Some(path.clone()), ..Default::default() };
        let result = Config::load(&args);
        std::fs::remove_file(path).unwrap();
        result
    };
    let config = load(
        r#"
[[users]]
id = "alice"
preset = "okta"
claims = { email = "alice@acme.dev", groups = ["admins"] }
"#,
    )
    .unwrap();
    assert_eq!(config.user("alice").unwrap().claims["groups"], json!(["admins"]));
    assert!(load("[[users]]\nid = \"a\"\n[[users]]\nid = \"a\"\n").is_err());
    assert!(load("[[users]]\nid = \"a\"\npreset = \"nope\"\n").is_err());
    assert!(load("[[users]]\nid = \"a\"\nemail = \"oops\"\n").is_err());
}

#[tokio::test]
async fn overriding_the_sub_from_claim_rederives_sub() {
    let app = app();
    // Dev API, on presets whose `sub` comes from `id` (numeric and string ids).
    let res = get(&app, "/p/github/dev/api/token?scope=openid&id=42").await.json();
    assert_eq!((&res["id_token_claims"]["id"], &res["id_token_claims"]["sub"]), (&json!(42), &json!("42")));
    let res = get(&app, "/p/discord/dev/api/token?scope=openid&id=99887766").await.json();
    assert_eq!(res["id_token_claims"]["sub"], "99887766");
    // An explicit `sub` still wins, and leaving `id` alone keeps the default.
    let res = get(&app, "/p/github/dev/api/token?scope=openid&id=42&sub=custom").await.json();
    assert_eq!(res["id_token_claims"]["sub"], "custom");
    let res = get(&app, "/p/github/dev/api/token?scope=openid&name=Jo").await.json();
    assert_eq!(res["id_token_claims"]["sub"], "1234567");

    // dev_claims on /authorize.
    let res = get(
        &app,
        &format!("/authorize?client_id=spa&redirect_uri={}&response_type=id_token&scope=openid&nonce=n&dev_preset=github&dev_claims={}", enc(CB), enc(r#"{"id":7}"#)),
    )
    .await;
    let frag: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(res.location().fragment().unwrap().as_bytes()).into_owned().collect();
    assert_eq!(claims(&frag["id_token"])["sub"], "7");

    // dev_claims on the password grant.
    let res = post_form(
        &app,
        "/token",
        &[
            ("grant_type", "password"),
            ("username", "jo"),
            ("password", "x"),
            ("client_id", "cli"),
            ("scope", "openid"),
            ("dev_preset", "github"),
            ("dev_claims", r#"{"id":8}"#),
        ],
    )
    .await
    .json();
    assert_eq!(claims(res["id_token"].as_str().unwrap())["sub"], "8");
}

async fn set_clock(app: &Router, body: Value) -> Resp {
    let req = Request::post("/dev/api/clock")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req).await
}

#[tokio::test]
async fn clock_offset_expires_server_side_state() {
    let app = app();
    assert_eq!(get(&app, "/dev/api/clock").await.json()["offset"], 0);
    let tokens = get(&app, "/dev/api/token?email=me@example.com").await.json();

    // An authorization code, a session and a max_age-bound silent login.
    let auth = |extra: &str| {
        format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid{extra}", enc(CB))
    };
    let res = get(&app, &auth(&format!("&dev_claims={}", enc(r#"{"sub":"s1"}"#)))).await;
    let cookie = res.cookie();
    let code = query_param(&res.location(), "code").unwrap();

    // Two hours on: the code (5 min) has expired, and max_age=3600 forces a new login, but the
    // session itself (30 days) is still there.
    let res = set_clock(&app, json!({ "advance": "2h" })).await.json();
    assert_eq!((res["offset"].as_i64(), res["offset_text"].as_str()), (Some(7200), Some("+2h")));
    let res = post_form(
        &app,
        "/token",
        &[("grant_type", "authorization_code"), ("code", &code), ("client_id", "web"), ("redirect_uri", CB)],
    )
    .await;
    assert_eq!(res.json()["error_description"], "authorization code has expired");
    let res = get_with(&app, &auth("&prompt=none&max_age=3600"), &[("cookie", &cookie)]).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("login_required"));
    let res = get_with(&app, &auth("&prompt=none"), &[("cookie", &cookie)]).await;
    assert!(query_param(&res.location(), "code").is_some());

    // 31 days on: the refresh token and the access token have expired, and so has the session.
    set_clock(&app, json!({ "offset": "31d" })).await;
    let res = post_form(
        &app,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("client_id", "localoidc-dev"),
        ],
    )
    .await;
    assert_eq!(res.json()["error"], "invalid_grant");
    let bearer = format!("Bearer {}", tokens["access_token"].as_str().unwrap());
    assert_eq!(get_with(&app, "/userinfo", &[("authorization", &bearer)]).await.status, StatusCode::UNAUTHORIZED);
    let res = get_with(&app, &auth("&prompt=none"), &[("cookie", &cookie)]).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("login_required"));

    // Reset: back to real time.
    assert_eq!(set_clock(&app, json!({ "reset": true })).await.json()["offset"], 0);
}

#[tokio::test]
async fn clock_offset_shifts_issued_timestamps() {
    let (app, _) = app_with(Config { clock_offset: 600, ..Default::default() });
    let real = localoidc::util::wall_clock();
    let iat = |res: &Value| res["access_token_claims"]["iat"].as_i64().unwrap();
    let res = get(&app, "/dev/api/token").await.json();
    assert!((iat(&res) - real - 600).abs() <= 5, "{}", iat(&res));

    // Behind real time, set in plain seconds.
    set_clock(&app, json!({ "offset": -3600 })).await;
    let res = get(&app, "/dev/api/token").await.json();
    assert!((iat(&res) - real + 3600).abs() <= 5, "{}", iat(&res));

    // Pages warn while the clock is shifted.
    let page = get(&app, "/dev").await.body;
    assert!(page.contains("clock-banner") && page.contains("<b>-1h</b> behind"), "{page}");
    set_clock(&app, json!({ "reset": true })).await;
    assert!(!get(&app, "/dev").await.body.contains("clock-banner"));

    // Bad requests leave the clock alone.
    for body in [
        json!({}),
        json!({ "offset": 1, "reset": true }),
        json!({ "advance": "soon" }),
        json!({ "offset": "6000w" }),
        json!({ "offset": "40000d" }),
    ] {
        let res = set_clock(&app, body.clone()).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(get(&app, "/dev/api/clock").await.json()["offset"], 0);
}

async fn inspected(app: &Router, query: &str) -> Vec<Value> {
    let res = get(app, &format!("/dev/api/requests{query}")).await.json();
    res["entries"].as_array().unwrap().clone()
}

#[tokio::test]
async fn inspector_records_requests_and_why_they_failed() {
    let app = app();
    // A bad code, with Basic client authentication.
    post_form_with(
        &app,
        "/token",
        &[("grant_type", "authorization_code"), ("code", "not-a-real-code-123"), ("redirect_uri", CB)],
        &[("authorization", "Basic d2ViOnMzY3JldA==")],
    )
    .await;
    // client_secret_post.
    post_form(
        &app,
        "/token",
        &[("grant_type", "client_credentials"), ("client_id", "svc"), ("client_secret", "hunter2")],
    )
    .await;
    // An error redirected back to the client, a form_post success and an HTML error page.
    get(&app, &format!("/authorize?client_id=spa&redirect_uri={}&response_type=banana", enc(CB))).await;
    get(
        &app,
        &format!("/authorize?client_id=spa&redirect_uri={}&response_type=id_token&response_mode=form_post&scope=openid&nonce=n&dev_claims=%7B%7D", enc(CB)),
    )
    .await;
    get(&app, "/authorize?client_id=spa&response_type=code").await;
    // GitHub reports token errors as HTTP 200 with a form-encoded body.
    post_form(&app, "/p/github/login/oauth/access_token", &[("code", "nope-nope-nope"), ("client_id", "gh")]).await;
    // A bearer token names its client.
    let token = get(&app, "/dev/api/token?client_id=cli").await.json()["access_token"].as_str().unwrap().to_string();
    get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {token}"))]).await;
    // Never recorded.
    get(&app, "/assets/app.css").await;
    get(&app, "/health").await;
    get(&app, "/p/okta/dev/requests").await;

    let all = inspected(&app, "").await;
    let by = |endpoint: &str, n: usize| all.iter().filter(|e| e["endpoint"] == endpoint).nth(n).unwrap().clone();
    assert_eq!(all.len(), 8, "{all:#?}");

    let userinfo = &all[0];
    assert_eq!((&userinfo["client_id"], &userinfo["outcome"]), (&json!("cli"), &json!("OK")));
    assert!(
        userinfo["authorization"].as_str().unwrap().starts_with("Bearer ey")
            && userinfo["authorization"].as_str().unwrap().ends_with('…')
    );
    assert_eq!(all[1]["category"], "dev");

    let github = &all[2];
    assert_eq!(
        (&github["issuer"], &github["status"], &github["error"]),
        (&json!("github"), &json!(200), &json!("invalid_grant"))
    );

    let page = by("/authorize", 0);
    assert_eq!((&page["status"], &page["error"]), (&json!(400), &json!("Missing redirect_uri")));
    assert_eq!(page["error_description"], "The authorization request did not include a redirect_uri.");
    assert_eq!(by("/authorize", 1)["outcome"], "form_post with id_token");
    let redirected = by("/authorize", 2);
    assert_eq!((&redirected["error"], &redirected["redirect"]), (&json!("unsupported_response_type"), &json!(CB)));
    assert_eq!(redirected["error_description"], "unsupported response_type 'banana'");

    let cc = by("/token", 0);
    assert_eq!((&cc["client_id"], &cc["outcome"]), (&json!("svc"), &json!("tokens: access_token")));
    assert_eq!(cc["params"]["client_secret"], "•••");
    let bad = by("/token", 1);
    assert_eq!((&bad["client_id"], &bad["authorization"]), (&json!("web"), &json!("Basic web:•••")));
    assert_eq!((&bad["status"], &bad["error"]), (&json!(400), &json!("invalid_grant")));
    assert_eq!(bad["error_description"], "authorization code is invalid");
    assert_eq!(bad["params"]["code"], "not-a-re…");

    // Filters.
    assert_eq!(inspected(&app, "?client_id=web").await.len(), 1);
    assert_eq!(inspected(&app, "?errors=true").await.len(), 4);
    assert_eq!(inspected(&app, &format!("?after={}", bad["id"])).await.len(), 7);
    assert_eq!(inspected(&app, "?limit=2").await.len(), 2);

    // Clearing keeps the ids going, so pollers using `after` don't miss anything.
    let res = send(&app, Request::delete("/dev/api/requests").body(Body::empty()).unwrap()).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = get(&app, "/dev/api/requests").await.json();
    assert_eq!((res["entries"].as_array().unwrap().len(), res["latest_id"].as_u64()), (0, Some(8)));

    // HTML pages are summarised by their title.
    start_login(&app, "", "").await;
    assert_eq!(inspected(&app, "").await[0]["outcome"], "page: Sign in");
}

async fn arm(app: &Router, body: Value) -> Resp {
    let req = Request::post("/dev/api/faults")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, req).await
}

#[tokio::test]
async fn faults_fail_matching_requests() {
    let app = app();
    let cc = |client: &'static str| {
        let app = app.clone();
        async move { post_form(&app, "/token", &[("grant_type", "client_credentials"), ("client_id", client)]).await }
    };

    // Back-channel: the next two client_credentials requests from `svc` fail; others don't.
    let res = arm(&app, json!({ "endpoint": "token", "client_id": "svc", "grant_type": "client_credentials", "error": "invalid_grant", "count": 2 })).await;
    assert_eq!(res.status, StatusCode::CREATED);
    let id = res.json()["id"].as_u64().unwrap();
    assert_eq!(cc("other").await.status, StatusCode::OK);
    for _ in 0..2 {
        let res = cc("svc").await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
        assert_eq!(res.headers["x-localoidc-fault"], id.to_string().as_str());
        assert_eq!(res.json()["error_description"], format!("injected by localoidc (fault {id})"));
    }
    assert_eq!(cc("svc").await.status, StatusCode::OK);

    // Provider aliases and issuer filters: Keycloak's userinfo fails until removed; root's doesn't.
    let res =
        arm(&app, json!({ "endpoint": "userinfo", "issuer": "keycloak", "error": "invalid_token", "always": true }))
            .await;
    let always = res.json()["id"].as_u64().unwrap();
    let token = get(&app, "/p/keycloak/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string();
    let bearer = format!("Bearer {token}");
    for _ in 0..2 {
        let res = get_with(&app, "/p/keycloak/protocol/openid-connect/userinfo", &[("authorization", &bearer)]).await;
        assert_eq!((res.status, res.json()["error"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid_token")));
    }
    let root = get(&app, "/dev/api/token").await.json()["access_token"].as_str().unwrap().to_string();
    let res = get_with(&app, "/userinfo", &[("authorization", &format!("Bearer {root}"))]).await;
    assert_eq!(res.status, StatusCode::OK);

    // Defaults: a bare fault is a 500 server_error. A delay without an error just slows things down.
    arm(&app, json!({ "endpoint": "jwks" })).await;
    let res = get(&app, "/.well-known/jwks.json").await;
    assert_eq!((res.status, res.json()["error"].as_str()), (StatusCode::INTERNAL_SERVER_ERROR, Some("server_error")));
    arm(&app, json!({ "endpoint": "jwks", "delay_ms": 300 })).await;
    let started = std::time::Instant::now();
    assert_eq!(get(&app, "/jwks").await.status, StatusCode::OK);
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));

    // Authorization errors go back to the client, armed or per request with `dev_error`.
    let auth = |extra: &str| {
        format!("/authorize?client_id=web&redirect_uri={}&response_type=code&scope=openid&state=st{extra}", enc(CB))
    };
    arm(&app, json!({ "endpoint": "authorize", "error": "access_denied", "error_description": "nope" })).await;
    let res = get(&app, &auth("&dev_claims=%7B%7D")).await;
    let loc = res.location();
    assert!(loc.as_str().starts_with(CB));
    assert_eq!(
        (query_param(&loc, "error"), query_param(&loc, "error_description"), query_param(&loc, "state")),
        (Some("access_denied".into()), Some("nope".into()), Some("st".into()))
    );
    assert!(query_param(&get(&app, &auth("&dev_claims=%7B%7D")).await.location(), "code").is_some());
    let res = get(&app, &auth("&dev_error=login_required")).await;
    assert_eq!(query_param(&res.location(), "error").as_deref(), Some("login_required"));

    // The inspector shows injected errors with their reason.
    let latest = &get(&app, "/dev/api/requests?errors=true&limit=1").await.json()["entries"][0];
    assert_eq!(
        (&latest["error"], &latest["error_description"]),
        (&json!("login_required"), &json!("injected by localoidc (dev_error)"))
    );

    // Listing, the banner, removing (also under a provider issuer) and validation.
    let armed = get(&app, "/dev/api/faults").await.json();
    assert_eq!(armed.as_array().unwrap().iter().map(|f| f["id"].as_u64().unwrap()).collect::<Vec<_>>(), [always]);
    assert!(get(&app, "/dev").await.body.contains("1 fault is armed"));
    let res =
        send(&app, Request::delete(format!("/p/okta/dev/api/faults/{always}")).body(Body::empty()).unwrap()).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = send(&app, Request::delete(format!("/dev/api/faults/{always}")).body(Body::empty()).unwrap()).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert!(!get(&app, "/dev").await.body.contains("faults-banner"));
    arm(&app, json!({ "endpoint": "token", "always": true })).await;
    let res = send(&app, Request::delete("/dev/api/faults").body(Body::empty()).unwrap()).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    assert_eq!(get(&app, "/dev/api/faults").await.json(), json!([]));
    assert_eq!(arm(&app, json!({ "endpoint": "token", "status": 200 })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(arm(&app, json!({ "endpoint": "nope" })).await.status, StatusCode::UNPROCESSABLE_ENTITY);
}
