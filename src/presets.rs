//! Provider presets: claim shapes and quirks of common identity providers.

use std::sync::OnceLock;

use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub label: &'static str,
    /// `string` | `bool` | `number` | `json`
    pub kind: &'static str,
    pub default: Value,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub help: &'static str,
}

impl Field {
    fn help(mut self, help: &'static str) -> Self {
        self.help = help;
        self
    }
}

fn s(name: &'static str, label: &'static str, default: &str) -> Field {
    Field { name, label, kind: "string", default: json!(default), help: "" }
}
fn b(name: &'static str, label: &'static str, default: bool) -> Field {
    Field { name, label, kind: "bool", default: json!(default), help: "" }
}
fn n(name: &'static str, label: &'static str, default: i64) -> Field {
    Field { name, label, kind: "number", default: json!(default), help: "" }
}
fn j(name: &'static str, label: &'static str, default: Value) -> Field {
    Field { name, label, kind: "json", default, help: "" }
}

#[derive(Debug, Clone, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    /// `oidc` or `oauth2` (OAuth2-only providers such as GitHub have no ID token natively).
    pub protocol: &'static str,
    pub description: &'static str,
    pub color: &'static str,
    pub fields: Vec<Field>,
    /// Claim used to derive `sub` when the preset has no explicit `sub` field.
    pub sub_from: Option<&'static str>,
    /// When set, access tokens are opaque strings with this prefix instead of JWTs.
    pub access_token_prefix: Option<&'static str>,
    pub id_token_extra: Value,
    pub access_token_extra: Value,
    pub default_scope: &'static str,
    /// Provider-specific emulated endpoints, relative to the preset's issuer: (method + description, path).
    pub endpoints: Vec<(&'static str, &'static str)>,
}

impl Preset {
    pub fn default_claims(&self) -> Map<String, Value> {
        let mut claims = Map::new();
        for field in &self.fields {
            match &field.default {
                Value::String(s) if s.is_empty() => {}
                v => {
                    claims.insert(field.name.to_string(), v.clone());
                }
            }
        }
        self.ensure_sub(&mut claims);
        claims
    }

    pub fn ensure_sub(&self, claims: &mut Map<String, Value>) {
        let has_sub = claims.get("sub").is_some_and(|v| !v.is_null() && v != "");
        if has_sub {
            if let Some(Value::Number(n)) = claims.get("sub") {
                let s = n.to_string();
                claims.insert("sub".into(), Value::String(s));
            }
            return;
        }
        let derived = self
            .sub_from
            .and_then(|f| claims.get(f))
            .filter(|v| !v.is_null())
            .map(crate::util::value_to_string)
            .unwrap_or_else(|| format!("user-{}", crate::util::random_string(12).to_lowercase()));
        claims.insert("sub".into(), Value::String(derived));
    }

    /// Apply a `login_hint` to a claim set: emails go to `email`, anything else to a username-ish claim.
    pub fn apply_login_hint(&self, claims: &mut Map<String, Value>, hint: &str) {
        if hint.is_empty() {
            return;
        }
        if hint.contains('@') {
            claims.insert("email".into(), json!(hint));
            if self.id == "microsoft" || self.id == "okta" {
                claims.insert("preferred_username".into(), json!(hint));
            }
        } else {
            let key = ["preferred_username", "login", "username", "nickname", "cognito:username"]
                .into_iter()
                .find(|k| self.fields.iter().any(|f| f.name == *k))
                .unwrap_or("preferred_username");
            claims.insert(key.into(), json!(hint));
        }
    }
}

pub fn all() -> &'static [Preset] {
    static PRESETS: OnceLock<Vec<Preset>> = OnceLock::new();
    PRESETS.get_or_init(build)
}

pub fn get(id: &str) -> Option<&'static Preset> {
    all().iter().find(|p| p.id == id)
}

pub fn get_or_generic(id: &str) -> &'static Preset {
    get(id).unwrap_or_else(generic)
}

pub fn generic() -> &'static Preset {
    &all()[0]
}

const NAME: &str = "Jane Developer";

fn build() -> Vec<Preset> {
    vec![
        Preset {
            id: "generic",
            name: "Generic OIDC",
            protocol: "oidc",
            description: "Every standard OpenID Connect claim, plus a few common extras (groups, roles).",
            color: "#6366f1",
            fields: vec![
                s("sub", "Subject (sub)", "user-1234"),
                s("name", "Full name", NAME),
                s("given_name", "Given name", "Jane"),
                s("middle_name", "Middle name", "Ada"),
                s("family_name", "Family name", "Developer"),
                s("nickname", "Nickname", "JD"),
                s("preferred_username", "Username", "jane"),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                s("picture", "Picture URL", "https://www.gravatar.com/avatar/?d=identicon"),
                s("profile", "Profile URL", "https://example.com/jane"),
                s("website", "Website", "https://jane.example.com"),
                s("gender", "Gender", "unspecified"),
                s("birthdate", "Birthdate", "1990-01-01"),
                s("zoneinfo", "Time zone", "Europe/London"),
                s("locale", "Locale", "en-US"),
                n("updated_at", "Updated at (epoch seconds)", 1767225600),
                s("phone_number", "Phone number", "+44 20 7946 0000"),
                b("phone_number_verified", "Phone verified", false),
                j(
                    "address",
                    "Address",
                    json!({ "street_address": "1 Example Street", "locality": "London", "postal_code": "EC1A 1AA", "country": "GB" }),
                ),
                j("groups", "Groups", json!(["developers"])),
                j("roles", "Roles", json!(["user"])),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "openid profile email offline_access",
            endpoints: vec![],
        },
        Preset {
            id: "google",
            name: "Google",
            protocol: "oidc",
            description: "Google Identity / Sign in with Google. Set `hd` to emulate a Google Workspace account.",
            color: "#4285f4",
            fields: vec![
                s("sub", "Subject (sub)", "109876543210987654321").help("Google subjects are 21-digit numeric strings"),
                s("email", "Email", "jane.developer@gmail.com"),
                b("email_verified", "Email verified", true),
                s("name", "Full name", NAME),
                s("given_name", "Given name", "Jane"),
                s("family_name", "Family name", "Developer"),
                s("picture", "Picture URL", "https://lh3.googleusercontent.com/a/default-user=s96-c"),
                s("locale", "Locale", "en"),
                s("hd", "Hosted domain (hd)", "").help("Workspace domain; leave empty for consumer accounts"),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "openid profile email",
            endpoints: vec![
                ("GET authorize", "/o/oauth2/v2/auth"),
                ("GET userinfo", "/oauth2/v3/userinfo"),
                ("GET tokeninfo", "/tokeninfo"),
            ],
        },
        Preset {
            id: "github",
            name: "GitHub",
            protocol: "oauth2",
            description: "GitHub OAuth Apps. Opaque `gho_` access tokens and a REST-style `/user` endpoint.",
            color: "#24292f",
            fields: vec![
                n("id", "User ID", 1234567),
                s("login", "Login", "janedev"),
                s("name", "Name", NAME),
                s("email", "Public email", "jane@example.com"),
                s("avatar_url", "Avatar URL", "https://avatars.githubusercontent.com/u/1234567?v=4"),
                s("html_url", "Profile URL", "https://github.com/janedev"),
                s("company", "Company", "@acme"),
                s("location", "Location", "London"),
                s("bio", "Bio", ""),
                s("node_id", "Node ID", "MDQ6VXNlcjEyMzQ1Njc="),
                s("type", "Type", "User"),
                b("site_admin", "Site admin", false),
            ],
            sub_from: Some("id"),
            access_token_prefix: Some("gho_"),
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "read:user user:email",
            endpoints: vec![
                ("GET authorize", "/login/oauth/authorize"),
                ("POST token", "/login/oauth/access_token"),
                ("GET user", "/user"),
                ("GET user emails", "/user/emails"),
            ],
        },
        Preset {
            id: "microsoft",
            name: "Microsoft Entra ID",
            protocol: "oidc",
            description: "Microsoft identity platform v2.0 (Azure AD / Entra ID) with tenant and object IDs.",
            color: "#0078d4",
            fields: vec![
                s("sub", "Subject (pairwise sub)", "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"),
                s("oid", "Object ID (oid)", "00000000-0000-0000-66f3-3332eca7ea81"),
                s("tid", "Tenant ID (tid)", "9188040d-6c67-4c5b-b112-36a304b66dad"),
                s("name", "Name", NAME),
                s("preferred_username", "Preferred username", "jane@contoso.onmicrosoft.com"),
                s("email", "Email", "jane@contoso.com"),
                j("roles", "App roles", json!([])),
                j("groups", "Group object IDs", json!([])),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({ "ver": "2.0" }),
            access_token_extra: json!({ "ver": "2.0" }),
            default_scope: "openid profile email offline_access User.Read",
            endpoints: vec![
                ("GET authorize", "/oauth2/v2.0/authorize"),
                ("POST token", "/oauth2/v2.0/token"),
                ("GET Graph /me", "/v1.0/me"),
            ],
        },
        Preset {
            id: "facebook",
            name: "Facebook",
            protocol: "oauth2",
            description: "Facebook Login with Graph API `/me` (supports the `fields` query parameter).",
            color: "#1877f2",
            fields: vec![
                s("id", "User ID", "10223344556677889"),
                s("name", "Name", NAME),
                s("first_name", "First name", "Jane"),
                s("last_name", "Last name", "Developer"),
                s("email", "Email", "jane@example.com"),
                j(
                    "picture",
                    "Picture",
                    json!({ "data": { "height": 50, "width": 50, "is_silhouette": false, "url": "https://platform-lookaside.fbsbx.com/platform/profilepic/" } }),
                ),
            ],
            sub_from: Some("id"),
            access_token_prefix: Some("EAAB"),
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "public_profile email",
            endpoints: vec![
                ("GET authorize", "/v19.0/dialog/oauth"),
                ("GET token", "/v19.0/oauth/access_token"),
                ("GET me", "/me?fields=id,name,email,picture"),
            ],
        },
        Preset {
            id: "apple",
            name: "Sign in with Apple",
            protocol: "oidc",
            description: "Apple ID tokens, including private relay emails and real-user status.",
            color: "#111111",
            fields: vec![
                s("sub", "Subject (sub)", "001234.0a1b2c3d4e5f60718293a4b5c6d7e8f9.1234"),
                s("email", "Email", "abc123xyz@privaterelay.appleid.com"),
                b("email_verified", "Email verified", true),
                b("is_private_email", "Private relay email", true),
                n("real_user_status", "Real user status", 2).help("0 unsupported, 1 unknown, 2 likely real"),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({ "nonce_supported": true }),
            access_token_extra: json!({}),
            default_scope: "openid name email",
            endpoints: vec![("GET authorize", "/auth/authorize"), ("POST token", "/auth/token"), ("GET keys", "/auth/keys")],
        },
        Preset {
            id: "auth0",
            name: "Auth0",
            protocol: "oidc",
            description: "Auth0 tenants. Custom claims must be namespaced URLs, e.g. https://example.com/roles.",
            color: "#eb5424",
            fields: vec![
                s("sub", "Subject (sub)", "auth0|64f1c0ffee0000000000abcd"),
                s("nickname", "Nickname", "jane"),
                s("name", "Name", NAME),
                s("picture", "Picture URL", "https://s.gravatar.com/avatar/00000000000000000000000000000000?s=480&r=pg&d=identicon"),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                s("updated_at", "Updated at", "2026-01-01T00:00:00.000Z"),
                j("https://example.com/roles", "Namespaced roles", json!(["admin"])),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "openid profile email offline_access",
            endpoints: vec![("POST token", "/oauth/token")],
        },
        Preset {
            id: "okta",
            name: "Okta",
            protocol: "oidc",
            description: "Okta org / custom authorization servers.",
            color: "#007dc1",
            fields: vec![
                s("sub", "Subject (sub)", "00u1a2b3c4d5e6f7g8h9"),
                s("name", "Name", NAME),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                s("preferred_username", "Preferred username", "jane@example.com"),
                j("groups", "Groups", json!(["Everyone"])),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({ "ver": 1, "idp": "00o1a2b3c4d5e6f7g8h9", "amr": ["pwd"] }),
            access_token_extra: json!({ "ver": 1 }),
            default_scope: "openid profile email offline_access",
            endpoints: vec![
                ("GET authorize", "/v1/authorize"),
                ("POST token", "/v1/token"),
                ("GET userinfo", "/v1/userinfo"),
                ("GET keys", "/v1/keys"),
            ],
        },
        Preset {
            id: "keycloak",
            name: "Keycloak",
            protocol: "oidc",
            description: "Keycloak realms with realm and client roles.",
            color: "#4d4d4d",
            fields: vec![
                s("sub", "Subject (sub)", "f3b4c2a1-1234-4cde-9abc-0123456789ab"),
                s("preferred_username", "Username", "jane"),
                s("name", "Name", NAME),
                s("given_name", "Given name", "Jane"),
                s("family_name", "Family name", "Developer"),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                j("realm_access", "Realm roles", json!({ "roles": ["default-roles-master", "offline_access", "uma_authorization"] })),
                j("resource_access", "Client roles", json!({ "account": { "roles": ["manage-account", "view-profile"] } })),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({ "typ": "ID" }),
            access_token_extra: json!({ "typ": "Bearer" }),
            default_scope: "openid profile email",
            endpoints: vec![
                ("GET authorize", "/protocol/openid-connect/auth"),
                ("POST token", "/protocol/openid-connect/token"),
                ("GET userinfo", "/protocol/openid-connect/userinfo"),
                ("GET certs", "/protocol/openid-connect/certs"),
            ],
        },
        Preset {
            id: "gitlab",
            name: "GitLab",
            protocol: "oidc",
            description: "GitLab OIDC plus the REST `/api/v4/user` endpoint.",
            color: "#fc6d26",
            fields: vec![
                s("sub", "Subject (sub)", "1234567"),
                s("name", "Name", NAME),
                s("nickname", "Nickname", "janedev"),
                s("preferred_username", "Username", "janedev"),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                s("profile", "Profile URL", "https://gitlab.com/janedev"),
                s("picture", "Avatar URL", "https://gitlab.com/uploads/-/system/user/avatar/1234567/avatar.png"),
                j("groups", "Groups", json!(["acme"])),
                j("groups_direct", "Direct groups", json!(["acme"])),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "openid profile email read_user",
            endpoints: vec![
                ("GET authorize", "/oauth/authorize"),
                ("POST token", "/oauth/token"),
                ("GET userinfo", "/oauth/userinfo"),
                ("GET user", "/api/v4/user"),
            ],
        },
        Preset {
            id: "discord",
            name: "Discord",
            protocol: "oauth2",
            description: "Discord OAuth2 with the `/api/users/@me` endpoint.",
            color: "#5865f2",
            fields: vec![
                s("id", "User ID (snowflake)", "80351110224678912"),
                s("username", "Username", "janedev"),
                s("global_name", "Display name", "Jane"),
                s("discriminator", "Discriminator", "0"),
                s("avatar", "Avatar hash", ""),
                s("email", "Email", "jane@example.com"),
                b("verified", "Email verified", true),
                s("locale", "Locale", "en-US"),
                b("mfa_enabled", "MFA enabled", false),
            ],
            sub_from: Some("id"),
            access_token_prefix: None,
            id_token_extra: json!({}),
            access_token_extra: json!({}),
            default_scope: "identify email",
            endpoints: vec![
                ("GET authorize", "/oauth2/authorize"),
                ("POST token", "/api/oauth2/token"),
                ("GET user", "/api/users/@me"),
            ],
        },
        Preset {
            id: "cognito",
            name: "AWS Cognito",
            protocol: "oidc",
            description: "Amazon Cognito user pools with groups and token_use claims.",
            color: "#ff9900",
            fields: vec![
                s("sub", "Subject (sub)", "a1b2c3d4-5678-90ab-cdef-111122223333"),
                s("cognito:username", "Username", "jane"),
                j("cognito:groups", "Groups", json!(["admins"])),
                s("email", "Email", "jane@example.com"),
                b("email_verified", "Email verified", true),
                s("name", "Name", NAME),
            ],
            sub_from: None,
            access_token_prefix: None,
            id_token_extra: json!({ "token_use": "id" }),
            access_token_extra: json!({ "token_use": "access" }),
            default_scope: "openid profile email",
            endpoints: vec![
                ("GET authorize", "/oauth2/authorize"),
                ("POST token", "/oauth2/token"),
                ("GET userinfo", "/oauth2/userInfo"),
            ],
        },
    ]
}
