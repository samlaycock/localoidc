use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;

use crate::presets;
use crate::state::AppState;
use crate::tenant::Tenant;

pub async fn openid_configuration(State(state): State<AppState>, tenant: Tenant) -> impl IntoResponse {
    let u = |p: &str| tenant.url(p);
    let mut claims: BTreeSet<&str> = [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        "sid",
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "phone_number",
        "phone_number_verified",
        "address",
        "updated_at",
    ]
    .into_iter()
    .collect();
    claims.extend(tenant.default_preset(&state.config).fields.iter().map(|f| f.name));

    Json(json!({
        "issuer": tenant.issuer,
        "authorization_endpoint": u("/authorize"),
        "token_endpoint": u("/token"),
        "userinfo_endpoint": u("/userinfo"),
        "jwks_uri": u("/jwks"),
        "registration_endpoint": u("/register"),
        "end_session_endpoint": u("/end_session"),
        "revocation_endpoint": u("/revoke"),
        "introspection_endpoint": u("/introspect"),
        "device_authorization_endpoint": u("/device_authorization"),
        "pushed_authorization_request_endpoint": u("/par"),
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "response_types_supported": [
            "code", "id_token", "id_token token", "code id_token", "code token", "code id_token token", "token", "none"
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "grant_types_supported": [
            "authorization_code", "implicit", "refresh_token", "client_credentials", "password",
            "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "userinfo_signing_alg_values_supported": ["RS256"],
        "request_object_signing_alg_values_supported": ["none", "RS256", "ES256", "HS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"
        ],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": claims,
        "claim_types_supported": ["normal"],
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": false,
        "require_pushed_authorization_requests": false,
        "claims_parameter_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "frontchannel_logout_supported": false,
        "backchannel_logout_supported": false,
        "localoidc": {
            "preset": tenant.preset.map(|p| p.id),
            "dev_token_endpoint": u("/dev/api/token"),
            "dev_rotate_keys_endpoint": u("/dev/api/rotate-keys"),
            "dev_ui": u("/dev"),
            "presets": presets::all().iter().map(|p| p.id).collect::<Vec<_>>(),
        }
    }))
}

pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.keys.jwks())
}
