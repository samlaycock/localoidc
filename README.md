# localoidc

[![CI](https://github.com/samlaycock/localoidc/actions/workflows/ci.yml/badge.svg)](https://github.com/samlaycock/localoidc/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/samlaycock/localoidc)](https://github.com/samlaycock/localoidc/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

A local OpenID Connect / OAuth 2.0 provider for offline development and testing. It's a single Rust binary (or Docker image) with no external services, and it can pretend to be Google, GitHub, Microsoft Entra ID and eight other providers.

- **A claims editor instead of a password prompt.** At login you pick a provider to emulate and set exactly what goes into the tokens.
- **Provider emulation.** It reproduces the claim shapes, token formats and provider-specific endpoints of Google, GitHub, Microsoft Entra ID, Facebook, Apple, Auth0, Okta, Keycloak, GitLab, Discord and AWS Cognito, such as GitHub's `/user` or Graph's `/me`.
- **Custom claims everywhere.** The login UI, the device flow, the token generator and the dev API all accept custom claims. You can also override reserved claims (`aud`, `exp`, …) for negative tests.
- **Mint tokens without a login.** You can do it from a web page (`/dev`) or a JSON API (`/dev/api/token`).
- **See why a request failed.** The request inspector at `/dev/requests` shows every request your app makes, what it sent and the exact reason anything was rejected.
- **Built for automated tests.** Sign in from Playwright or Cypress with a single query parameter, or turn on auto-login. [Fault injection](#injecting-faults) and a [shifted clock](#shifting-the-clock) cover the unhappy paths. [Declared users](#declared-users) give a team and its CI the same named identities.
- **Spec-compliant.** It passes the OpenID Foundation conformance suite's Basic, Implicit, Hybrid, Form Post, Config, Dynamic, RP-initiated logout and back-channel logout plans.

> [!WARNING]
> localoidc is for development and testing only. It accepts any client by default, lets anyone sign in or mint tokens as any identity, and serves unauthenticated endpoints for minting tokens and rotating keys. Never expose it to the internet or use it to protect real data.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Endpoints and protocol support](#endpoints-and-protocol-support)
- [Provider emulation](#provider-emulation)
- [Minting tokens for development and tests](#minting-tokens-for-development-and-tests)
- [Inspecting requests](#inspecting-requests)
- [Configuration](#configuration)
- [Conformance](#conformance)
- [Contributing](#contributing)
- [License](#license)

## Installation

**Docker** (linux/amd64 and linux/arm64):

```sh
docker run --rm -p 9400:9400 -v localoidc:/data ghcr.io/samlaycock/localoidc
```

The image is tagged `:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`. It runs as a non-root user and keeps its state in the `/data` volume. Pass flags after the image name, e.g. `docker run … ghcr.io/samlaycock/localoidc --auto-login`.

**From source** (needs a recent stable Rust toolchain):

```sh
cargo install --git https://github.com/samlaycock/localoidc --locked
localoidc
```

Or clone the repository and run `cargo run --release`.

## Quick start

Start localoidc with either command above. It serves http://localhost:9400.

Point your app at the issuer `http://localhost:9400`. OIDC libraries read everything else from discovery (`/.well-known/openid-configuration`). With environment-based config, that typically looks like:

```sh
OIDC_ISSUER=http://localhost:9400
OIDC_CLIENT_ID=my-app          # anything
OIDC_CLIENT_SECRET=dev-secret  # anything
```

Any `client_id`, `client_secret` and `redirect_uri` is accepted unless you [declare clients](#configuration). When your app redirects to the login page, pick a provider, adjust the claims and sign in.

To get a token without a browser:

```sh
curl -s 'http://localhost:9400/dev/api/token?email=me@example.com' | jq .
```

To make localoidc look like a specific provider, use that provider's issuer, for example `http://localhost:9400/p/google`. See [Provider emulation](#provider-emulation).

## Endpoints and protocol support

| What | Where |
|---|---|
| Discovery | `/.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`) |
| JWKS | `/jwks`, `/.well-known/jwks.json` |
| Authorization | `/authorize` (GET/POST) |
| Token | `/token` |
| UserInfo | `/userinfo` |
| Introspection (RFC 7662) | `/introspect` |
| Revocation (RFC 7009) | `/revoke` |
| RP-initiated logout | `/end_session` |
| Device authorization (RFC 8628) | `/device_authorization`, verification page `/device` |
| Pushed authorization requests (RFC 9126) | `/par` |
| Dynamic client registration (RFC 7591) | `/register` |
| Token generator UI (non-standard) | `/dev` |
| Token API (non-standard) | `/dev/api/token` |
| Provider presets (non-standard) | `/dev/api/presets` |
| Declared users (non-standard) | `/dev/api/users` |
| Signing key rotation (non-standard) | `POST /dev/api/rotate-keys` |
| Clock offset (non-standard) | `/dev/api/clock` (GET/POST) |
| Sessions (non-standard) | `/dev/api/sessions` (GET), `/dev/api/sessions/{sid}` (DELETE) |
| Fault injection (non-standard) | `/dev/api/faults` (GET/POST/DELETE), `/dev/api/faults/{id}` (DELETE) |
| Request inspector (non-standard) | `/dev/requests`, `/dev/api/requests` (GET/DELETE) |
| Built-in test redirect target | `/callback` |
| Health check | `/health` |

### Supported protocol features

- Response types: `code`, `id_token`, `id_token token`, `code id_token`, `code token`, `code id_token token`, `token` and `none`.
- Response modes: `query`, `fragment` and `form_post`. The authorization response includes `iss` (RFC 9207).
- PKCE with `S256` and `plain`.
- `nonce`, `state`, `prompt` (`none`, `login`, `consent`, `select_account`), `max_age`, `login_hint`, `acr_values`, and `resource`/`audience`.
- ID tokens include `at_hash`, `c_hash`, `auth_time`, `sid` and `azp`.
- Request objects, passed by value (`request=`) or by reference (`request_uri=`, fetched over HTTP(S)). RS256 request objects are verified against the client's registered `jwks` or `jwks_uri`. Other algorithms, and clients without registered keys, are accepted unverified.
- Grants: `authorization_code`, `refresh_token` (including scope down-scoping), `client_credentials`, `password`, `device_code` and token exchange (RFC 8693).
- Client authentication: `client_secret_basic`, `client_secret_post` and `none`. `private_key_jwt` and `client_secret_jwt` assertions are accepted without verification.
- Signing: ID and access tokens are signed with RS256. Access tokens follow RFC 9068 (`typ: at+jwt`). Refresh tokens are signed JWTs too, so they keep working after a restart.
- Sessions use a cookie, so `prompt=none` silent auth works. A "Continue as…" shortcut appears on the next login. Signing in again during a session keeps the original `auth_time`, unless `prompt=login` or `max_age` requires a fresh login.
- Userinfo is returned as a signed JWT for clients registered with `userinfo_signed_response_alg=RS256`.
- Reusing an authorization code revokes the tokens issued from it.
- RP-initiated logout: registered clients must send a valid `id_token_hint` with a registered `post_logout_redirect_uri`, otherwise an error page is shown. Unregistered clients can redirect as long as they're identified by `client_id` or a hint.
- [Back-channel logout](#back-channel-logout): when a session ends, clients that used it get a signed logout token.

**Not implemented:** front-channel logout, `check_session_iframe`, encrypted tokens and userinfo, unsigned ID tokens, pairwise subjects, JARM, and signing algorithms other than RS256.

### Which claims go where

By default every claim you set appears in the ID token, userinfo and (unless `access_token_identity_claims = false`) the access token, whatever scopes were requested. That's usually what you want from a local IdP.

Set `claims_by_scope = true` for spec-strict behaviour (OIDC Core 5.4):
- The ID token and userinfo only carry the standard claims the granted scopes allow: `profile`, `email`, `address` and `phone`.
- Unless `response_type=id_token`, those claims come only from userinfo, not the ID token.
- Claims requested explicitly with the `claims` request parameter (OIDC Core 5.5) are released where they were asked for.
- Non-standard claims such as `roles`, `groups` or your custom claims go only in the access token.

### Back-channel logout

localoidc implements [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html). A client opts in by registering a `backchannel_logout_uri`, in `localoidc.toml` or through dynamic registration:

```toml
[[clients]]
client_id = "my-web-app"
redirect_uris = ["http://localhost:3000/api/auth/callback"]
backchannel_logout_uri = "http://localhost:3000/api/auth/backchannel-logout"
```

- localoidc remembers which clients received tokens during each browser session.
- When the session ends, each of those clients that has a `backchannel_logout_uri` receives a POST with `logout_token=<JWT>`. That includes the client that started the logout. The logout token is signed like an ID token (`typ: logout+jwt`). It carries `iss`, `aud`, `iat`, `exp` (two minutes), `jti`, `sub`, `sid` and the back-channel logout `events` claim.
- Sessions end through RP-initiated logout (`/end_session`, using the session cookie or the `sid` in `id_token_hint`) or through `DELETE /dev/api/sessions/{sid}`. The latter is the same as the user logging out somewhere else. `GET /dev/api/sessions` lists active sessions, and the `/dev` page has the same list with an **End session** button.
- Deliveries happen before the logout response, with a 5 second timeout per client. A client that fails or is unreachable doesn't block the logout. Deliveries show up in the [request inspector](#inspecting-requests) as outgoing requests, with their status.
- Refresh tokens issued during the session stop working when it ends, unless they were issued with `offline_access`.
- Clients that aren't declared (accepted in the default lenient mode) have nowhere to receive a logout token, so they aren't notified.

## Provider emulation
## Provider emulation

There are two ways to use the presets:

1. **Pick one at login.** On the root issuer, the login page has a provider picker that switches the claim template. Your choice is remembered in the session.
2. **Use a provider issuer.** Every preset is also served as its own issuer at `/p/<preset>`, e.g. `http://localhost:9400/p/google`. It has its own discovery document and provider-specific endpoint aliases, so you can point SDKs that hard-code a provider's paths at it.

To make a preset the default on the root issuer, use `--default-preset <id>`.

| Preset | Notes | Extra endpoints under `/p/<preset>` |
|---|---|---|
| `generic` | Standard OIDC claims, plus `groups` and `roles` | – |
| `google` | 21-digit `sub`, `hd` for Workspace | `/o/oauth2/v2/auth`, `/oauth2/v3/userinfo`, `/tokeninfo` |
| `github` | OAuth2 with opaque `gho_` tokens. `response_type` is optional. The token endpoint returns form-encoded responses unless you send `Accept: application/json` | `/login/oauth/authorize`, `/login/oauth/access_token`, `/user`, `/user/emails` |
| `microsoft` | `oid`, `tid`, `ver: 2.0`, `scp` | `/oauth2/v2.0/authorize`, `/oauth2/v2.0/token`, `/v1.0/me` (Graph shape) |
| `facebook` | Opaque `EAAB…` tokens | `/{version}/dialog/oauth`, `/{version}/oauth/access_token`, `/me?fields=…` |
| `apple` | Private relay email, `real_user_status` | `/auth/authorize`, `/auth/token`, `/auth/keys` |
| `auth0` | Namespaced custom claims | `/oauth/token` |
| `okta` | `cid`, `uid`, `scp`, `ver` | `/v1/authorize`, `/v1/token`, `/v1/userinfo`, `/v1/keys`, … |
| `keycloak` | `realm_access`, `resource_access`, `typ` | `/protocol/openid-connect/{auth,token,userinfo,certs,logout}` |
| `gitlab` | `groups`, `groups_direct` | `/oauth/authorize`, `/oauth/token`, `/api/v4/user` |
| `discord` | Snowflake ids | `/oauth2/authorize`, `/api/oauth2/token`, `/api/users/@me` |
| `cognito` | `cognito:username`, `cognito:groups`, `token_use` | `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userInfo` |

`GET /dev/api/presets` lists all the presets.

## Minting tokens for development and tests

**Web page:** open `http://localhost:9400/dev` (or `/p/<preset>/dev`). Set the claims and generate tokens. The page also shows copyable `export` lines, curl snippets for userinfo and refresh, and the equivalent API call.

**JSON API:**

```sh
# Quick GET: unknown query params become claims (values are parsed as JSON when possible).
curl -s 'http://localhost:9400/dev/api/token?email=me@example.com&roles=["admin"]'

# Full POST. `claims` are merged over the preset defaults; a null value removes a claim.
curl -s -X POST http://localhost:9400/dev/api/token -H 'content-type: application/json' -d '{
  "preset": "google",
  "client_id": "my-app",
  "audience": "api://orders",
  "scope": "openid email",
  "claims": { "email": "me@acme.dev", "hd": "acme.dev", "picture": null },
  "access_token_claims": { "permissions": ["orders:write"] },
  "expires_in": 300,
  "refresh_token": true
}'
```

The response is a normal token response plus `id_token_claims`, `access_token_claims` and `issuer`. Other options are `defaults: false` (start from an empty claim set), `id_token: false` and `nonce`.

### Declared users

Declare named users in `localoidc.toml` so a team, its tests and CI all sign in as the same people:

```toml
[[users]]
id = "alice"                  # used by dev_user and the dev API
label = "Alice (admin)"       # optional, shown on the login page
preset = "google"             # optional, otherwise the issuer's default preset
claims = { email = "alice@acme.dev", roles = ["admin"] }
access_claims = { permissions = ["orders:write"] }  # optional, access token only
# defaults = false            # don't merge over the preset's default claims
# password = "s3cret"         # required by the password grant when set
```

- Users appear at the top of the login, device and `/dev` pages for one-click sign-in.
- Each user gets a stable `sub` shaped like the provider's (for example 21 digits for Google) unless you set one. For presets that derive `sub` from another claim, such as GitHub's `id`, that claim is generated instead.
- `/authorize?…&dev_user=alice` signs in as Alice straight away. `dev_claims` are merged on top.
- With `--auto-login`, a `login_hint` matching a user's `id` or `email` signs in as that user.
- The `password` grant resolves `username` the same way.
- `POST /dev/api/token` accepts `"user": "alice"` (or `?user=alice` on GET), with `claims` and `access_token_claims` merged on top. `GET /dev/api/users` lists the users as the issuer would issue them.

### Automating browser logins (Playwright, Cypress, …)

- Add `dev_user=<id>` to an `/authorize` request to sign in as a [declared user](#declared-users) immediately.
- Add `dev_claims=<JSON or base64url JSON>` to an `/authorize` request. It signs in immediately with the preset defaults merged with those claims. `dev_preset=<id>` picks the preset.
- Alternatively, start the server with `--auto-login` so every authorization request signs in with the preset defaults. A `login_hint` sets the email or username, or picks a declared user.
- The `password` and `client_credentials` grants accept `dev_claims` and `dev_access_claims` form parameters.

### Rotating the signing key

`POST /dev/api/rotate-keys`, or the **Rotate signing key** button on `/dev`, generates a new signing key. It's useful for testing how your app handles JWKS changes.

- The keyring is shared by all issuers.
- New tokens are signed with the new key straight away.
- The previous two keys stay in the JWKS, so tokens already issued keep verifying until a third rotation retires them.

```sh
curl -s -X POST http://localhost:9400/dev/api/rotate-keys
# {"kid":"…new…","retired_kids":["…old…"],"jwks_uri":"http://localhost:9400/jwks"}
```

### Shifting the clock

localoidc can run its clock ahead of (or behind) real time. Use this to test what happens when things expire, without waiting days for it:

- Authorization codes, sessions, refresh tokens and device codes expire by the shifted clock. Move it forward 31 days and refresh tokens return `invalid_grant`, `prompt=none` returns `login_required`, and `/userinfo` rejects old access tokens.
- `max_age` is checked against it, so moving forward forces a fresh login.
- New tokens get `iat`, `exp` and `auth_time` from the shifted clock. This simulates an identity provider whose clock is off, which tests your app's clock-skew leeway.

Your app's clock isn't affected, so a token your app already holds still expires on real time. Use short lifetimes (`expires_in`) to test that side.

```sh
curl -s -X POST http://localhost:9400/dev/api/clock -H 'content-type: application/json' -d '{"advance": "31d"}'
# {"now":…,"offset":2678400,"offset_text":"+31d","real_now":…}
curl -s -X POST http://localhost:9400/dev/api/clock -H 'content-type: application/json' -d '{"reset": true}'
```

- `POST /dev/api/clock` takes exactly one of `offset` (set it), `advance` (move it; negative moves back) or `reset: true`. Durations are seconds or text such as `90s`, `15m`, `2h`, `31d` or `1d12h`. `GET /dev/api/clock` shows the current state.
- The `/dev` page has the same controls. While the clock is shifted, every page shows a warning banner.
- `--clock-offset <duration>` (`LOCALOIDC_CLOCK_OFFSET`) sets an offset at startup.
- The offset isn't saved, so a restart always goes back to real time. Records that expire while the clock is ahead are purged within a minute. After that, moving the clock back doesn't restore them.

### Injecting faults

Make the next requests to an endpoint fail on purpose, or respond slowly, to test how your app handles an identity provider that misbehaves. This works on requests your app makes itself, so the app doesn't need to change anything.

```sh
# The app's next refresh fails with invalid_grant
curl -s -X POST http://localhost:9400/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "token", "grant_type": "refresh_token", "error": "invalid_grant"}'

# The JWKS endpoint answers 503 until the fault is removed
curl -s -X POST http://localhost:9400/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "jwks", "error": "temporarily_unavailable", "always": true}'

# The next login is denied
curl -s -X POST http://localhost:9400/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "authorize", "error": "access_denied"}'

curl -s -X DELETE http://localhost:9400/dev/api/faults   # remove them all
```

- `endpoint` is one of `authorize`, `token`, `userinfo`, `jwks`, `discovery`, `introspect`, `revoke`, `device_authorization`, `par`, `register` or `end_session`. Provider-specific paths count too, e.g. GitHub's `/login/oauth/access_token` is `token` and Keycloak's `.../certs` is `jwks`.
- Narrow it with `issuer` (`root` or a preset id), `client_id` and `grant_type`.
- `error` is the OAuth error to return (default `server_error`) with an optional `error_description`. `status` sets the HTTP status; by default it follows the error (401 for `invalid_client` and `invalid_token`, 500 for `server_error`, 503 for `temporarily_unavailable`, otherwise 400).
- `delay_ms` (up to 30000) waits before answering. On its own, without an `error`, it just makes the request slow.
- A fault affects the next matching request, or the next `count` of them, or every one with `always: true` until it's removed.
- Authorization errors are redirected back to the client with `state` and the right response mode, like a real one. For a one-off, add `dev_error=<code>` (and optionally `dev_error_description`) to an `/authorize` request.
- `GET /dev/api/faults` lists the armed faults and `DELETE /dev/api/faults/{id}` removes one. The `/dev` page has the same controls, and every page shows a warning banner while faults are armed. Injected responses carry an `x-localoidc-fault` header, and the [request inspector](#inspecting-requests) shows them with their description.
- localoidc's own `/dev` tools are never affected. Faults live in memory, so a restart clears them.

## Inspecting requests

Open `http://localhost:9400/dev/requests` (linked as **Requests** in the top bar) to see the last 500 requests to every issuer, newest first. New requests appear as they arrive.

- Each row shows the endpoint, the client and the outcome: `redirect with code`, `tokens: access_token, id_token`, `page: Sign in`, or the error code. Failures are marked in red.
- Click a row to see its parameters, the `Authorization` header, where a redirect went and, for failures, why. For example: `invalid_grant — redirect_uri does not match the authorization request`. That includes errors sent back to your app's redirect URI and GitHub-style errors returned with HTTP 200.
- Filter by `client_id` or to errors only. Discovery, JWKS and localoidc's own `/dev` tools are hidden unless you ask for them.
- Secrets (`client_secret`, `password`, `client_assertion`, Basic credentials) are masked. Tokens and codes are cut to their first 8 characters, which is enough to match them across requests.
- The list is kept in memory, so a restart clears it.

Tests can use the same data to check what an app actually sent:

```sh
curl -s -X DELETE http://localhost:9400/dev/api/requests      # start from a clean slate
# ... run the login flow ...
curl -s 'http://localhost:9400/dev/api/requests?client_id=my-app&errors=true' | jq '.entries[] | {endpoint, error, error_description}'
```

`GET /dev/api/requests` returns `{"entries": [...], "latest_id": …, "capacity": 500}` and accepts `client_id`, `errors=true`, `limit` and `after=<id>` (only newer entries). Clearing doesn't reset ids, so polling with `after` never misses a request.

## Configuration

Settings come from CLI flags, `LOCALOIDC_*` environment variables, or a `localoidc.toml` in the working directory (or `--config <path>`). Flags and environment variables win over the file. See [`localoidc.example.toml`](localoidc.example.toml) for every setting and `localoidc --help` for the flags.

Declared clients get their secret, redirect URIs and post-logout redirect URIs enforced. Other clients are accepted with anything, unless `strict_clients = true`:

```toml
[[clients]]
client_id = "my-web-app"
client_secret = "dev-secret"
redirect_uris = ["http://localhost:3000/api/auth/callback"]
post_logout_redirect_uris = ["http://localhost:3000/"]
```

Named identities go in `[[users]]`. See [Declared users](#declared-users).

### State

- All state lives in `~/.localoidc/` (`--data-dir`): the current signing key in `signing-key.pem`, retired keys in `retired-keys/`, and everything else in the SQLite database `state.db`.
- The database holds sessions, authorization codes, pending logins, device codes, opaque tokens, the revocation list and dynamically registered clients, so a restart loses nothing. Expired rows are purged every minute.
- Delete `state.db` to start fresh. `--ephemeral-keys` generates a new signing key on every start. Without a data directory, an in-memory database is used.

### Docker

- In the image the state lives in `/data` (`LOCALOIDC_DATA_DIR`), and the server binds `0.0.0.0` (`LOCALOIDC_HOST`).
- Mount a config file with `-v ./localoidc.toml:/localoidc.toml -e LOCALOIDC_CONFIG=/localoidc.toml`.
- The issuer must be a URL your app can reach and that matches what the browser sees. If both a browser and other containers need to reach the server, set `--issuer` (`LOCALOIDC_ISSUER`) to a URL that works for both, or use `--dynamic-issuer` to derive the issuer from each request's `Host` header.

## Conformance

localoidc passes the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)'s Basic, Implicit, Hybrid, Form Post, Config, Dynamic, RP-initiated logout and back-channel logout plans. The few expected skips are features that aren't implemented, such as unsigned ID tokens and pairwise subjects. To run the suite locally, use `./conformance/run.sh`. See [`conformance/README.md`](conformance/README.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and release.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
