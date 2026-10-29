# localoidc

A local OpenID Connect / OAuth 2.0 provider for offline development and testing. It's a single Rust binary with no external services.

- **Claims editor instead of a password prompt.** At login you pick a provider to emulate and set exactly what goes into the tokens.
- **Provider emulation.** It can emulate Google, GitHub, Microsoft Entra ID, Facebook, Apple, Auth0, Okta, Keycloak, GitLab, Discord and AWS Cognito. That covers their claim shapes, token formats and provider-specific endpoints such as GitHub's `/user` or Graph's `/me`.
- **Custom claims everywhere.** The login UI, the device flow, the token generator, the dev API and the CLI all accept custom claims. You can also override reserved claims (`aud`, `exp`, …) for negative tests.
- **Mint tokens without a login.** You can do it from a web page (`/dev`), a JSON API (`/dev/api/token`) or the CLI (`localoidc token`).

## Quick start

```sh
docker run --rm -p 9400:9400 -v localoidc:/data ghcr.io/samlaycock/localoidc
# or from source
cargo run --release
```

Both serve http://localhost:9400. The image is published for linux/amd64 and linux/arm64 with the tags `:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`. It runs as a non-root user and keeps its state in the `/data` volume.

Point your app at the issuer `http://localhost:9400`. Any `client_id`, `client_secret` and `redirect_uri` is accepted unless you declare clients in `localoidc.toml`.

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
| Signing key rotation (non-standard) | `POST /dev/api/rotate-keys` |
| Built-in test redirect target | `/callback` |

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

Not implemented: front-/back-channel logout, `check_session_iframe`, encrypted tokens and userinfo, unsigned ID tokens, pairwise subjects, and JARM.

### Which claims go where

By default every claim you set appears in the ID token, userinfo and (unless `access_token_identity_claims = false`) the access token, whatever scopes were requested. That's usually what you want from a local IdP.

Set `claims_by_scope = true` for spec-strict behaviour (OIDC Core 5.4):
- The ID token and userinfo only carry the standard claims the granted scopes allow: `profile`, `email`, `address` and `phone`.
- Unless `response_type=id_token`, those claims come only from userinfo, not the ID token.
- Claims requested explicitly with the `claims` request parameter (OIDC Core 5.5) are released where they were asked for.
- Non-standard claims such as `roles`, `groups` or your custom claims go only in the access token.

### Conformance

The [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) can be run locally with `./conformance/run.sh`. See [`conformance/README.md`](conformance/README.md).

## Provider emulation

There are two ways to use the presets:

1. **Pick one at login.** On the root issuer, the login page has a provider picker that switches the claim template. Your choice is remembered in the session.
2. **Use a provider issuer.** Every preset is also served as its own issuer at `/p/<preset>`, e.g. `http://localhost:9400/p/google`. It has its own discovery document and provider-specific endpoint aliases, so you can point SDKs that hard-code a provider's paths at it.

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

`localoidc presets` lists all the presets.

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

**CLI:** this uses the same signing key and database, so the server doesn't need to be running.

```sh
export TOKEN=$(localoidc token --format access -c email=me@example.com -c 'roles=["admin"]')
localoidc token --preset microsoft --audience api://orders --access-claim tenant=t1
```

### Rotating the signing key

`POST /dev/api/rotate-keys`, or the **Rotate signing key** button on `/dev`, generates a new signing key. It's useful for testing how your app handles JWKS changes.

- The keyring is shared by all issuers.
- New tokens are signed with the new key straight away.
- The previous two keys stay in the JWKS, so tokens already issued keep verifying until a third rotation retires them.

```sh
curl -s -X POST http://localhost:9400/dev/api/rotate-keys
# {"kid":"…new…","retired_kids":["…old…"],"jwks_uri":"http://localhost:9400/jwks"}
```

### Declared users

Declare named users in `localoidc.toml` so a team, its tests and CI all sign in as the same people:

```toml
[[users]]
id = "alice"                  # used by dev_user, --user and the dev API
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
- On the CLI, `localoidc token --user alice` mints tokens for a user, and `localoidc users` lists them.

### Automating browser logins (Playwright, Cypress, …)

- Add `dev_user=<id>` to an `/authorize` request to sign in as a [declared user](#declared-users) immediately.
- Add `dev_claims=<JSON or base64url JSON>` to an `/authorize` request. It signs in immediately with the preset defaults merged with those claims. `dev_preset=<id>` picks the preset.
- Alternatively, start the server with `--auto-login` so every authorization request signs in with the preset defaults. A `login_hint` sets the email or username, or picks a declared user.
- The `password` and `client_credentials` grants accept `dev_claims` and `dev_access_claims` form parameters.

## Configuration

Settings come from CLI flags, `LOCALOIDC_*` environment variables, or `localoidc.toml`. See [`localoidc.example.toml`](localoidc.example.toml) and `localoidc --help`.

- All state lives in `~/.localoidc/`: the current signing key in `signing-key.pem`, retired keys in `retired-keys/`, and everything else in the SQLite database `state.db`. That covers sessions, authorization codes, pending logins, device codes, opaque tokens, the revocation list and dynamically registered clients, so a restart loses nothing. Each kind of record has its own table (`key`, JSON `value`, `expires_at`). Expired rows are purged every minute. Delete `state.db` to start fresh. If there's no data directory, an in-memory SQLite database is used.
- In the Docker image the state lives in `/data` (`LOCALOIDC_DATA_DIR`), and the server binds `0.0.0.0` (`LOCALOIDC_HOST`). Pass flags after the image name, e.g. `docker run … ghcr.io/samlaycock/localoidc --auto-login`, and mount a config file with `-v ./localoidc.toml:/localoidc.toml -e LOCALOIDC_CONFIG=/localoidc.toml`.
- If both a browser and other containers need to reach the server, set `--issuer` (`LOCALOIDC_ISSUER`) to a URL that works for both, or use `--dynamic-issuer`.

## Development

```sh
cargo test                       # integration tests for every flow
cargo clippy --all-targets -- -D warnings
cargo fmt
docker build -t localoidc .      # the release image
```

## Releases

Releases are managed with [changesets](https://github.com/changesets/changesets). `package.json` holds the version, and `npm run version` copies it into `Cargo.toml` and `Cargo.lock`.

1. Every pull request includes a changeset (`npm run changeset`, or `npm run changeset -- --empty` for changes users won't notice). CI checks for one.
2. On `main`, the release workflow keeps a "Release <version>" pull request open. It applies the pending changesets: the version bump and `CHANGELOG.md`. CI runs on it, including a Docker build check.
3. Merging that pull request does the release:
   - builds the image natively for amd64 and arm64;
   - pushes `ghcr.io/samlaycock/localoidc:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`;
   - tags `v<version>` and creates the GitHub release from the changelog.
