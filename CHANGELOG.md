# localoidc

## 0.2.0

### Minor Changes

- [#11](https://github.com/samlaycock/localoidc/pull/11) [`4d2beb7`](https://github.com/samlaycock/localoidc/commit/4d2beb7007f29dd367af2f681c1ee5e6d773cca4) Thanks [@samlaycock](https://github.com/samlaycock)! - Add OIDC Back-Channel Logout 1.0. Clients can register a `backchannel_logout_uri` (in `localoidc.toml` or through dynamic registration). When a browser session ends, through `/end_session` or the new `DELETE /dev/api/sessions/{sid}`, each client that used it gets a signed logout token. Deliveries appear in the request inspector. `GET /dev/api/sessions` and a Sessions card on `/dev` list active sessions.
  
  Refresh tokens issued during a session now stop working when the session ends, unless they were issued with `offline_access`. This also applies to plain RP-initiated logout.

- [#7](https://github.com/samlaycock/localoidc/pull/7) [`b8eaa87`](https://github.com/samlaycock/localoidc/commit/b8eaa877435d59545024c5509113792ff1a9ba13) Thanks [@samlaycock](https://github.com/samlaycock)! - Add a clock offset for testing expiry and clock skew. `POST /dev/api/clock` (with `offset`, `advance` or `reset`), the controls on `/dev`, or `--clock-offset` / `LOCALOIDC_CLOCK_OFFSET` run the server clock ahead of or behind real time. That shifts token timestamps and every expiry check: codes, sessions, refresh tokens, device codes and `max_age`. A banner shows on every page while the clock is shifted.

- [#3](https://github.com/samlaycock/localoidc/pull/3) [`c52ec01`](https://github.com/samlaycock/localoidc/commit/c52ec013ffac90b86dad3a2b6738b62c0ff88c77) Thanks [@samlaycock](https://github.com/samlaycock)! - Add declared users: `[[users]]` in `localoidc.toml` defines named identities that show up on the login page and can be used with `dev_user=<id>` on `/authorize`, `"user"` in the dev token API, the `password` grant and `--auto-login` login hints. Each user gets a stable, provider-shaped `sub`. `GET /dev/api/users` lists them.

- [#10](https://github.com/samlaycock/localoidc/pull/10) [`4624106`](https://github.com/samlaycock/localoidc/commit/4624106ba4be71d3e92b213542c36efb28cad812) Thanks [@samlaycock](https://github.com/samlaycock)! - Add fault injection. `POST /dev/api/faults` (or the Faults card on `/dev`) makes the next matching requests to an endpoint fail with a chosen OAuth error and status, or respond slowly. Faults can target an issuer, a client or a grant type, and include provider-specific paths. Authorization errors are redirected back to the client like real ones, and `dev_error=<code>` does the same for a single `/authorize` request. A banner shows on every page while faults are armed.

- [#9](https://github.com/samlaycock/localoidc/pull/9) [`7cd1753`](https://github.com/samlaycock/localoidc/commit/7cd17533124b30f40e48f5a47b75b28820980ae6) Thanks [@samlaycock](https://github.com/samlaycock)! - **Breaking:** removed the `localoidc token` and `localoidc presets` subcommands. localoidc is used only over HTTP, through its pages or its API: mint tokens with `/dev/api/token` (or the `/dev` page) and list presets with `/dev/api/presets`. Running `localoidc` starts the server as before, with the same flags; the `localoidc serve` subcommand is gone too.

- [#8](https://github.com/samlaycock/localoidc/pull/8) [`b407362`](https://github.com/samlaycock/localoidc/commit/b407362b9fa251f890755391f793233b38ed86bf) Thanks [@samlaycock](https://github.com/samlaycock)! - Add a request inspector. `/dev/requests` shows the last 500 requests to every issuer, live, with their (masked) parameters, outcome and, for failures, the exact reason, including errors redirected back to the client. `GET /dev/api/requests` (filterable by `client_id`, `errors`, `after` and `limit`) and `DELETE /dev/api/requests` let tests check what an app actually sent.

### Patch Changes

- [#7](https://github.com/samlaycock/localoidc/pull/7) [`b8eaa87`](https://github.com/samlaycock/localoidc/commit/b8eaa877435d59545024c5509113792ff1a9ba13) Thanks [@samlaycock](https://github.com/samlaycock)! - Serve the bundled CSS and JavaScript with `Cache-Control: no-cache`, so browsers don't keep running an old `app.js` against a newer version's pages after an upgrade.

- [#6](https://github.com/samlaycock/localoidc/pull/6) [`a30d529`](https://github.com/samlaycock/localoidc/commit/a30d529f7fc480d77f1ff821abcd3bd29119a98d) Thanks [@samlaycock](https://github.com/samlaycock)! - On presets that derive `sub` from another claim (GitHub, Facebook, Discord), setting `id` with `dev_claims` or the dev token API now updates `sub` too. Before, `sub` kept the preset's default value unless it was set explicitly.

## 0.1.0

### Minor Changes

- [#1](https://github.com/samlaycock/localoidc/pull/1) [`0192879`](https://github.com/samlaycock/localoidc/commit/0192879ea70b7ba87c41df0879054690ee696149) Thanks [@samlaycock](https://github.com/samlaycock)! - First release of localoidc, a local OpenID Connect / OAuth 2.0 provider for offline development, published as a Docker image (`ghcr.io/samlaycock/localoidc`) for linux/amd64 and linux/arm64. Logging in shows a short wizard (provider, claims, custom claims) instead of a password prompt, with saved identities for one-click sign-in. It emulates Google, GitHub, Microsoft Entra ID, Facebook, Apple, Auth0, Okta, Keycloak, GitLab, Discord and Cognito, and adds non-standard endpoints for minting tokens and rotating signing keys. It passes the OpenID Foundation conformance suite's Basic, Implicit, Hybrid, Form Post, Config, Dynamic and RP-initiated logout plans.
