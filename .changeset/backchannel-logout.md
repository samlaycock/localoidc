---
"localoidc": minor
---

Add OIDC Back-Channel Logout 1.0. Clients can register a `backchannel_logout_uri` (in `localoidc.toml` or through dynamic registration). When a browser session ends, through `/end_session` or the new `DELETE /dev/api/sessions/{sid}`, each client that used it gets a signed logout token. Deliveries appear in the request inspector. `GET /dev/api/sessions` and a Sessions card on `/dev` list active sessions.

Refresh tokens issued during a session now stop working when the session ends, unless they were issued with `offline_access`. This also applies to plain RP-initiated logout.
