---
"localoidc": minor
---

Add a clock offset for testing expiry and clock skew. `POST /dev/api/clock` (with `offset`, `advance` or `reset`), the controls on `/dev`, or `--clock-offset` / `LOCALOIDC_CLOCK_OFFSET` run the server clock ahead of or behind real time. That shifts token timestamps and every expiry check: codes, sessions, refresh tokens, device codes and `max_age`. A banner shows on every page while the clock is shifted.
