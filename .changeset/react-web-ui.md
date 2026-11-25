---
"localoidc": minor
---

The web UI is rebuilt as a React app with shadcn/ui components. Everything works as before (the claims editor at sign-in, the token generator with the clock, faults, sessions and signing key, the request inspector and the device pages), with a few changes:

- The overview, token generator and request inspector switch without reloading, and the request inspector's filters are kept in the URL.
- Changing the clock, faults or sessions updates the page in place instead of reloading it.
- There's a light, dark and system theme switch.
- The sign-in and device pages still work without JavaScript, signing in with the preset's default claims.
- `GET /dev/api/info` returns what the web UI shows about an issuer: its endpoints, the other issuers, the clock and the armed faults. `GET /dev/api/sessions` now includes each session's `label` and its `backchannel_clients`.
