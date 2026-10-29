---
"localoidc": minor
---

Add fault injection. `POST /dev/api/faults` (or the Faults card on `/dev`) makes the next matching requests to an endpoint fail with a chosen OAuth error and status, or respond slowly. Faults can target an issuer, a client or a grant type, and include provider-specific paths. Authorization errors are redirected back to the client like real ones, and `dev_error=<code>` does the same for a single `/authorize` request. A banner shows on every page while faults are armed.
