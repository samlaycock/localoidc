---
"localoidc": minor
---

Add a request inspector. `/dev/requests` shows the last 500 requests to every issuer, live, with their (masked) parameters, outcome and, for failures, the exact reason, including errors redirected back to the client. `GET /dev/api/requests` (filterable by `client_id`, `errors`, `after` and `limit`) and `DELETE /dev/api/requests` let tests check what an app actually sent.
