---
"localoidc": minor
---

Add declared users: `[[users]]` in `localoidc.toml` defines named identities that show up on the login page and can be used with `dev_user=<id>` on `/authorize`, `"user"` in the dev token API, `localoidc token --user`, the `password` grant and `--auto-login` login hints. Each user gets a stable, provider-shaped `sub`. `GET /dev/api/users` and `localoidc users` list them.
