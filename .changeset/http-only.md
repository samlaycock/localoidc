---
"localoidc": minor
---

**Breaking:** removed the `localoidc token` and `localoidc presets` subcommands. localoidc is used only over HTTP, through its pages or its API: mint tokens with `/dev/api/token` (or the `/dev` page) and list presets with `/dev/api/presets`. Running `localoidc` starts the server as before, with the same flags; the `localoidc serve` subcommand is gone too.
