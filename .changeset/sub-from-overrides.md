---
"localoidc": patch
---

On presets that derive `sub` from another claim (GitHub, Facebook, Discord), setting `id` with `dev_claims` or the dev token API now updates `sub` too. Before, `sub` kept the preset's default value unless it was set explicitly.
