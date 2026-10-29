# localoidc

## 0.1.0

### Minor Changes

- [#1](https://github.com/samlaycock/localoidc/pull/1) [`0192879`](https://github.com/samlaycock/localoidc/commit/0192879ea70b7ba87c41df0879054690ee696149) Thanks [@samlaycock](https://github.com/samlaycock)! - First release of localoidc, a local OpenID Connect / OAuth 2.0 provider for offline development, published as a Docker image (`ghcr.io/samlaycock/localoidc`) for linux/amd64 and linux/arm64. Logging in shows a short wizard (provider, claims, custom claims) instead of a password prompt, with saved identities for one-click sign-in. It emulates Google, GitHub, Microsoft Entra ID, Facebook, Apple, Auth0, Okta, Keycloak, GitLab, Discord and Cognito, and adds non-standard endpoints for minting tokens and rotating signing keys. It passes the OpenID Foundation conformance suite's Basic, Implicit, Hybrid, Form Post, Config, Dynamic and RP-initiated logout plans.
