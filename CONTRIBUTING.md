# Contributing to localoidc

Thanks for helping out. Bug reports, provider-emulation fixes and new features are all welcome. For anything large, please open an issue first so we can agree on the approach.

## Development

You need a recent stable Rust toolchain. Node.js is only needed for changesets.

```sh
cargo run                        # serve on http://localhost:9400
cargo test                       # integration tests for every flow
cargo clippy --all-targets -- -D warnings
cargo fmt
docker build -t localoidc .      # the release image
```

CI runs `cargo fmt --check`, clippy with `-D warnings` and `cargo test` on every pull request.

- The login, device and token generator pages share `assets/app.js` and `assets/app.css`. Both are compiled into the binary, so rebuild after changing them.
- Provider presets (claim shapes, defaults and endpoints) live in `src/presets.rs`. Provider-specific routes are in `src/routes/providers.rs`.

If you change protocol behaviour, run the [OpenID conformance suite](conformance/README.md) (`./conformance/run.sh`) as well. It needs Docker.

## Changesets

Every pull request needs a changeset: a short Markdown file under `.changeset/` that says what changed and whether it's a `patch`, `minor` or `major` change. It becomes the changelog entry.

```sh
npm ci
npm run changeset                # describe a change users will notice
npm run changeset -- --empty     # for CI, tests, docs and other invisible changes
```

CI fails if a pull request has no changeset.

## Releases

Releases are managed with [changesets](https://github.com/changesets/changesets). `package.json` holds the version, and `npm run version` copies it into `Cargo.toml` and `Cargo.lock`.

1. Changesets land on `main` with their pull requests.
2. The release workflow keeps a "Release <version>" pull request open. It applies the pending changesets: the version bump and `CHANGELOG.md`. CI runs on it, including a Docker build check.
3. Merging that pull request does the release:
   - builds the image natively for amd64 and arm64;
   - pushes `ghcr.io/samlaycock/localoidc:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`;
   - tags `v<version>` and creates the GitHub release from the changelog.

## License

By contributing, you agree that your contributions will be dual licensed under the MIT and Apache-2.0 licenses, as described in the [README](README.md#license).
