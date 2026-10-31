# OpenID conformance testing

This directory runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against localoidc. It's the same software used for official OpenID Connect certification.

## Running

You need Docker (OrbStack or Docker Desktop on macOS), a Rust toolchain and `git`.

```sh
./conformance/run.sh                  # every plan group
./conformance/run.sh basic config     # selected groups
./conformance/run.sh --list           # show groups and the plans they map to
./conformance/run.sh --down           # stop and remove the suite containers
```

The script:

1. Fetches the suite's runner scripts at the pinned version (`SUITE_VERSION`, default `release-v5.3.4`) into `.suite/`. The suite server itself comes from the matching prebuilt image.
2. Builds localoidc and runs it on the host at `127.0.0.1:9450` with [`localoidc.toml`](localoidc.toml) and a fresh data dir (`.data/`).
3. Starts the suite (MongoDB, server, nginx) plus a Caddy TLS proxy with Docker Compose. Caddy exposes localoidc to the suite as `https://localoidc.test`, because the suite requires an `https` issuer.
4. Runs the plans with the suite's `run-test-plan.py` and exports the results to `results/`. You'll find a zip per plan, `run.log` and `localoidc.log` there.

The suite keeps running afterwards. You can browse the detailed logs at https://localhost.emobix.co.uk:8443, a public DNS name that resolves to 127.0.0.1; accept the self-signed certificate. The script exits non-zero if any check failed or warned unexpectedly.

| Group | Plan | Client registration |
|---|---|---|
| `config` | `oidcc-config-certification-test-plan` | static |
| `basic` | `oidcc-basic-certification-test-plan` | static |
| `implicit` | `oidcc-implicit-certification-test-plan` | static |
| `hybrid` | `oidcc-hybrid-certification-test-plan` | static |
| `formpost` | `oidcc-formpost-{basic,implicit,hybrid}-certification-test-plan` | static |
| `dynamic` | `oidcc-dynamic-certification-test-plan` | dynamic |
| `logout` | `oidcc-rp-initiated-logout-certification-test-plan` | dynamic |
| `backchannel` | `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | dynamic |

## Key rotation

`oidcc-server-rotate-keys` expects an operator to rotate the OP's keys between the test's setup and its start. [`patch-runner.py`](patch-runner.py) adds a hook to the fetched `run-test-plan.py` that calls localoidc's non-standard `POST /dev/api/rotate-keys` at that point. The patch fails loudly if a new suite version moves the code it hooks into.

## How login is automated

The suite drives localoidc's real login page with its headless browser, which follows the `browser` section of [`configs/*.json`](configs). It waits for the **Sign in** button and clicks it, so tokens carry the generic preset's default claims. If the page's JavaScript doesn't run in the headless browser, the empty claim fields make the server fall back to those same defaults.

Some tests take a screenshot of an error page or the login page for manual review. In official certification a person checks those; here they show up as `REVIEW` results in the suite UI.

## Files

| File | Purpose |
|---|---|
| `run.sh` | Entry point |
| `docker-compose.yml` | Suite services, Caddy TLS proxy and the runner container |
| `Caddyfile` | TLS termination for `https://localoidc.test` → host `:9450` |
| `localoidc.toml` | localoidc config for conformance runs, including the two static clients the suite uses |
| `configs/static.json` | Suite config for static-client plans: client credentials and browser automation |
| `configs/dynamic.json` | Suite config for dynamic-registration plans |
| `patch-runner.py` | Adds the key-rotation hook to the suite's runner |
| `expected-failures.json`, `expected-skips.json` | Known, accepted results, tagged with the plan `groups` they occur in; anything else fails the run |

## Notes

- On Linux, containers can't reach `127.0.0.1` on the host. Run with `LOCALOIDC_BIND=0.0.0.0 ./conformance/run.sh`.
- Use `SUITE_PORT=9443` if port 8443 is taken on the host. The suite's internal URLs are unaffected.
- The hostname must contain a dot (`localoidc.test`), because Java only sends TLS SNI for multi-label hostnames.
