#!/usr/bin/env bash
# Run the OpenID Foundation conformance suite against localoidc.
#
#   ./conformance/run.sh                 # every plan group
#   ./conformance/run.sh basic config    # selected groups
#   ./conformance/run.sh --list          # show groups
#   ./conformance/run.sh --down          # stop the suite containers
#
# Builds localoidc, runs it on the host (127.0.0.1:9450) with a fresh data dir,
# starts the suite + a TLS proxy with Docker Compose, runs the plans and exports
# the results to conformance/results/. The suite UI stays up afterwards at
# https://localhost.emobix.co.uk:8443 for inspecting logs.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"
ROOT="$(cd .. && pwd)"

export SUITE_VERSION="${SUITE_VERSION:-release-v5.3.4}"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
SUITE_PORT="${SUITE_PORT:-8443}"
export SUITE_PORT
# On Linux, containers can't reach 127.0.0.1 on the host; set LOCALOIDC_BIND=0.0.0.0 there.
LOCALOIDC_BIND="${LOCALOIDC_BIND:-127.0.0.1}"

STATIC="configs/static.json"
DYNAMIC="configs/dynamic.json"
ALL_GROUPS="config basic implicit hybrid formpost dynamic logout"

plans_for() {
    case "$1" in
        config)   echo "oidcc-config-certification-test-plan $STATIC" ;;
        basic)    echo "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC" ;;
        implicit) echo "oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC" ;;
        hybrid)   echo "oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC" ;;
        formpost)
            echo "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC"
            echo "oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC"
            echo "oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client] $STATIC"
            ;;
        dynamic)  echo "oidcc-dynamic-certification-test-plan[response_type=code] $DYNAMIC" ;;
        logout)   echo "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=dynamic_client] $DYNAMIC" ;;
        *) echo "unknown plan group '$1' (groups: $ALL_GROUPS)" >&2; return 1 ;;
    esac
}

compose() { docker compose -f "$HERE/docker-compose.yml" "$@"; }
log() { printf '\033[1m==> %s\033[0m\n' "$*"; }

case "${1:-}" in
    --list) for g in $ALL_GROUPS; do echo "$g:"; plans_for "$g" | sed 's/^/  /'; done; exit 0 ;;
    --down) compose --profile runner down -v; exit 0 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac

GROUPS_TO_RUN="${*:-$ALL_GROUPS}"
PLAN_ARGS=()
for g in $GROUPS_TO_RUN; do
    while IFS= read -r line; do
        # Plan spec and config path are separate argv entries.
        PLAN_ARGS+=("${line% *}" "${line##* }")
    done < <(plans_for "$g")
done

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "the Docker daemon is not running" >&2; exit 1; }

# 1. Fetch the suite's runner scripts at the pinned version (the server itself is a prebuilt image).
if [ ! -f ".suite/$SUITE_VERSION" ]; then
    log "Fetching conformance suite scripts ($SUITE_VERSION)"
    rm -rf .suite
    git clone --quiet --depth 1 --branch "$SUITE_VERSION" --filter=blob:none --sparse "$SUITE_REPO" .suite/repo
    git -C .suite/repo sparse-checkout set scripts
    mv .suite/repo/scripts .suite/scripts
    rm -rf .suite/repo
    touch ".suite/$SUITE_VERSION"
fi
python3 patch-runner.py .suite/scripts/run-test-plan.py

# 2. Build and start localoidc on the host with a throwaway data dir.
log "Building localoidc"
cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"
mkdir -p results
rm -rf .data
"$ROOT/target/release/localoidc" --config localoidc.toml --host "$LOCALOIDC_BIND" --data-dir "$HERE/.data" \
    > results/localoidc.log 2>&1 &
LOCALOIDC_PID=$!
trap 'kill $LOCALOIDC_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:9450/health" >/dev/null && break
    kill -0 $LOCALOIDC_PID 2>/dev/null || { cat results/localoidc.log; echo "localoidc failed to start" >&2; exit 1; }
    sleep 0.2
done

# 3. Start the suite and the TLS proxy.
log "Starting conformance suite $SUITE_VERSION"
compose --profile runner build --quiet runner
compose up -d --quiet-pull mongodb server nginx localoidc
printf 'Waiting for the suite to boot'
for i in $(seq 1 120); do
    if curl -skf -o /dev/null "https://localhost:$SUITE_PORT/api/runner/available"; then break; fi
    [ "$i" = 120 ] && { echo; compose logs --tail 50 server; echo "suite did not start" >&2; exit 1; }
    printf '.'; sleep 2
done
echo
log "Checking the suite can reach https://localoidc.test"
compose run --rm --no-deps --entrypoint python3 runner -c \
    "import httpx,sys; r=httpx.get('https://localoidc.test/.well-known/openid-configuration', verify=False); print(r.status_code, r.json()['issuer']); sys.exit(r.status_code!=200)"

# 4. Run the plans. The runner fails on expectations that never come up, so only pass
#    the expected failures/skips tagged with a group that's being run.
for kind in failures skips; do
    python3 - "$kind" $GROUPS_TO_RUN > "results/expected-$kind.json" <<'PY'
import json, sys
kind, groups = sys.argv[1], set(sys.argv[2:])
entries = [e for e in json.load(open(f"expected-{kind}.json")) if groups & set(e.pop("groups"))]
print(json.dumps(entries, indent=2))
PY
done
log "Running: $GROUPS_TO_RUN"
rm -f results/*.zip
set +e
compose run --rm --no-deps runner --export-dir results --verbose \
    --expected-failures-file results/expected-failures.json --expected-skips-file results/expected-skips.json \
    "${PLAN_ARGS[@]}" 2>&1 | tee results/run.log
STATUS=${PIPESTATUS[0]}
set -e

log "Results exported to conformance/results/ (suite UI: https://localhost.emobix.co.uk:$SUITE_PORT)"
exit "$STATUS"
