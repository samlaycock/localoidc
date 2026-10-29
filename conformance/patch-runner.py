#!/usr/bin/env python3
"""Teach the suite's run-test-plan.py to rotate localoidc's signing key for oidcc-server-rotate-keys.

The test fetches the OP's JWKS, then waits for an operator to rotate the keys and press Start.
The stock runner presses Start straight away; this inserts a call to localoidc's non-standard
rotation endpoint (LOCALOIDC_ROTATE_KEYS_URL) just before it. Idempotent.
"""
import sys

path = sys.argv[1]
src = open(path).read()
marker = "LOCALOIDC_ROTATE_KEYS_URL"
if marker in src:
    sys.exit(0)

anchor = "                    print('Starting test')\n                    await conformance.start_test(module_id)\n"
if src.count(anchor) != 1:
    sys.exit(f"patch-runner.py: couldn't find the rotate-keys start hook in {path}; the suite version may have changed")

hook = (
    "                    print('Starting test')\n"
    "                    rotate_url = os.environ.get('LOCALOIDC_ROTATE_KEYS_URL')  # added by localoidc conformance/patch-runner.py\n"
    "                    if rotate_url:\n"
    "                        import httpx\n"
    "                        print('Rotating OP signing keys via ' + rotate_url)\n"
    "                        httpx.post(rotate_url, verify=False).raise_for_status()\n"
    "                    await conformance.start_test(module_id)\n"
)
open(path, "w").write(src.replace(anchor, hook))
print("patched " + path)
