#!/usr/bin/env bash
#
# Run the end-to-end integration test against a real Vault dev server.
#
# With CERTMANAGER_IT_VAULT_ADDR set (CI, where Woodpecker runs Vault as a
# service) the test is run directly. Otherwise a throwaway dev server is
# started with docker/podman and torn down afterwards.
#
# VAULT_ADDR is deliberately ignored: this test mounts PKI and writes policies,
# and a developer shell usually has VAULT_ADDR pointing at production.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.21}"
CONTAINER_NAME="${CONTAINER_NAME:-certmanager-integration-vault}"

run_tests() {
  env -u VAULT_ADDR -u VAULT_TOKEN \
    CERTMANAGER_IT_VAULT_ADDR="${CERTMANAGER_IT_VAULT_ADDR}" \
    CERTMANAGER_IT_VAULT_TOKEN="${CERTMANAGER_IT_VAULT_TOKEN}" \
    go test -tags=integration -count=1 -v ./test/integration/...
}

if [ -n "${CERTMANAGER_IT_VAULT_ADDR:-}" ]; then
  echo "Using the Vault dev server at ${CERTMANAGER_IT_VAULT_ADDR}"
  CERTMANAGER_IT_VAULT_TOKEN="${CERTMANAGER_IT_VAULT_TOKEN:-root}"
  run_tests
  exit 0
fi

RUNTIME=""
for candidate in docker podman; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    RUNTIME="${candidate}"
    break
  fi
done
if [ -z "${RUNTIME}" ]; then
  echo "ERROR: need docker or podman to start a Vault dev server, or set VAULT_ADDR" >&2
  exit 1
fi

cleanup() {
  "${RUNTIME}" rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "Starting ${VAULT_IMAGE} dev server via ${RUNTIME}"
"${RUNTIME}" run -d --name "${CONTAINER_NAME}" \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=root \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  "${VAULT_IMAGE}" \
  server -dev >/dev/null

# The test itself polls sys/health, so no sleep here.
CERTMANAGER_IT_VAULT_ADDR="http://127.0.0.1:8200"
CERTMANAGER_IT_VAULT_TOKEN="root"
run_tests
