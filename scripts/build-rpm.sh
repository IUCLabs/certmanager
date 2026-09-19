#!/usr/bin/env bash
#
# Package the (already built) certmanager binary into an RPM with nfpm,
# bundling generated bash/zsh/fish shell completions.
# Usage: scripts/build-rpm.sh [version]   (version defaults to $CI_COMMIT_TAG)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION="${1:-${CI_COMMIT_TAG:-0.0.0-dev}}"
VERSION="${VERSION#v}" # strip a leading v
BINARY="certmanager"
DIST="dist"

if [ ! -f "${DIST}/${BINARY}" ]; then
  echo "ERROR: ${DIST}/${BINARY} not found; run 'make build' first" >&2
  exit 1
fi

# Generate shell completions from the freshly built binary so they always match
# the shipped flags.
COMP_DIR="${DIST}/completions"
mkdir -p "${COMP_DIR}"
"./${DIST}/${BINARY}" completion bash >"${COMP_DIR}/${BINARY}.bash"
"./${DIST}/${BINARY}" completion zsh >"${COMP_DIR}/_${BINARY}"
"./${DIST}/${BINARY}" completion fish >"${COMP_DIR}/${BINARY}.fish"

export PACKAGE_NAME="${BINARY}"
export PACKAGE_VERSION="${VERSION}"
export PACKAGE_RELEASE="1"
export PACKAGE_ARCH="amd64"
export PACKAGE_PLATFORM="linux"
export PACKAGE_DESCRIPTION="Issues Vault PKI certificates for Puppet-managed nodes; drop-in replacement for the Python certmanager script"
export PACKAGE_MAINTAINER="Ben Vincent <12552114+neoloc@users.noreply.github.com>"
export PACKAGE_HOMEPAGE="https://github.com/IUCLabs/certmanager"
export PACKAGE_LICENSE="MIT"

envsubst <packaging/nfpm.yaml >"${DIST}/nfpm.yaml"
nfpm pkg --config "${DIST}/nfpm.yaml" --target "${DIST}" --packager rpm

echo "Built:"
ls -1 "${DIST}"/*.rpm
