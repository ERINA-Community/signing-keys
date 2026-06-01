#!/usr/bin/env bash
# verify-image.sh — Verify cosign signature on EESSI Docker images.
#
# External consumers use this to confirm that an image was actually built
# and signed by the official EESSI pipeline (not a local copy or a
# tampered variant).
#
# The public key is fetched from the published GitHub repo
# (ERINA-Community/signing-keys) — no Azure access required.

set -euo pipefail

# === Pinned constants ===
COSIGN_VERSION="3.0.6"
# SHA256 from the official cosign_checksums.txt for v3.0.6.
# Re-verify when bumping the version:
#   https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign_checksums.txt
COSIGN_SHA256_LINUX_AMD64="c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"
PUBKEY_URL="https://raw.githubusercontent.com/ERINA-Community/signing-keys/main/signing.pub"
REGISTRY="eessidockerrepository.azurecr.io"

usage() {
  cat <<EOF
Usage: $(basename "$0") <image>[:tag|@digest] [<image>...]

Verifies cosign signatures on EESSI Docker images against the published
public key (ERINA-Community/signing-keys/main/signing.pub).

Examples:
  $(basename "$0") eessi-java:4.1.2.14-prerelease
  $(basename "$0") eessi-java@sha256:d84846038c9647a3c81800ed5f76620a3a9759230ccf5115a6af84f8031dec6a
  $(basename "$0") eessi-java:1.2.3 eessi-circuitbreaker:1.2.3 eessi-holodeck:1.2.3

Prerequisites:
  - Logged in to ${REGISTRY} with 'docker login'
    (the same credentials you use for docker pull).
  - Network access to:
      github.com           (downloads the cosign binary and the public key)
      rekor.sigstore.dev   (transparency log inclusion proof)
      ${REGISTRY}  (fetches the image manifest and .sig artifact)
EOF
}

[ $# -lt 1 ] && { usage; exit 2; }

# === Platform detection ===
if [ "$(uname -s)" != "Linux" ]; then
  echo "This bash version only supports Linux. Use Verify-Image.ps1 on Windows." >&2
  exit 1
fi
if [ "$(uname -m)" != "x86_64" ] && [ "$(uname -m)" != "amd64" ]; then
  echo "Only linux-amd64 is pinned in this version. Add a SHA256 for $(uname -m) from cosign_checksums.txt." >&2
  exit 1
fi

# === Install cosign if not cached ===
COSIGN_DIR="${HOME}/.cache/eessi-cosign/${COSIGN_VERSION}"
COSIGN_BIN="${COSIGN_DIR}/cosign"
if [ ! -x "${COSIGN_BIN}" ]; then
  mkdir -p "${COSIGN_DIR}"
  echo "Downloading cosign ${COSIGN_VERSION} to ${COSIGN_BIN}..." >&2
  curl -fsSL \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    -o "${COSIGN_BIN}"
  echo "${COSIGN_SHA256_LINUX_AMD64}  ${COSIGN_BIN}" | sha256sum -c - >&2
  chmod +x "${COSIGN_BIN}"
fi

# === Fetch the public key fresh each run (cheap, and catches key rotation) ===
PUBKEY_FILE="$(mktemp)"
trap 'rm -f "${PUBKEY_FILE}"' EXIT
curl -fsSL "${PUBKEY_URL}" -o "${PUBKEY_FILE}"

# === Verify each ref ===
PASS=0
FAIL=0
TOTAL=$#
for raw in "$@"; do
  # Prepend the registry if a short form was given (no registry hostname).
  if [[ "${raw}" == *.azurecr.io/* ]]; then
    ref="${raw}"
  else
    ref="${REGISTRY}/${raw}"
  fi

  echo
  echo "=== ${ref} ==="
  if output=$("${COSIGN_BIN}" verify --key "${PUBKEY_FILE}" "${ref}" 2>&1); then
    PASS=$((PASS + 1))
    echo "${output}" | grep -E "^Verification for|^  - " | head -4
    echo "VERIFIED"
  else
    FAIL=$((FAIL + 1))
    echo "${output}" | tail -5
    echo "FAILED"
    if echo "${output}" | grep -qi "UNAUTHORIZED\|authentication required"; then
      echo "Hint: run 'docker login ${REGISTRY}' with your credentials and try again."
    fi
  fi
done

echo
echo "=== Result: ${PASS}/${TOTAL} verified ==="
exit $FAIL
