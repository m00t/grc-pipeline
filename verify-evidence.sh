#!/usr/bin/env bash
# verify-evidence.sh <bundle.tar.gz>
# Proves an evidence bundle is intact and authentic, without trusting whoever handed it to you.
# Each check exits non-zero on failure. Prints CHAIN INTACT only if every check passes.

# Expects, in the current folder (override with env vars):
#   evidence.tar.gz.sha256  - hash sidecar written when the bundle was created   (SIDECAR)
#   evidence.sig.bundle     - Cosign signature bundle written when it was signed (SIG_BUNDLE)
set -euo pipefail


# Git Bash on Windows rewrites arguments that look like paths (such as the identity regexp) before passing them to cosign.exe. Turn that off. This has no effect on Linux or macOS.
export MSYS_NO_PATHCONV=1

BUNDLE="${1:?usage: verify-evidence.sh <bundle.tar.gz>}"
SIDECAR="${SIDECAR:-evidence.tar.gz.sha256}"
SIG_BUNDLE="${SIG_BUNDLE:-evidence.sig.bundle}"

# Only signatures made by this repo's grc-gate workflow, via GitHub Actions OIDC, are accepted.
# The repo was renamed from grc-terraform-aws-bucket to grc-pipeline. Signatures record the name at
# signing time and never change, so bundles signed before the rename carry the old name.
OIDC_ISSUER="https://token.actions.githubusercontent.com"
IDENTITY_REGEXP='^https://github\.com/m00t/(grc-pipeline|grc-terraform-aws-bucket)/\.github/workflows/grc-gate\.yml@'

fail() { echo "FAIL: $1"; exit 1; }

for f in "$BUNDLE" "$SIDECAR" "$SIG_BUNDLE"; do
  [ -f "$f" ] || fail "missing file: $f"
done

# INTEGRITY: has the bundle changed since it was created?
# Recompute its SHA-256 and compare it to the sidecar.
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$BUNDLE" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$BUNDLE" | awk '{print $1}')   # macOS
fi
expected=$(awk '{print $1}' "$SIDECAR")
if [ "$actual" != "$expected" ]; then
  echo "  expected: $expected"
  echo "  actual:   $actual"
  fail "INTEGRITY - bundle hash does not match the sidecar (bundle was modified)"
fi
echo "PASS: INTEGRITY - SHA-256 matches the sidecar"

# AUTHENTICITY + TIMELINESS: who signed it & and when?
# Verifies the signature, the Sigstore certificate (pinned to GitHub Actions and this repo's workflow) and the signed timestamp in the public transparency log.
if ! cosign verify-blob "$BUNDLE" \
      --bundle "$SIG_BUNDLE" \
      --certificate-oidc-issuer "$OIDC_ISSUER" \
      --certificate-identity-regexp "$IDENTITY_REGEXP"; then
  fail "AUTHENTICITY - signature not valid for this bundle, issuer or workflow identity"
fi
echo "PASS: AUTHENTICITY + TIMELINESS - signed by this repo's grc-gate.yml workflow, logged in Rekor"

# PRESERVATION: is the vaulted copy still retrievable, unaltered, and under Object Lock?
# Set VAULT_BUCKET and VAULT_KEY (the vaulted evidence.tar.gz) to run this check.
if [ -n "${VAULT_BUCKET:-}" ] && [ -n "${VAULT_KEY:-}" ]; then
  mode=$(aws s3api get-object-retention --bucket "$VAULT_BUCKET" --key "$VAULT_KEY" \
           --query 'Retention.Mode' --output text) || fail "PRESERVATION - no Object Lock retention on s3://$VAULT_BUCKET/$VAULT_KEY"
  retain=$(aws s3api get-object-retention --bucket "$VAULT_BUCKET" --key "$VAULT_KEY" \
           --query 'Retention.RetainUntilDate' --output text)
  now=$(date -u +%Y-%m-%dT%H:%M:%S)
  [[ "${retain:0:19}" > "$now" ]] || fail "PRESERVATION - retention expired at $retain"

  # The vaulted copy must be byte-for-byte the bundle being verified.
  copy="./.vault-copy.tar.gz"
  aws s3 cp --only-show-errors "s3://$VAULT_BUCKET/$VAULT_KEY" "$copy" || fail "PRESERVATION - could not retrieve vaulted copy"
  if command -v sha256sum >/dev/null 2>&1; then
    vaulted=$(sha256sum "$copy" | awk '{print $1}')
  else
    vaulted=$(shasum -a 256 "$copy" | awk '{print $1}')
  fi
  rm -f "$copy"
  [ "$vaulted" = "$actual" ] || fail "PRESERVATION - vaulted copy differs from this bundle"
  echo "PASS: PRESERVATION - vaulted copy matches, $mode retention until $retain"
else
  echo "SKIP: PRESERVATION - set VAULT_BUCKET and VAULT_KEY to check the vault"
fi

echo "CHAIN INTACT"