#!/usr/bin/env bash
# enforcement-check.sh — is Darkbloom's APNs code-identity gate actually enforced?
#
# Context: coordinator/registry/registry.go:1016 (codeAttestationEnforcedLocked)
# returns false whenever APNS_ENFORCE_AFTER is unset or still in the future, in
# which case providers that never passed the code-identity round-trip still
# receive private text traffic. The value lives in the operator's secret manager;
# the single external witness is the aggregate boolean below.
#
# Usage: verify/enforcement-check.sh [api-base]     (default https://api.darkbloom.dev)
set -euo pipefail

BASE="${1:-https://api.darkbloom.dev}"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

stats="$(curl -fsS --max-time 20 "$BASE/v1/stats")"

enforced=$(jq -r '.code_attestation_enforced // "absent"' <<<"$stats")
attested=$(jq -r '.code_attested_providers   // "absent"' <<<"$stats")
active=$(  jq -r '.active_providers          // "absent"' <<<"$stats")

echo "coordinator:            $BASE"
echo "code_attestation_enforced: $enforced"
echo "code_attested_providers:   $attested"
echo "active_providers:          $active"

if [ "$enforced" = "true" ]; then
  echo
  echo "GATE ON — un-attested providers are refused private text routing."
  if [ "$attested" != "absent" ] && [ "$active" != "absent" ]; then
    echo "Coverage: $attested of $active active providers hold a code-identity proof."
  fi
else
  echo
  echo "GATE OFF (grace mode) — providers that never passed the APNs code-identity"
  echo "round-trip are still routed private text. In this state the network's"
  echo "provider-side code guarantee is the pre-v0.6.0 one: a self-reported binary"
  echo "hash (itself default-off since v0.6.0). See DEVPROOF-REPORT.md N2."
fi

echo
echo "--- feed: does it expose the code-identity signal per provider yet? (N4) ---"
feed="$(curl -fsS --max-time 30 "$BASE/v1/providers/attestation")"
jq -r '.providers[0] | keys[]' <<<"$feed" | tr '\n' ' '; echo
for k in code_attested se_key_bound attestation_blob attestation_signature; do
  if jq -e --arg k "$k" '.providers[0] | has($k)' >/dev/null <<<"$feed"; then
    echo "  present: $k"
  else
    echo "  ABSENT:  $k"
  fi
done
