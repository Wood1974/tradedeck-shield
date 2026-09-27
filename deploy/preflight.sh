#!/usr/bin/env bash
set -euo pipefail
required=(SHIELD_API_AUTH_MODE SHIELD_ATTESTATION_MODE SHIELD_PLAY_INTEGRITY_MODE SHIELD_AUTHZ_MODE SHIELD_LOCAL_JWT_SECRET SHIELD_APP_ID GOOGLE_PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON)
for k in "${required[@]}"; do [[ -n "${!k:-}" ]] || { echo "missing:$k"; exit 1; }; done
[[ "$SHIELD_API_AUTH_MODE" == local ]] || exit 1
[[ "$SHIELD_ATTESTATION_MODE" == production ]] || exit 1
[[ "$SHIELD_PLAY_INTEGRITY_MODE" == production ]] || exit 1
[[ "$SHIELD_AUTHZ_MODE" == local ]] || exit 1
[[ "${#SHIELD_LOCAL_JWT_SECRET}" -ge 32 ]] || exit 1
echo "Shield production configuration preflight passed"
