#!/usr/bin/env bash
set -euo pipefail
echo "Source deployment from CI is disabled. Deploy by hand: flyctl deploy --app glarion-api --remote-only --ha=false. scripts/deploy-signed.ps1 is the signed local rollback package." >&2
exit 1
