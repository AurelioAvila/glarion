#!/usr/bin/env bash
set -euo pipefail
echo "Unsigned source deployment is disabled. Build the candidate, sign its immutable image digest with the publisher certificate, then use scripts/deploy-signed.ps1." >&2
exit 1
