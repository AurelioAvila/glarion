#!/usr/bin/env bash
# Deploys the current commit to Fly.io.
#
#   bash scripts/deploy-fly.sh
#
# Assumes the app already exists (`fly launch --no-deploy` once, the first
# time) and every secret is already set (`fly secrets set NAME=value`,
# never on this machine's command line for a live key — paste it directly
# into the prompt Fly gives you, or use `fly secrets set NAME=- < file`
# from a file outside the repo). This script only builds and ships the
# image; it never touches secrets, so it has nothing sensitive to leak.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v flyctl >/dev/null 2>&1 && ! command -v fly >/dev/null 2>&1; then
    echo "error: the Fly CLI is not installed. See https://fly.io/docs/flyctl/install/" >&2
    exit 1
fi

FLY="$(command -v flyctl || command -v fly)"

echo "==> Running local checks first (a broken build shouldn't reach production)"
bash scripts/ci-local.sh

echo "==> Deploying"
"$FLY" deploy
