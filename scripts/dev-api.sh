#!/usr/bin/env bash
# Runs the API against the development database, with the settings the
# local dashboard needs.
#
#   bash scripts/dev-api.sh
#
# Starts the dedicated Postgres cluster if it is not already up, then runs
# the API on port 8080 with CORS opened to the local web server. The JWT
# secret is generated once and kept outside the repository.

set -euo pipefail

cd "$(dirname "$0")/.."

WEB_ORIGIN="${GLARION_WEB_ORIGIN:-http://localhost:5173}"
SECRET_FILE="${GLARION_DEV_HOME:-$HOME/.glarion-devdb}/jwt-secret"

bash scripts/dev-db.sh start >/dev/null

if [ ! -f "$SECRET_FILE" ]; then
    mkdir -p "$(dirname "$SECRET_FILE")"
    # `head` closing the pipe makes `tr` exit on SIGPIPE, which pipefail
    # would treat as failure.
    (
        set +o pipefail
        LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48 >"$SECRET_FILE"
    )
    chmod 600 "$SECRET_FILE" 2>/dev/null || true
fi

# The development database, not the test one. The integration tests
# truncate every table, so running the app against that database means a
# test run wipes the accounts and scan history you were working with.
# Local secrets, if there are any.
#
# Kept in a gitignored file rather than typed into a terminal each time:
# an API key pasted onto a command line ends up in shell history, and one
# committed to a repository ends up somewhere much worse. See .env.local.example.
if [ -f .env.local ]; then
    echo "Loading .env.local"
    set -a
    # shellcheck disable=SC1091
    . ./.env.local
    set +a
fi

DATABASE_URL="$(bash scripts/dev-db.sh url dev)"
JWT_SECRET="$(cat "$SECRET_FILE")"

# Added to the built-in first-party origins rather than replacing them —
# the API's allowlist is additive by design.
export DATABASE_URL JWT_SECRET
export CORS_EXTRA_ORIGINS="$WEB_ORIGIN"
export PORT="${PORT:-8080}"
export RUST_LOG="${RUST_LOG:-info,sqlx=warn}"

echo "API on http://localhost:$PORT — CORS open to $WEB_ORIGIN"
exec cargo run --quiet --bin api
