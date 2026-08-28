#!/usr/bin/env bash
# Fills in the Stripe values in .env.local from the Stripe CLI's own login.
#
#   bash scripts/link-stripe.sh
#
# The CLI already holds a test-mode key for whichever account you logged
# into. This copies that key, and starts a webhook listener long enough to
# capture its signing secret, so neither value has to be pasted anywhere by
# hand — and neither is ever printed.
#
# Test mode only, on purpose. A live key is worth money, and the right
# place to handle one is the deployment platform's secret store, not a file
# on a development machine.

set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="$HOME/.config/stripe/config.toml"
ENV_FILE=".env.local"
PORT="${PORT:-8080}"

if [ ! -f "$CONFIG" ]; then
    echo "error: the Stripe CLI is not logged in. Run: stripe login" >&2
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    cp .env.local.example "$ENV_FILE"
    echo "Created $ENV_FILE"
fi

# --- the API key -------------------------------------------------------

# Read and written entirely inside python: passing a key through a shell
# variable puts it in the process table, where any other process on the
# machine can read it.
python - "$CONFIG" "$ENV_FILE" <<'PY'
import pathlib
import re
import sys

config_path, env_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
config = config_path.read_text(encoding="utf-8")

# The CLI stores its key under the profile it is using. Only ever the test
# one: a live key is deliberately out of scope here.
match = re.search(r"test_mode_api_key\s*=\s*['\"]([^'\"]+)['\"]", config)
if not match:
    print("  no test key found in the CLI config — run: stripe login")
    raise SystemExit(0)

key = match.group(1)
if not key.startswith("sk_test_") and not key.startswith("rk_test_"):
    print("  the key in the CLI config is not a test key; refusing to copy it")
    raise SystemExit(0)

env = env_path.read_text(encoding="utf-8")
env = re.sub(r"^STRIPE_SECRET_KEY=.*$", f"STRIPE_SECRET_KEY={key}", env, flags=re.M)
env_path.write_text(env, encoding="utf-8", newline="\n")
print("  secret key: copied from the CLI login")
PY

# --- the webhook signing secret ----------------------------------------

if ! command -v stripe >/dev/null 2>&1; then
    echo "  webhook secret: skipped, the stripe CLI is not on PATH"
    exit 0
fi

echo "  webhook secret: starting a listener to capture it"

LISTEN_LOG="$(mktemp)"
trap 'rm -f "$LISTEN_LOG"' EXIT

# The listener prints the secret on startup and then stays running to
# forward events. Started detached so this script can read the secret and
# return; the listener has to keep running for webhooks to arrive locally.
stripe listen --forward-to "localhost:$PORT/api/billing/webhook" \
    >"$LISTEN_LOG" 2>&1 &
LISTEN_PID=$!

for _ in $(seq 1 20); do
    if grep -q "whsec_" "$LISTEN_LOG" 2>/dev/null; then
        break
    fi
    sleep 1
done

python - "$LISTEN_LOG" "$ENV_FILE" <<'PY'
import pathlib
import re
import sys

log_path, env_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
match = re.search(r"(whsec_[A-Za-z0-9]+)", log_path.read_text(encoding="utf-8", errors="replace"))

if not match:
    print("  webhook secret: the listener did not report one")
    raise SystemExit(0)

env = env_path.read_text(encoding="utf-8")
env = re.sub(r"^STRIPE_WEBHOOK_SECRET=.*$", f"STRIPE_WEBHOOK_SECRET={match.group(1)}", env, flags=re.M)
env_path.write_text(env, encoding="utf-8", newline="\n")
print("  webhook secret: captured")
PY

echo
echo "The listener is running as pid $LISTEN_PID and must stay running for"
echo "webhooks to reach a local API. Stop it with: kill $LISTEN_PID"
echo
echo "Values written to $ENV_FILE, which is gitignored. Nothing was printed."
