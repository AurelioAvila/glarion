#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml, locally.
#
# Worth having even when hosted CI is working — it catches a failure before
# a push rather than after — and it is the only safety net when Actions
# cannot run at all, which is the case on a private repository whose
# account has no Actions billing configured.
#
#   bash scripts/ci-local.sh
#
# Exits non-zero on the first failure, like CI does.

set -euo pipefail

cd "$(dirname "$0")/.."

step() {
    echo
    echo "=== $1 ==="
}

step "Formatting"
cargo fmt --all -- --check

step "Clippy"
cargo clippy --workspace --all-targets -- -D warnings

step "Dependency vulnerabilities"
# Skipped rather than failed when the tool is not installed, same as the
# frontend check below — but worth having: this is what caught rsa-mysql
# and the old rustls-webpki duplication (see audit.toml for the one
# advisory that stays ignored, and why). Requires `cargo install
# cargo-audit`.
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit --ignore RUSTSEC-2023-0071
else
    echo "skipped — run 'cargo install cargo-audit' to include this"
fi

step "Frontend types and tests"
# Skipped rather than failed when dependencies are not installed: the
# backend checks should still be runnable without a Node toolchain.
if [ -d web/node_modules ]; then
    (cd web && npx tsc --noEmit && npm test --silent)
else
    echo "skipped — run 'npm install' in web/ to include this"
fi

step "Starting the development database"
# Needed so the integration tests run rather than skip.
bash scripts/dev-db.sh start >/dev/null
TEST_DATABASE_URL="$(bash scripts/dev-db.sh url)"
export TEST_DATABASE_URL

step "Tests"
# --test-threads=1: the integration tests truncate shared tables.
cargo test --workspace -- --test-threads=1

step "Confirming the authorization gate was actually exercised"
# The gate tests skip silently without a database, which would make a green
# run meaningless. Treat a skip as a failure, exactly as CI does.
gate_output=$(cargo test --workspace --test scan_gate -- --test-threads=1 --nocapture 2>&1)

if grep -q "skipping: TEST_DATABASE_URL not set" <<<"$gate_output"; then
    echo "FAILED: the scan gate tests skipped, so the gate is unverified." >&2
    exit 1
fi

if ! grep -qE "test result: ok\. [1-9][0-9]* passed" <<<"$gate_output"; then
    echo "FAILED: no scan gate tests reported as passing." >&2
    echo "$gate_output" >&2
    exit 1
fi

echo
echo "All checks passed."
