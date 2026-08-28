# Glarion

SaaS website security scanner: orchestrates open-source tools (Nuclei, testssl.sh, httpx, subfinder) behind a Rust backend, producing normalized, polished reports.

**License:** proprietary (consistent with the rest of the portfolio: PC Tweaker, Redaxa, PC Tweaker Uninstaller). Not open-source.

## Non-negotiable constraint: ownership verification

No active scan may run against a target whose ownership has not been verified (DNS TXT or `.well-known` file) and whose verification is not currently valid (30-day TTL). See `crates/orchestrator/src/verification.rs` — this is the project's primary safety logic and takes priority over any other feature.

The gate is enforced in two places, deliberately. `crates/api/src/routes/scans.rs`
refuses to queue a job for an unverified target; `crates/orchestrator/src/runner.rs`
re-checks at execution time, because a job can sit in the queue while its
verification lapses and the runner is what actually sends packets.

## Where traffic can be aimed

Proving ownership of a name is not the same as proving the name is safe to
contact. A hostname that passes every syntactic check can still resolve to
`127.0.0.1` or to `169.254.169.254`, which would point the scanner at our own
infrastructure or at the cloud metadata service. Two layers handle this:

- `crates/orchestrator/src/domain.rs` rejects targets *written* as an IP
  literal, as `localhost`, or under an internal suffix.
- `crates/orchestrator/src/net_guard.rs` rejects targets that *resolve* to
  any non-public address, and is what stops a public domain deliberately
  pointed at private space. Our own HTTPS fetches additionally pin the
  connection to the address that was validated, closing the DNS-rebinding
  window between check and connect.

## Structure

- `crates/api` — HTTP API (Axum): auth, target, verification, scan endpoints.
  Also builds the `runner` binary.
- `crates/orchestrator` — ownership verification, target validation, scan
  policy, job runner, external tool wrappers.
- `crates/report` — result normalization and report generation (not yet built).
- `migrations/` — Postgres schema (sqlx migrate).

## Running

Two processes, sharing a database:

```bash
cargo run --bin api       # HTTP API
cargo run --bin runner    # scan worker
```

Required environment: `DATABASE_URL`, `JWT_SECRET` (32+ chars). Optional:
`PORT`, `CORS_EXTRA_ORIGINS`. Both binaries refuse to start rather than
fall back to defaults.

The runner needs [`nuclei`](https://github.com/projectdiscovery/nuclei) on
`PATH`; a job whose tool is missing fails with a recorded reason rather
than hanging.

## Testing

```bash
bash scripts/dev-db.sh test
```

That is the command you want. It creates (on first run) and starts a
Postgres cluster dedicated to this project, then runs the whole suite with
the integration tests active.

Plain `cargo test --workspace` also works, but the scan-gate integration
tests in `crates/api/tests/scan_gate.rs` **skip silently** without a
database — a green `cargo test` on a machine with no Postgres does *not*
mean the gate was exercised. CI sets `TEST_DATABASE_URL` and fails the
build if those tests skip, because an unexercised gate is not a verified
gate.

### The dev database

`scripts/dev-db.sh` manages a cluster in `~/.glarion-devdb` on port 5433,
created under your normal user account with a generated password. It is
deliberately separate from any system PostgreSQL install: it needs no
superuser credentials and cannot disturb an existing database.

```bash
bash scripts/dev-db.sh start     # create + start
bash scripts/dev-db.sh stop
bash scripts/dev-db.sh status
bash scripts/dev-db.sh url       # print the connection URL
bash scripts/dev-db.sh destroy   # delete it entirely
```

## Status

Built and covered by 50 passing unit tests:

- Ownership verification (DNS TXT + `.well-known`), 30-day TTL, fail-closed
- Target validation rejecting IP literals, loopback, `.internal`, and the
  cloud metadata address
- Resolved-address filtering against SSRF, including IPv4-mapped IPv6 and
  carrier-grade NAT ranges
- Auth: Argon2 hashing, JWT pinned to HS256 with `token_version` revocation,
  constant-work login that does not leak which addresses are registered
- Rate limiting on the authentication endpoints
- Scan policy: tool allowlist, 6 scans per target per 24h
- The API gate and the runner's independent re-check
- Nuclei wrapper: argv-only spawn, enforced rate limit, attacking template
  categories excluded, JSONL parsing into normalized findings

Not yet built: report generation, Stripe billing, the frontend, and the
testssl/httpx/subfinder wrappers.

The gate has been verified against a live database, and the integration
tests were mutation-checked — disabling the expiry check makes
`scan_is_refused_when_verification_has_expired` fail, so the test is known
to be capable of catching a regression rather than merely passing.

### Known limits

- The auth rate limiter is per-process and keyed on the TCP peer address,
  so it does not survive horizontal scaling and collapses to a single
  bucket behind a reverse proxy. See `crates/api/src/rate_limit.rs`.
- The resolved-address check cannot be pinned for an external scanner
  process, leaving a small DNS-rebinding window between check and scan.

Full plan: `C:\Users\aurel\.claude\plans\nifty-waddling-shore.md`.

### Running the checks locally

```bash
bash scripts/ci-local.sh
```

Mirrors the hosted workflow: formatting, clippy, the full suite with the
integration tests active, and the assertion that the gate tests actually
ran rather than skipped. Hosted Actions do not run on this repository until
the account has Actions billing configured, so this script is currently the
one that enforces those checks.
