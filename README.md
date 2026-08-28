# Glarion

Website security scanner. Orchestrates open-source scanning tools behind a
Rust API and normalizes their output into a single finding model.

Proprietary. Not open-source.

## The constraint everything else is arranged around

A service that scans arbitrary domains on request is an attack tool unless
it can prove the requester owns the target. So no scan runs against a
domain whose ownership has not been proved and whose proof has not lapsed.

Ownership is proved with a DNS TXT record or a `.well-known` file and
expires after 30 days. The check runs in two independent places:

- `crates/api/src/routes/scans.rs` refuses to queue a job for an unverified
  target.
- `crates/orchestrator/src/runner.rs` checks again at execution time,
  because a job can sit in the queue while its verification lapses, and the
  runner is what actually sends traffic.

Every queued scan writes an authorization record in the same transaction as
the job, so a job cannot exist without a trail of who authorized it.

## Where traffic can be aimed

Proving ownership of a name is not the same as proving the name is safe to
contact. A hostname that passes every syntactic check can still resolve to
`127.0.0.1` or `169.254.169.254`, which would point the scanner at our own
infrastructure or at the cloud metadata service. Two layers handle this:

- `crates/orchestrator/src/domain.rs` rejects targets *written* as an IP
  literal, as `localhost`, or under an internal suffix.
- `crates/orchestrator/src/net_guard.rs` rejects targets that *resolve* to
  a non-public address, which is what stops a public domain deliberately
  pointed at private space. Outbound HTTPS additionally pins the connection
  to the address that passed the check, closing the DNS-rebinding window.

Intensity is capped independently of authorization: detection-only tools on
an allowlist, six scans per target per day, an enforced request rate, and
fuzzing, brute-force and denial-of-service template categories excluded.
External tools are spawned with an argument vector, never a shell string.

## Structure

- `crates/api` — HTTP API (Axum): auth, targets, verification, scans,
  results. Also builds the `runner` binary.
- `crates/orchestrator` — verification, target validation, scan policy, job
  runner, tool wrappers.
- `crates/report` — triage and report rendering.
- `web/` — the dashboard: TypeScript compiled with `tsc`, no framework and
  no bundler, matching the rest of the portfolio.
- `migrations/` — Postgres schema, applied with sqlx.

## Running

```bash
bash scripts/dev-api.sh                              # API + database
cargo run --bin runner                               # scan worker
cd web && npm install && npm run build               # dashboard, once
python -m http.server 5173 --directory web           # serve it
```

`scripts/dev-api.sh` starts the development database, generates a JWT
secret on first run, and opens CORS to the local dashboard. In production
the API needs `DATABASE_URL` and `JWT_SECRET` (32+ characters); `PORT` and
`CORS_EXTRA_ORIGINS` are optional. Both binaries refuse to start rather
than fall back to a default.

The dashboard talks to the same origin it is served from. On localhost it
falls back to port 8080, so development needs no configuration and no
machine-specific URL can be committed by accident.

The runner needs [`nuclei`](https://github.com/projectdiscovery/nuclei) on
`PATH`. A job whose tool is missing fails with a recorded reason rather
than hanging.

## Testing

```bash
bash scripts/dev-db.sh test
```

Creates and starts a Postgres cluster dedicated to this project, then runs
the whole suite with the integration tests active. 135 tests at present.

Plain `cargo test --workspace` also works, but the integration tests in
`crates/api/tests/scan_gate.rs` **skip silently** without a database, so a
green run on a machine with no Postgres does not mean the gate was
exercised. Before pushing, run the full set of checks:

```bash
bash scripts/ci-local.sh
```

That mirrors the hosted workflow — formatting, clippy, the suite with
integration tests active, and an assertion that the gate tests ran rather
than skipped. It is currently the only thing enforcing those checks:
GitHub Actions will not start on this repository until the account has
Actions billing configured.

### The development database

`scripts/dev-db.sh` manages a cluster in `~/.glarion-devdb` on port 5433,
created under your normal user account with a generated password. It is
deliberately separate from any system PostgreSQL install: it needs no
superuser credentials and cannot disturb an existing database.

```bash
bash scripts/dev-db.sh start     # create and start
bash scripts/dev-db.sh stop
bash scripts/dev-db.sh status
bash scripts/dev-db.sh url       # print the connection URL
bash scripts/dev-db.sh destroy   # delete it entirely
```

## Status

Working: ownership verification, target and resolved-address validation,
authentication, scan policy and both gate checks, the Nuclei wrapper, and
the job runner.

Authentication uses Argon2 with JWTs pinned to HS256 and a `token_version`
column for revocation. Login performs the same work whether or not the
account exists, so response timing does not reveal which addresses are
registered. Authentication and verification endpoints are rate limited.

The gate has been verified against a live database and mutation-checked:
disabling the expiry check makes
`scan_is_refused_when_verification_has_expired` fail, so the test is known
to be capable of catching a regression rather than merely passing.

Findings are triaged rather than listed: a real scan of a small production
site returned 32 results, of which three warranted action and nineteen were
inventory. The scanner's own severity is not used as the priority — it
rates a missing Content-Security-Policy as informational, which is wrong
for a report going to a client. Reports are rendered as a single
self-contained HTML file under the agency's name, printable to PDF.

Not built yet: billing, and the testssl/httpx/subfinder wrappers.

### Known limits

- The rate limiters are per-process and keyed on the TCP peer address, so
  they do not survive horizontal scaling and collapse to a single bucket
  behind a reverse proxy. See `crates/api/src/rate_limit.rs`.
- The resolved-address check cannot pin the address for an external scanner
  process, leaving a small DNS-rebinding window between check and scan.
