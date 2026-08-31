<h1 align="center">Glarion</h1>

<p align="center">
  <strong>Website security monitoring for agencies that manage client sites.</strong><br>
  Verify ownership, run controlled scans and turn noisy tool output into reports clients can act on.
</p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/AurelioAvila/glarion/ci.yml?branch=master&style=for-the-badge&label=security%20checks" alt="Security checks status">
  <img src="https://img.shields.io/badge/tests-208-52C78D?style=for-the-badge" alt="208 automated tests">
  <img src="https://img.shields.io/badge/API-Rust%20%2B%20Axum-F0F0F2?style=for-the-badge&logo=rust&logoColor=111111" alt="Rust and Axum API">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-proprietary-7C7E88?style=for-the-badge" alt="Proprietary license"></a>
</p>

> **Built around authorization, not assumptions.** Full scans require current DNS or `.well-known` ownership proof, are checked again at execution time, and reject private, loopback and cloud-metadata destinations. Every queued scan retains an authorization trail.

| Proof point | What is enforced |
|---|---|
| **Target authorization** | Two independent ownership gates, including expiry at execution time |
| **SSRF resistance** | Resolved-address validation and address pinning close DNS-rebinding paths |
| **Safe scan policy** | Detection-only allowlist, rate limits and no fuzzing, brute force or denial-of-service templates |
| **Verified quality** | 208 tests, including live-database integration and mutation checks for the authorization gate |
| **Actionable output** | Findings are normalized and triaged into self-contained client reports |

The source is public for technical review and transparency, not for reuse. Glarion is proprietary software; see [LICENSE](LICENSE).

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

## Two tiers, and why only one is gated

A full scan probes: it requests paths a site never advertised and tries
known vulnerability fingerprints against them. That is the act the gate
above exists for.

Reading a site's DNS records, its TLS configuration, the response headers
on its front page, and the two files it publishes for automated readers is
not that. It is what a browser or a search-engine crawler collects on an
ordinary visit, and there is nothing to authorise about reading what a site
broadcasts to anyone. `POST /api/preview` does exactly that much and no
more — one front-page request, two well-known files, `GET` only, no
redirects followed — and needs neither an account nor a verified domain.

Keeping them apart matters commercially as much as legally. Before it,
nobody could see a single result without first editing DNS for a client's
domain, which is to say before we had shown them anything at all.

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
- `crates/report` — report rendering. Triage lives in `orchestrator`,
  since deciding which findings matter is domain knowledge rather than
  presentation, and the worker needs it too.
- `web/` — the dashboard: TypeScript compiled with `tsc`, no framework and
  no bundler, matching the rest of the portfolio. Driven from the keyboard:
  `⌘K`/`Ctrl-K` or `/` opens the command palette, `j`/`k` walk the list.
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

Email uses Resend, the provider already used elsewhere in the portfolio:
set `RESEND_API_KEY`, `MAIL_FROM`, and `PUBLIC_URL` (where confirmation
links should point — taken from configuration rather than from a request
header, since a link built from an attacker-supplied Host is how
confirmation mail becomes phishing). With no key configured, messages are
logged instead of sent and the confirmation link appears in the API output,
so the signup flow can be exercised locally without a mail account.

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
the whole suite with the integration tests active. 208 tests at present.

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
bash scripts/dev-db.sh url       # connection URL for the test database
bash scripts/dev-db.sh url dev   # connection URL for the app's database
bash scripts/dev-db.sh destroy   # delete it entirely
```

The cluster holds two databases. `glarion_test` is what the integration
tests use, and they TRUNCATE every table in it; `glarion_dev` is what the
running app uses. Keeping them apart is why a test run no longer destroys
the accounts and scan history you were working with.

## Status

Working: ownership verification, target and resolved-address validation,
authentication, scan policy and both gate checks, the Nuclei wrapper, and
the job runner.

Registration collects a name and date of birth alongside the address; the
date of birth exists to check the account holder is old enough to enter a
paid contract, which is the only reason to hold it. An account cannot be
used until the address is confirmed through an emailed link, and neither
signup nor sign-in reveals whether an address is already registered.

Authentication uses Argon2 with JWTs pinned to HS256 and a `token_version`
column for revocation. Login performs the same work whether or not the
account exists, so response timing does not reveal which addresses are
registered. Confirmation links are stored only as a hash, expire after 24
hours, and stop working once used. Authentication and verification
endpoints are rate limited.

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

Sites can be put on a weekly or monthly schedule. A schedule is standing
authorization, so it can only be set while ownership is proved, and the
scheduler refuses — loudly — once that proof lapses rather than quietly
scanning on. Notification is sent only when a result differs from the one
before it: a weekly "still three issues" teaches people to filter the
sender, and then the message that mattered goes unread too.

## Plans

| Plan | Price | Sites | Automatic checks |
|---|---|---|---|
| Free | — | 1 | No |
| Studio | 39 EUR / month, 390 / year | 10 | Weekly or monthly |
| Agency | 99 EUR / month, 990 / year | 40 | Weekly or monthly |

Priced per account with a site allowance, not per site. The competition
charges from about 90 USD per application, which is a sensible model for a
company protecting its own domain and the wrong one for an agency looking
after twenty of somebody else's.

The site allowance is derived from the plan rather than stored beside it:
two copies of the same number drift apart the moment either is written
without the other, and the one that drifts is the one enforcing a paid
limit.

Checkout and cancellation are hosted by Stripe, so no card detail reaches
these servers.

Copy `.env.local.example` to `.env.local` and fill it in; `dev-api.sh`
loads it. That file is gitignored, and secrets belong in it rather than on
a command line, where they end up in shell history. With none of it set the
billing endpoints refuse rather than granting anything, and the rest of the
product works unchanged.

**Before taking money:** a subscription is continuous business activity,
which in Italy needs a P.IVA and VAT handling. Stripe Tax computes the
rates; the filing obligation is not something software solves.

Not built yet: the testssl/httpx/subfinder wrappers.

### Known limits

- The rate limiters are per-process and keyed on the TCP peer address, so
  they do not survive horizontal scaling and collapse to a single bucket
  behind a reverse proxy. See `crates/api/src/rate_limit.rs`.
- The resolved-address check cannot pin the address for an external scanner
  process, leaving a small DNS-rebinding window between check and scan.
