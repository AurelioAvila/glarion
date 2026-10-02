# Local recovery — 2 October 2026

Status: prepared and tested locally; **not deployed**. Public health still returns
HTTP 525. The existing database and its nine users are preserved.

## Runtime

The intended path is the existing Cloudflare Tunnel → `127.0.0.1:8187` → the
Windows API, with a separate Windows scan worker and the existing Supabase Free
database. Preserve the tunnel's other application routes and all email DNS.
No inbound firewall port is needed. Availability depends on this PC being on,
the operator being signed in, and the internet connection staying available.

- `TRUST_PROXY_CLIENT_IP=cloudflare` trusts `cf-connecting-ip` and binds the API
  to loopback. Fly's previous proxy mode remains supported.
- `DATABASE_MIGRATIONS=verify` checks applied migration status and repository
  checksums without requesting schema privileges. Schema changes are operator
  work; never alter historical migration bytes or production checksums.
- The dedicated runtime database role has scoped table privileges, no DDL or
  role administration, and uses the official Supabase CA with `verify-full`.
- `.runtime/private/settings.dpapi` uses Windows CurrentUser DPAPI and an ACL
  restricted to the operator and SYSTEM. Never commit or print its contents.
  Fresh JWT signing material requires existing users to sign in again.

## Release gate

Build `scripts/Local-Service.cs` with the installed .NET Framework compiler.
Sign the final API, worker, Nuclei and native launcher with the user's publisher
certificate and a trusted timestamp. Package the built frontend and Supabase CA
with them. Create `manifest.ps1` containing one `# files=` JSON dictionary of
relative paths to SHA-256 hashes, then sign that manifest after packaging.
The manifest is data and must never be executed.

The native launcher checks Windows trust, the pinned publisher, the manifest
timestamp, required entries, path confinement and all file hashes before
decrypting settings or starting a component. `local-service.exe api --verify`
and `local-service.exe runner --verify` validate without starting either service.
Check that modifying a packaged static file causes verification to fail, then
restore its exact original bytes. Any later change requires re-signing.

Only after these checks, configure `GlarionLocalAPI` and `GlarionLocalWorker` to
run the signed launcher directly with `api` and `runner`, respectively, using
the existing interactive limited user and restart settings. Do not weaken
PowerShell policy. The tasks remain disabled while the package is incomplete.

## Completion checks

1. Reconnect SimplySign Desktop: the provider currently reports its device not
   ready. Do not publish an unsigned launcher or incomplete manifest.
2. Create the authorized Resend `glarion-local-mail` key with Sending access for
   `glarion.app` only, and store it in DPAPI. The browser account currently
   open does not contain this domain, although the connector sees it verified.
3. The rotated live Glarion Stripe key and existing webhook secret are encrypted
   locally. Six active EUR prices have been verified: Solo 19/month or 170/year,
   Studio 39/month or 350/year, Agency 99/month or 750/year. Update the existing
   Glarion webhook URL from the deleted Fly hostname to
   `https://glarion.app/api/billing/webhook` when the new service is ready;
   preserve its four event subscriptions and avoid duplicate endpoints.
4. Confirm supervised API/worker startup, local health, configured email and
   Stripe; then add Glarion to the existing tunnel and replace only its old
   Fly A/AAAA records with proxied tunnel CNAME records.
5. Verify public HTTPS health, landing, app authentication, email confirmation
   and recovery, preview email, plan selection and signed webhook processing.
   Do not make real purchases to test. Record receipts before declaring success.

Local verification completed: backend tests including the migration-history
regression and Cloudflare address parsing, frontend tests and build, Clippy,
formatting, dependency audit and optimized API/worker build. Final native package
verification correctly stops on the unsigned launcher; its success and tamper
checks remain pending the signing session.
