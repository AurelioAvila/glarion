# Signed local backend recovery — 2 October 2026

Backend restored; transactional email remains incomplete. This is not a claim
that registration, account recovery or the complete purchase flow has passed.

- Runtime source commit: `256694c`.
- API and worker run in local Windows scheduled tasks, through the signed native
  launcher, with limited privileges and a one-minute restart interval.
- Existing Supabase Free database retained; nine accounts preserved. The
  dedicated role verifies schema checksums without DDL grants and uses verified
  TLS with the official CA. No migration checksum or customer password changed.
- Existing Cloudflare Tunnel retained, with its Second Take route unchanged.
  Glarion's four old Fly A/AAAA records were replaced by two proxied tunnel CNAME
  records. No email DNS records or paid plans were changed.
- The rotated live Stripe key and existing webhook signing secret are stored
  under CurrentUser DPAPI. The existing webhook now targets the Glarion domain;
  all four event subscriptions are unchanged. Six live EUR prices verified.
- Publisher: Aurelio Avila, certificate thumbprint
  `4F8341A74D16077AE1849DC8B8CAC99F22606754`; DigiCert timestamp present. Native
  launcher, API, worker, Nuclei and signed package manifest verified. Package
  verification passes and rejects a modified static page. The copied signed
  `runtime-manifest.ps1` retains its exact original bytes.
- Manifest SHA-256:
  `4A16523523EB8270AD5D9D52C2FAE19AB21734EC7C25D6C95EE3EEEB6FFD439C`.
- Public smoke: `/health`, `/`, `/app/`, pricing, sample report, setup guide,
  privacy, terms and security contact return HTTP 200. Anonymous targets and
  billing requests return 401; an unsigned webhook returns 401. The public
  check of the owner's Glarion domain returned twelve observations and its
  limited-scope notice. Sign-in and registration screens render correctly.
- Local checks: backend tests, migration regression, Cloudflare proxy parsing,
  frontend tests/build, formatting, Clippy, dependency audit, optimized build,
  native signature/hash verification and tamper rejection passed.

Outstanding: create the approved domain-restricted Resend sending key from the
account containing `glarion.app`, import it encrypted, restart both components,
then verify confirmation/recovery and preview delivery. No real payment was
made. This local hosting requires the PC, operator session and connection to
remain available; it is not an independent always-on cloud server.
