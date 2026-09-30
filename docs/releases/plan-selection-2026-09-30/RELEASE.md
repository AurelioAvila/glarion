# Glarion v0.4.2 — Select a plan and continue with confidence

Every marketing plan is now a complete clickable offer with audience descriptions, factual feature lists, a clear site allowance and a visible action. Monthly/yearly controls show the actual billed total and saving. The selected paid plan and interval remain visible through account entry and email confirmation in the same browser, then lead to billing review with an explicit checkout action. Existing subscriptions change through Stripe's billing portal.

## Validation

- TypeScript check and build; all 24 frontend tests pass, including validated and expired plan preferences, blocked storage and the account destination.
- CI, Rust format/clippy, backend integration tests and CodeQL pass on source `33ec7b5dc7956a57b9a342585c0a1f6e2fb0a533`: [CI](https://github.com/AurelioAvila/glarion/actions/runs/36766335360), [CodeQL](https://github.com/AurelioAvila/glarion/actions/runs/36766331227).
- Desktop, 390px and 320px checks: no horizontal overflow; plan actions remain at least 48px high. Keyboard selection reaches signup with the expected plan.
- Isolated browser fixtures verified the confirmation redirect into Studio yearly billing review, an explicit checkout request with `studio/yearly`, and an existing Solo subscription changing through the portal. No real payment was made.
- Fifteen distinct marketing destinations and all section anchors resolve. Live Agency yearly selection reaches signup at EUR 750/year.
- Read-only production Stripe price verification confirms all six active EUR offers and their single-month/single-year recurrence: Solo 19/170, Studio 39/350, Agency 99/750. Prices exclude VAT.

## Signed distribution

- Source PR: [#40](https://github.com/AurelioAvila/glarion/pull/40); merge `a109d02fc0da396a598ccf4f559df0b5ba393910`.
- Immutable image: `registry.fly.io/glarion-api@sha256:5e1a73cae9831ca39be5ae6bc3e98facc975a3a65cc2d849aa5470bba5a10d08`.
- Signed manifest: `image-manifest.ps1`, SHA-256 `91BA8EE3E01F693A7A2ADECFC4442A475714D7022BE7D7046F4866C39FF7CB15`.
- Authenticode status Valid; publisher Aurelio Avila, certificate thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`; trusted DigiCert timestamp present.
- Deployment used `scripts/deploy-signed.ps1`, which verifies publisher, timestamp and configuration hash before using the immutable image.
- All three Fly machines have the signed digest; application health and rolling smoke checks pass.

The publisher signature binds the final image and deployment configuration. No unsigned CI deployment is enabled. Plan preferences are device-local and expire after seven days; confirmation in another browser falls back to the normal workspace. No conversion uplift is claimed.
