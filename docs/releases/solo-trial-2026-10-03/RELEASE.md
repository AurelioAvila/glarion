# Solo free trial — 3 October 2026

First-time Solo subscribers start with a 14-day free trial. Checkout still
collects a card; the subscription cancels instead of continuing unpaid if no
payment method is present when the trial ends. Accounts with billing history,
Studio and Agency are unchanged. Landing, pricing and plan pages say so before
checkout.

## Package

Based on the 2 October growth-counter release, which master already contains.
Changed entries: `api.exe`, `web/dist/app.js`, `web/landing.html`,
`web/pricing.html`, `web/plans.css`. The worker, Nuclei and launcher are the
previously signed binaries.

- `api.exe` SHA-256 `697D0386E909CA7FC9FA4FBB3AAD763DA30495F2946DEE094E98107A6F2E3346`
- Signed manifest SHA-256 `7741591DBF6FFAA35D69D62DE976AD64A67A39659910FE965E30459EFACD0699` (`runtime-manifest.ps1`, data only)

## Checks

- `cargo fmt --check`, Clippy with warnings denied, API billing tests including
  the trial rule; frontend type check and 25 tests.
- Publisher signature and timestamp on every packaged binary and the manifest;
  `api --verify` and `runner --verify` accept the package; a modified static
  file is rejected.
- After restart: local and public `/health` 200; home, pricing, how-it-works,
  sample report, app shell and assets 200; the pricing page and app bundle
  show the trial; anonymous checkout and unsigned webhook are refused; a public
  check returns twelve observations.

The previous package is kept beside the live one as `release.bak-20261003` for
rollback. No checkout was completed.
