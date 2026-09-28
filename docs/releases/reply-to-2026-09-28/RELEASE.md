# Glarion v0.4.0 — 28 September 2026

PR #36 passed CI and CodeQL and was merged as `fde3bafc1d8dc01e8c4b82bffc0a0369a564caeb`.

- Change: public-check emails now use `hello@glarion.app` as Reply-To. Cloudflare Email Routing forwards that address to its verified destination.
- Deployment: reused the immutable application image `registry.fly.io/glarion-api@sha256:4ac6e3a80a0ce1f2ab470ae7ebff8a42034940ee7b07623a8ba38d2c07b13b86`, built from `0221abf167ec4548300ae4742d4282e6d0b00379`. Only the Fly configuration changed. The previous `MAIL_REPLY_TO` secret was removed.
- Signed release artifact: `image-manifest.ps1`, SHA-256 `717800243EDC6B9B92340DE7BE45A6009F4DEE5474945CA8058D1C15E01F1B4B`. Authenticode status `Valid`, publisher thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`, DigiCert timestamp present. The manifest was validated as data and was never executed. Fly configuration SHA-256: `F41702BE3FF25E3E6ED72B490AB67CA8F62BE8132D3AB1CDE843D3E78D65F471`.
- Production verification: all three Fly machines have the signed image digest and `MAIL_REPLY_TO=hello@glarion.app`; `/health`, `/`, and `/pricing.html` returned HTTP 200. A public-check preview for `example.com` was delivered to `hello@glarion.app` at 13:20 Europe/Rome. The received message shows `Reply-To: hello@glarion.app`, signed by `glarion.app`, and includes the sample report and pricing links.

Rollback configuration and image reference: `../asset-cache-2026-09-28/image-manifest.ps1`.
