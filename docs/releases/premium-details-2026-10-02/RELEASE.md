# Glarion v0.4.3 — Clear priorities and visible recommendations

Studio is highlighted with a Recommended badge and distinct styling on the landing, pricing page and account billing view. This is an editorial recommendation, not a claim about customer adoption. The accessible marketing link names include the badge; clickable offers and monthly/yearly selection remain intact.

The landing report excerpt now puts its high-priority finding in a tinted, bordered container with a labelled badge. Dashboard and generated report priorities have consistent, legible bordered badges. The sample retains its metadata, acquisition links and printable report behavior.

## Validation

- TypeScript check/build, 24 frontend tests and 23 report tests pass.
- Desktop, 390px and 320px checks show no horizontal overflow. Marketing actions remain over 48px high, yearly Studio selection reaches signup at EUR 350/year, and the isolated account billing view shows the recommendation. No real payment was made.
- Badge text contrast ranges from 5.54:1 to 6.95:1. Priority CSS in the sample matches the production renderer.
- Fifteen marketing destinations and section anchors pass locally; all fifteen production destinations and health return HTTP 200.
- Source `b800d15be9fa7798cf8dc6714e556ddf33c37b6b`: [CI](https://github.com/AurelioAvila/glarion/actions/runs/36942971455) and [CodeQL](https://github.com/AurelioAvila/glarion/actions/runs/36942968730) succeed.
- Production browser readback confirms the Studio badge, accessible recommendation and new priority treatment. No price or payment behavior changed.

## Signed distribution

- Source and release record PR: [#42](https://github.com/AurelioAvila/glarion/pull/42).
- Immutable image: `registry.fly.io/glarion-api@sha256:15a9ebe181c08dd5c9825c090b66a77d32df05b111c7ab52380ce788df291be7`.
- Signed manifest: `image-manifest.ps1`, SHA-256 `6A0914F80EAA864235E1BA74CF05C6FD870ECC875CF0A6C4719D8CEC8603BD3F`.
- Authenticode status Valid, publisher Aurelio Avila, certificate thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`, DigiCert timestamp present.
- Deployment used `scripts/deploy-signed.ps1`, which verifies the publisher, timestamp and deployment configuration hash. All three machines use the signed digest; rolling health and smoke checks succeed.
- Image built from the source commit above. The follow-up commit adds only this release record and signed manifest; these are excluded from the image by `.dockerignore`.

The immutable image and configuration are bound to the verified publisher signature. Unsigned CI deployment remains disabled. No conversion uplift is claimed.
