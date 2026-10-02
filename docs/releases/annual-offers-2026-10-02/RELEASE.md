# Glarion v0.4.4 — Clear annual savings and simpler setup

Yearly offers show the cost of twelve monthly payments struck through, a conservative savings percentage, the actual yearly charge and a rounded monthly equivalent. The comparison is labelled explicitly; it is not presented as a previous annual price. Landing, full pricing and account billing use the same calculation. The six active Stripe prices were verified read-only and remain unchanged.

| Plan | Twelve monthly payments | Annual charge | Saving | Monthly equivalent |
| --- | ---: | ---: | ---: | ---: |
| Solo | EUR 228 | EUR 170 | EUR 58; over 25% | EUR 14.17 |
| Studio | EUR 468 | EUR 350 | EUR 118; over 25% | EUR 29.17 |
| Agency | EUR 1188 | EUR 750 | EUR 438; over 36% | EUR 62.50 |

Studio's star recommendation sits above its card. This is an editorial recommendation, not a customer-popularity claim. All paid tools remain the same across plans; site allowance differs.

The setup, free-check, certificate and email-policy guides are shorter and lead to a clear next step. Public configuration and full scans are distinguished, account confirmation and domain verification are explained, and technical scan limits remain available. SPF/DMARC observation wording describes the requested policy without guaranteeing delivery; classification and authorisation gates are unchanged. Definitions were checked against [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) and [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489).

Pricing FAQ structured data matches visible answers. Mobile navigation keeps every guide link reachable. The privacy notice describes the existing seven-day selected-plan preference; collection behavior did not change. Sitemap dates were updated for the pages changed in this release.

## Validation

- TypeScript check/build, 25 frontend tests, 13 preview tests, five sitemap tests and Rust formatting pass locally.
- Source `542a4f4c2d75d189854961791a3d5713976069a1`: [complete CI](https://github.com/AurelioAvila/glarion/actions/runs/36946395282) and [CodeQL](https://github.com/AurelioAvila/glarion/actions/runs/36946390210) succeed. CI includes Clippy, workspace tests and database-backed scan-gate tests; their execution is asserted.
- Desktop, 390px and 320px UI checks show no horizontal overflow. The isolated checkout receives `studio/yearly`; no production payment was made.
- All 15 HTML pages have valid local destinations, anchors and structured data. All 15 production marketing destinations, health, security.txt and the new offer module return HTTP 200.
- Production browser readback confirms annual comparisons, the star recommendation and Studio signup at EUR 350/year with email-confirmation instructions.

## Signed distribution

- Source and release record PR: [#43](https://github.com/AurelioAvila/glarion/pull/43).
- Immutable image: `registry.fly.io/glarion-api@sha256:3c4ee04349618cfdeded51dc9a6220170a7df5f28538c49512a71c1a98152861`.
- Signed manifest: `image-manifest.ps1`, SHA-256 `78EE988658CEEFBF0C813502243C9205D95F4EA1F9EB596A4591F6FA303E4A14`.
- Authenticode status Valid; publisher Aurelio Avila, certificate thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`; trusted DigiCert timestamp present.
- Deployment used `scripts/deploy-signed.ps1`, which verifies the publisher signature, timestamp and deployment configuration hash. All three machines use the signed digest; rolling health and smoke checks succeed. One worker remains stopped under the existing scaling policy.
- The image is built from the source commit above. The subsequent record commit adds only this document and the signed manifest, excluded from the image by `.dockerignore`.

Unsigned CI deployment remains disabled. No conversion uplift is claimed.
