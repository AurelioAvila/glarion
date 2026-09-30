# Glarion landing simplification — 30 September 2026

PR #38 passed CI and CodeQL and was merged as `6f9e02d0f904dc77c28717b7361497a3dc82627e`.

- Immutable image: `registry.fly.io/glarion-api@sha256:cf92368803e47c7ed7ee318d4bd246bc4bb7681e0e56abe3de658784a6977e5b`, built from `53f9b93a94c065d7574c106e505dc5019c32c9c3`. Build inputs were checked against merged master and match exactly.
- Signed artifact: `image-manifest.ps1`, SHA-256 `A617EB7156E5657D7921FAF4916919E45DD1938B64B47469AABFDEBF799BBC72`. Authenticode status `Valid`, publisher Aurelio Avila, thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`, DigiCert timestamp present. The manifest was validated as data and was never executed. Configuration SHA-256: `F41702BE3FF25E3E6ED72B490AB67CA8F62BE8132D3AB1CDE843D3E78D65F471`.
- Changes: preserve the approved hero; replace the fictional portfolio overview and long technical/marketing sections with the free check, a labeled sample-report excerpt, three setup steps, compact pricing and short FAQs. Product guides stay accessible in a native footer disclosure. Body copy is 17–18px and form notes 15px; mobile controls stack. Landing assets use `?v=20260930`.
- Validation: TypeScript check/build and 23 compiled frontend tests passed locally; complete CI and both CodeQL analyses passed. Desktop, 390px and 320px layouts have no horizontal overflow. Empty-domain recovery, native FAQ disclosure and signup destination were verified in the browser. All local link destinations exist.
- Production: signed rolling deployment succeeded. All three Fly machines run the new digest and retain `MAIL_REPLY_TO=hello@glarion.app`. `/health`, `/`, `/pricing.html`, `/app/` and `/sample-report.html` returned HTTP 200. The public page displays the simplified content and new CSS asset version.

Rollback image and configuration: `../reply-to-2026-09-28/image-manifest.ps1`.

No conversion uplift is claimed. Use the existing public-check, signup and checkout attribution to measure results separately.

Production browser smoke: a public check of example.com completed with 12 observations, result actions and optional email capture visible. No account or email was submitted.
