# Pricing and onboarding release — 28 September 2026

PR #33 passed CI and CodeQL and was deployed from merged source commit `6e9edc61bb9de81be3e9df61577d710b5891dddd`.

- Immutable image: `registry.fly.io/glarion-api@sha256:dca1acdbf3b1321fb65deec61be024e672b625fbe1527e2d2cdcb17d8cde3f03`.
- Signed artifact: `image-manifest.ps1`. Authenticode status `Valid`, publisher thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`, DigiCert timestamp present. The manifest is data and was never executed.
- Validation: API unit tests 63 passed; orchestrator unit tests 140 passed; frontend TypeScript and build passed; 23 compiled frontend tests passed. CI ran the API integration suite with its dedicated test database. Desktop and mobile pricing, signup and in-app plans were reviewed.
- Production smoke: all three Fly machines ran the signed digest; `/health`, `/`, `/pricing.html` and `/app/` returned HTTP 200. A public check for `example.com` returned a partial result.
- A warm browser still reused previously cached CSS and JavaScript despite the new HTML. PR #34 adds versioned asset URLs; that follow-up requires its own signed release.

Previous image: `registry.fly.io/glarion-api@sha256:6ba004d795f236ee0b6da7498ee23d371f2f504f6b19128a14c3fbe21375ab19`.
