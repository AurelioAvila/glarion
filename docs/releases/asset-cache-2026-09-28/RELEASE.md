# Asset-cache hotfix — 28 September 2026

PR #34 passed CI and CodeQL and was deployed from merged source commit `0221abf167ec4548300ae4742d4282e6d0b00379`.

- Immutable image: `registry.fly.io/glarion-api@sha256:4ac6e3a80a0ce1f2ab470ae7ebff8a42034940ee7b07623a8ba38d2c07b13b86`.
- Signed artifact: `image-manifest.ps1`. Authenticode status `Valid`, publisher thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`, DigiCert timestamp present. The manifest is data and was never executed.
- Change: versioned CSS and JavaScript URLs make the updated pricing cards, public-check copy and app styles visible to warm browsers through Cloudflare. The frontend asset test accepts versioned stylesheet URLs.
- Validation: CI and CodeQL passed; 23 compiled frontend tests passed locally. A warm production browser displayed the new two-column pricing cards after reload.
- Production smoke: all three Fly machines ran the signed digest; `/health`, `/`, `/pricing.html`, `/app/` and `/sample-report.html` returned HTTP 200. The served HTML references `?v=20260928b` assets.

Previous image: `registry.fly.io/glarion-api@sha256:dca1acdbf3b1321fb65deec61be024e672b625fbe1527e2d2cdcb17d8cde3f03`.
