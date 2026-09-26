# Sample-report journey and contact update — 26 September 2026

Deployed to glarion.app from merged PR #29 after CI and publisher-signature verification.

- Source commit: `5425782e5bc6e5110aa7e02155b201d6895641a5`.
- Immutable image: `registry.fly.io/glarion-api@sha256:b9095e9836df85707498687052ebadc79e2a284bd1fb2ba2b47216340b8ab98e`.
- Signed artifact: `image-manifest.ps1`. Authenticode status `Valid`; publisher certificate thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`; timestamp present. The manifest is signed data, not a deployment script.
- CI: PR #29 run 128 passed, including frontend types/tests, formatting, Clippy and backend tests. The local Windows `tsx` runner could not start because `uv_os_get_passwd` returned ENOMEM; CI ran the frontend tests successfully.
- Visual verification: sample-report next step reviewed at desktop and 390px mobile; the pricing link resolved, there was no document overflow, and the promotion is hidden under print media.
- Production smoke: all three Fly machines use the signed digest; app health check passed; public sample report shows the new next step; landing, terms and privacy link to `hello@glarion.app`; sign-in loads without browser errors; the limited public check of glarion.app returned 12 observations.

Previous deployed digest, for rollback reference: `registry.fly.io/glarion-api@sha256:90001d0c20d21da7d61cce32507b17515afd27954df0174b0a74c1b63389a031`. Any rollback is a separate release action and must follow the signing rule.
