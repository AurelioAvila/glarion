# Free-plan activation update — 26 September 2026

Deployed to glarion.app from merged PR #31 after CI and publisher-signature verification.

- Source commit: `42b4c6b357030b3b5a0739a62827be2987ae644e`.
- Immutable image: `registry.fly.io/glarion-api@sha256:6ba004d795f236ee0b6da7498ee23d371f2f504f6b19128a14c3fbe21375ab19`.
- Signed artifact: `image-manifest.ps1`. Authenticode status `Valid`; publisher certificate thumbprint `4F8341A74D16077AE1849DC8B8CAC99F22606754`; DigiCert timestamp present. The manifest is signed data, not a deployment script.
- Validation: PR #31 CI and CodeQL passed; local TypeScript check and build passed; browser smoke covered empty account, verified Free and verified Solo. The local Windows `tsx` runner could not start because `uv_os_get_passwd` returned ENOMEM; CI ran the test suite successfully.
- Production smoke: all three Fly machines use the signed digest; health returned 200; `/app/` returned 200; the served JavaScript contains the new first-run and Free-plan copy.

Previous deployed digest, for rollback reference: `registry.fly.io/glarion-api@sha256:b9095e9836df85707498687052ebadc79e2a284bd1fb2ba2b47216340b8ab98e`. A rollback requires its own signing and verification.
