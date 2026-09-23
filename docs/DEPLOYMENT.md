# Production deployment (manual, signed)

The Fly Actions deploy job is disabled with `if: ${{ false }}`. The unsigned
source helper exits without deploying. The active path is
[`scripts/deploy-signed.ps1`](../scripts/deploy-signed.ps1), which deploys an
immutable image digest only after checking a timestamped Authenticode signature
from publisher Aurelio Avila and the hash of `fly.toml`. The
[September 8 release record](releases/growth-2026-09-08/RELEASE.md) shows a
completed deployment using this path. A skipped Actions deploy run does not
establish that the live site is stale.

For each new deployment:

1. Record the exact source commit (`git rev-parse HEAD`). Run
   `bash scripts/ci-local.sh` and check the GitHub CI run for that commit.
   Build and push the candidate image with the approved operator process;
   capture its immutable `registry.fly.io/glarion-api@sha256:…` digest. Confirm
   that image came from the recorded commit. Do not use a mutable tag or let
   Fly rebuild from source at deploy time.
2. Create a new manifest using the format of
   [`image-manifest.ps1`](releases/growth-2026-09-08/image-manifest.ps1):
   comment lines for `image=`, `config-sha256=` and `source-commit=`. Compute
   the configuration hash with `Get-FileHash fly.toml -Algorithm SHA256`. Sign
   the finished manifest with the user's publisher certificate and a trusted
   timestamp using the approved local signing session. Keep private keys,
   passwords and authentication codes out of the repository. The manifest is
   signed data; never execute it.
3. Verify `Get-AuthenticodeSignature` reports `Valid`, publisher thumbprint
   `4F8341A74D16077AE1849DC8B8CAC99F22606754`, and a timestamp. Then run
   `pwsh -File scripts/deploy-signed.ps1 -Manifest <signed-manifest-path>`.
   The helper rechecks the signature and configuration hash before passing
   the exact image digest to Fly.
4. After Fly reports success, confirm all production machines use that digest
   and are healthy. Request `https://glarion.app/health`, the home page and a
   representative public content page; check the expected content and HTTP
   status. Record deployment time, source commit, digest, manifest path and
   SHA-256, CI run, machine status and smoke results in a new release record
   under `docs/releases/`. A failed smoke check requires investigation or
   rollback before declaring the deployment complete.

The helper checks publisher, timestamp, manifest fields and `fly.toml` hash.
Image provenance, CI result and post-deploy health are operator checks; the
helper does not prove those on its own. Do not re-enable the Actions deploy
job while it still builds unsigned source.
