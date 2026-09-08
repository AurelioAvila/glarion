# Prism and acquisition measurement — 8 September 2026

Deployed to glarion.app after local validation and publisher-signature verification.

- Image: `registry.fly.io/glarion-api@sha256:0c97e2bf5a2f0adce08c85805dbc0e697a128fcbc33c11560073b19d3669fed0`
- Source candidate: `041c11d` (includes the latest master fixes).
- Signature: detached image-digest manifest `image-manifest.ps1`, Authenticode SHA-256, publisher Aurelio Avila, RFC3161 DigiCert timestamp; verified before deployment. The manifest is data, not an executable deployment command.
- Deployment uses the exact immutable digest, not a rebuilt image or mutable tag. All three existing Fly machines reference this digest after deployment.
- Validation: 296 backend tests with dedicated local PostgreSQL, 22 frontend tests, Clippy with warnings denied, formatting, and successful production image build.
- Browser: desktop and 390px mobile landing/report; no horizontal overflow in report; landing to report and public check to signup work. No browser script errors observed.
- Production smoke check: limited public check of glarion.app returned 12 observations. Our browser session used `?growth=off`; no fake signup, payment or ownership event was submitted.
- Private operator report: `/usr/local/bin/growth_report`, available through authenticated Fly SSH; business data is not exposed through a public endpoint or committed here.

The anonymous counters begin with this deployment and are operation counts, not visitor/cohort conversion rates. See the growth plan for attribution limits. New demonstration videos are prepared locally and have not been uploaded.

Unsigned source deployment helpers and the automatic CI deployment job are disabled in this source candidate. Future releases must build, sign their final image digest and use `scripts/deploy-signed.ps1`. The local helper validates publisher, timestamp and deployment-configuration hash before release. This does not automatically enforce a signature policy on independently administered cloud infrastructure.
