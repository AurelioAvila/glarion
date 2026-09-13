# Prism restyle — historical validation record

## Delivery

The user selected visual direction 6, later extended to the customer area and other pages.

- Homepage and account entry: pearl, lilac, coral, locally hosted Manrope and an optical ring.
- Customer area: sites, details, scans, plans and settings, with accessible mobile navigation.
- Consistent guides, privacy, terms and sample report. Legal text was unchanged.
- Generated reports: matching palette, responsive layout and print support, without new external requests.

## Functional improvements

- Customer-area requests use the same origin in local previews, removing the implicit port 8080 fallback.
- The skip link moves focus without changing the active screen.
- Active navigation and the add-site form expose explicit accessible states.
- Errors are announced to assistive technology; minimum new-password length matches the instructions.
- Onboarding correctly describes DNS/file verification and its 30-day validity.
- Removed the duplicate settings heading.

## Evidence recorded at this stage

- Build and TypeScript checks passed.
- 20 frontend tests passed, including request-origin regression and linked stylesheet-token checks.
- 21 report-generator tests passed, including escaping and print behavior.
- Deliberately invalid credentials received the expected local-service response without requests to port 8080.
- Keyboard navigation moved focus to content and preserved the current route.
- The add-site form and links were checked; no horizontal overflow was found in the mobile views examined.
- Pages and new assets returned HTTP 200.
- Independent review: ready to ship within the visible areas of nine delivered captures.
  The automated detector checked text only; it did not certify browser-computed contrast.

## Previews and limitations

Historical local app: http://localhost:5186/app/#/signin

Historical customer-area demo: http://127.0.0.1:5192/app/#/targets

The separate demo uses explicitly labeled fictional data and rejects mutations,
payments and scans. Its downloadable sample report is independent of the list
counts. The demo server lives in `.preview`, excluded from production packaging.

Actual account creation, email delivery, payments and real scans were not tested
at this stage. Nothing had been published at that point. Earlier security
corrections were preserved; the restyle was not a new comprehensive security audit.

## Report clarity and layout — 7 September 2026

- Public sample and generated reports share a generator: summary, top three
  actions linked to details, separate consequence/remediation sections, visible
  evidence, and observations separated from passed checks.
- The sample uses explicitly fictional data and retains that label in PDF.
  Social metadata and canonical URL were preserved. Public printing uses a
  CSP-compatible local script; browser printing and Ctrl/Cmd+P remain available
  for the sandboxed document.
- A4 layout was checked across three pages in Chrome 152. Identity sits in a
  footer margin box, separate from content. Long names were checked on desktop,
  phone and PDF. Repeating margins depend on CSS page-margin-box support and
  were not verified in other browsers.
- 23 report tests, 20 frontend tests and TypeScript checks passed. Hostile-text
  coverage includes a closing style tag; margin metadata is fully CSS-escaped.
- Independent review found the screen design ready and the PDF margin/long-title
  corrections resolved within the reviewed local scope.
- Historical preview: http://localhost:5186/ and
  http://localhost:5186/sample-report.html . The customer demo used the updated
  generator; no publication had occurred at this stage.

## Public release — 7 September 2026 (Europe/Rome)

The user approved proceeding after reviewing the previews.

- Revision 087663c was deployed to Fly as release v63 from
  codex/restyle-security-20260906. Immutable image:
  registry.fly.io/glarion-api@sha256:e98c7d2f6619010e045d449f294a14a3328647f9bf916e1b40fb47f9956c7ddb.
- Full local verification passed: 292 Rust tests, 20 frontend tests, TypeScript,
  formatting, Clippy and dependency audits. Scan-gate tests ran against a dedicated
  database. After disk exhaustion, compilation was repeated serially without debug
  symbols following cleanup of this project's Cargo artifacts only.
- App and worker were updated; Fly checks passed. No migration or secret change
  was needed. Previous release: v62,
  registry.fly.io/glarion-api:deployment-01M1NRWMDDH9SDXR95Z37CV7ZJ.
- Public domain: health returned 200. Report, app, CSS, JavaScript, image and font
  returned 200 with SHA-256 matching local artifacts. The landing was checked in
  the browser. Cloudflare rewrites the contact email and injects its decoder,
  so the public landing hash differs from the source file.
- Unauthenticated profile/scans/targets/billing returned 401 with Cache-Control:
  no-store. No production payments, emails or new real scans were performed.
- The branch was saved to GitHub; master was still at the previous base at that
  time. Deployment used the CLI without Discord announcements or social posts.
  The recorded follow-up was to merge the restyle before later master deployments.
- Public pages: https://glarion.app/ and https://glarion.app/sample-report.html .
  The site was no longer limited to the earlier local previews.

This document records historical checks and deployment state, not a certification
of the current release. Legacy filenames are retained to preserve inbound links.
