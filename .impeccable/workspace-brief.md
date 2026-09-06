# Prism extension — workspace and reading surfaces

User: after approving alternative 6 and the implemented landing, said “ok vai avanti” to extending the restyle to the customer workspace and remaining pages.

World: approved Prism from DESIGN.md and .preview/design-alternatives/option-6.png. This extends the system; it is not a new composition election. Workspace mode Operate; account entry Persuade/Operate; guides and legal/report surfaces Read.

Built scope: web/index.html + app.css (auth, list, site, scan, pricing, settings); shared prism.css; privacy/terms CSS; seo.css and four guides; sample-report.css; self-contained generated-report CSS in crates/report/src/html.rs. Homepage appearance remains the already-approved implementation. No deployment or promotion.

Account entry pairs the optical ring with a working form. Workspace uses a quiet white sidebar, pearl page, plum type, lilac active links and rose actions. Mobile retains all navigation links in a wrapping header; forms stack. Security statuses retain text and semantic colors. Reports keep agency identity and no new external resources.

Functional fixes: same-origin API default on local custom ports; explicit aria-current and add-panel expanded state; skip link no longer changes hash route; error notices announce as alerts; password change minlength matches the visible 12-character requirement; onboarding accurately names DNS/file proof and its expiry; settings duplicated title removed.

Validation: typecheck/build; 20 frontend tests including same-origin regression and linked token checks; 21 report tests including escaping/print behavior. Real local sign-in invalid credentials produces expected error from port5186. Authenticated visual testing uses isolated port5192 fixture data and a persistent visible demo label; all demo mutations/scans blocked. No successful real account creation, email delivery, paid checkout, live scans or deployment tested in this pass.

Screenshots: .impeccable/review/workspace/ signin-desktop.png, signup-mobile.png, targets-desktop.png, targets-mobile.png, settings-desktop.png, site-desktop.png, privacy-desktop.png, guide-mobile.png, report-mobile.png. Captures were opened/validated; scope is visible viewports. First desktop sign-in shot precedes a small mask-edge refinement; layout unchanged. Desktop1440x1000, mobile390x844.

Detector: regex fallback; one inherited SEO 2px accent was corrected at source to1px. It cannot certify computed contrast. No new artwork was generated; prior ring reused with original provenance.
