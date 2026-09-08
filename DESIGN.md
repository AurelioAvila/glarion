---
name: Glarion Prism
description: Pearl surfaces, plum typography and optical glass for website monitoring.
colors:
  site-bg: "#faf7fb"
  surface-raised: "#ffffff"
  site-surface: "#f2edf8"
  site-surface2: "#eae1f5"
  site-line: "#dcd2e5"
  site-soft: "#e9e1ee"
  site-text: "#2d103a"
  site-muted: "#695174"
  site-quiet: "#745e7d"
  prism-accent: "#bc294a"
  prism-violet: "#7345b2"
  prism-coral: "#e74767"
  site-signal-clear: "#176a4f"
  site-signal-warning: "#815b14"
  site-signal-alert: "#a33428"
typography:
  display:
    fontFamily: "Manrope, sans-serif"
    fontSize: "clamp(3.5rem, 6vw, 5.9rem)"
    fontWeight: 650
    lineHeight: 1.01
    letterSpacing: "-0.04em"
  headline:
    fontFamily: "Manrope, sans-serif"
    fontSize: "clamp(2rem, 3.5vw, 3.2rem)"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-0.04em"
  body:
    fontFamily: "Manrope, sans-serif"
    fontSize: "16px"
    lineHeight: 1.65
  button:
    fontFamily: "Manrope, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 600
    lineHeight: 1.4
rounded:
  control: "8px"
  panel: "14px"
  tag: "6px"
components:
  button-primary:
    backgroundColor: "{colors.prism-accent}"
    textColor: "white"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "0.9rem 1.3rem"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.site-text}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "0.9rem 1.3rem"
---

# Design System: Glarion Prism

## Overview

**Creative North Star: "Prism".** The built system follows user-selected alternative 6, approved with “la 6 mi piace.” The subsequent “ok vai avanti” approved extending Prism to the customer workspace and all remaining pages. Pearl surfaces, dark plum type, coral emphasis and translucent optical artwork give the marketing page its identity; operational and reading surfaces apply the same palette with quieter composition. This supersedes the agency-journal proposal across the implemented surfaces. Appearance approval does not authorize deployment.

Source of truth: the final cascade in `web/landing.css` and markup in `web/landing.html`; reference comp: `.preview/design-alternatives/option-6.png`.

Shared non-landing tokens live in `web/prism.css`, with surface rules in `web/app.css`, `web/seo.css`, `web/privacy.css` and `web/terms.css`. Generated reports embed `crates/report/src/report.css` through `crates/report/src/html.rs`; `crates/report/examples/sample_report.rs` produces the public sample from the same renderer. Workspace scope and limitations remain in `.impeccable/workspace-brief.md`. The report refinement is recorded in `.impeccable/report-brief.md`, with reviewed desktop, mobile and browser-generated PDF artifacts under `.impeccable/review/report/`. Its local finish review resolved the print identity/footer and long agency-header issues; it does not validate account, payment or live scan workflows. Work remains local.

## Colors

Primary actions use the deeper rose accent for white button text; coral supplies large headline emphasis. Violet supports interactive details and lilac tints organize supporting surfaces. Pearl backgrounds, plum text and muted plum descriptions carry ordinary reading. Existing green, amber and red signals retain their semantic roles in checker results.

In shared styles, `--bg`, `--sink`, `--rule`, `--ink`, `--ink-2` and `--ink-3` map respectively to the frontmatter's site background, surface, line, text, muted and quiet colors; `--raise` uses the raised white surface. `--accent` maps to rose and `--violet` to violet. The generated report uses the same plum, muted plum, divider and lilac palette on white, preserving its separate severity colors and agency identity.

**The Evidence Rule.** Status color accompanies readable status text; illustrations and fictional data remain explicitly identified.

## Typography

Manrope is self-hosted at `/fonts/manrope.ttf`, with the bundled OFL license. It supplies display, body and controls; inherited technical result annotations may retain the system monospace stack. Headlines use compact spacing and balanced wraps. Hero emphasis is upright coral type. Body copy stays readable, with section introductions limited to 65 characters per line where possible.

Workspace copy uses 15px/1.65 Manrope and compact headings (`clamp(1.85rem, 3vw, 2.55rem)`). Guides and legal pages use 16px/1.7 Manrope. Report body uses 16px/1.65 with the stack `Manrope, Segoe UI, sans-serif`: the public sample loads local Manrope through `prism.css`, while standalone reports make no new font requests and use the available fallback. Report titles use `clamp(2.3rem, 4.7vw, 3.8rem)` at 650 weight; visible evidence uses wrapping system monospace. Print body is 10pt, with explanations at 9.5pt.

## Layout

The landing desktop container is capped at 88rem with 5rem total horizontal clearance. At 1100px and below, clearance becomes 3rem; below 38rem it becomes 2rem. The sticky header measures 90px on desktop and 74px below 52rem.

Below 52rem, content and checker stack and the illustrative portfolio sidebar disappears. Navigation keeps sign-in and the account action. Below 38rem, the ring enters document flow between the hero copy and sample overview; the overview table keeps a 630px minimum width inside its own keyboard-focusable horizontal scroll region. The checker input and button remain side by side. Comparison content scrolls locally with a visible mobile hint. Mobile display type uses `clamp(2.8rem, 12vw, 4.3rem)`.

Workspace navigation uses a fixed 224px white sidebar and lilac active links with `aria-current`; at 900px it becomes a sticky wrapping header retaining navigation links. Main content caps at 78rem. Account entry pairs the reused ring with a half-width form, hiding the artwork and expanding the form at 900px. At 46rem, forms and facts stack and tabs wrap. Guides cap their shell at 66rem and article at 48rem; legal reading content caps at 52rem. These reading surfaces use an 80px header.

Reports use Read mode: a 1080px white document with `clamp(1.4rem, 5vw, 4rem)` padding, an agency/client/domain/date cover, a plum summary and linked priorities before the findings. Consequence and proposed action sit in two columns with a 2rem gap; at 700px and below they stack, page rounding and shadow disappear, and the date enters normal flow. Agency text wraps with 12rem of right clearance for the date on desktop and in print; mobile resets that clearance to zero. Evidence remains visible and wraps without horizontal scrolling.

Print uses A4 with 15mm top/side and 22mm bottom margins. The cover, action plan, findings and individual inventory items avoid internal page breaks. Up to eight reference observations follow findings naturally; more than eight start a new page. A bottom-center page margin box repeats domain, agency and date in a separate identity band; dynamic identity text is CSS hex-escaped. Save controls and report navigation disappear, but the public sample's fictional-data note stays visible. Print removes the page shadow, radius and screen padding.

## Elevation & Depth

Workspace content is flat: white ledgers and sidebar on pearl, with lilac form groups and selection. The command palette uses modal lift (`0 24px 60px #2d103a33`). Reports use a restrained document shadow (`0 20px 65px #3921470d`) on pearl; mobile and print remove it.

The illustrative portfolio floats on a restrained violet shadow (`0 18px 54px #52337316`). The checker and final action panel are flat lilac surfaces. Local decorative artwork at `web/prism-ring.png` provides optical depth through masking and multiply blending. Its one-time settling animation lasts 1.1s; reduced-motion preference disables animation, transitions and smooth scrolling.

## Shapes

Controls have softly rounded corners, larger panels use the panel radius, and sample status tags use the smaller tag radius. Thin dividers organize tables and later page sections. The retained brand mark sits in a plum circle.

## Components

Operational actions have a 44px minimum height; inputs have a 46px minimum, white fill, lilac border and violet focus treatment. Workspace focus is violet, error notices announce as alerts, and the skip link moves focus without changing the hash route. Reading callouts use thin violet or neutral dividers. Legal print removes navigation; generated reports keep A4 layout, severity labels and findings together and hide save controls. Shared styles honor reduced motion.

Primary actions use rose fill and deepen on hover. Secondary actions and account navigation use plum text with a muted lilac border, gaining a lilac background on hover. Main actions and checker controls have a 48px minimum height.

The checker uses a labeled light input, dark text, violet caret and an explicit red error message; loading, results and live announcements remain functional. Native FAQ disclosure semantics remain intact. Focus remains visible: generic focus is violet while the more specific inherited link, button and input rules retain the green outline.

The portfolio overview is a fictional illustration, with a visible sample label and an actual link to the sample report. Its sidebar and tags do not imply implemented dashboard functionality. The ring is decorative and hidden from assistive technology. All new artwork and font requests resolve locally.

The report summary leads with a conclusion and three truthful counts: need attention, worth a decision and for reference. Up to three actionable priorities link to their full findings, with an all-actions link when needed. Each finding pairs a readable priority label with “Why it matters,” a lilac “What to do” panel and visible “Observed evidence”; missing guidance is explicit. Reference observations are not passed security tests. Scope and limits remain part of the document. The save button is a 44px plum control; report links use violet hover and visible violet focus. Report smooth scrolling respects reduced motion.

## Do's and Don'ts

- **Do** preserve the selected pearl, plum, coral and lilac hierarchy and local Manrope asset.
- **Do** preserve focus, reduced motion, fictional-data labeling and local table scrolling.
- **Do** apply the approved Prism palette across workspace and reading surfaces while retaining their operational density, evidence and print behavior.
- **Do** keep report priorities linked to their visible evidence, retain agency identity and the printable fictional sample label, and preserve honest reference counts.
- **Don't** add invented report scores, deadlines, passed-check claims or security guarantees; standalone report typography must not introduce new font requests.
- **Don't** treat illustrative portfolio controls as delivered dashboard features or appearance approval as deployment authorization.
