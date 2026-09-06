---
name: Glarion landing
description: A technical journal for evidence-led website monitoring.
colors:
  site-bg: "#f5f3ed"
  site-surface: "#eeece5"
  site-surface2: "#e7e5dd"
  site-line: "#c9c9c0"
  site-soft: "#deded4"
  site-text: "#192b29"
  site-muted: "#4e605b"
  site-quiet: "#596b65"
  site-signal-clear: "#176a4f"
  site-signal-warning: "#815b14"
  site-signal-alert: "#a33428"
  checker-accent: "#cce3bc"
  checker-copy: "#c1d1c9"
typography:
  display:
    fontFamily: "Newsreader, Georgia, serif"
    fontSize: "clamp(3.4rem, 4.8vw, 4.9rem)"
    fontWeight: 450
    lineHeight: 1.02
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Newsreader, Georgia, serif"
    fontSize: "clamp(2.2rem, 3.8vw, 3.7rem)"
    fontWeight: 450
    lineHeight: 1.1
    letterSpacing: "-0.025em"
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "16px"
    lineHeight: 1.65
  navigation:
    fontFamily: '"Segoe UI", sans-serif'
    fontSize: "0.88rem"
    fontWeight: 500
    lineHeight: 1.4
rounded:
  field: "3px"
  action: "6px"
  panel: "8px"
spacing:
  compact: "0.75rem"
  standard: "1rem"
  roomy: "1.5rem"
  panel: "2rem"
  section-mobile: "3rem"
components:
  button-primary:
    backgroundColor: "{colors.site-text}"
    textColor: "{colors.site-bg}"
    rounded: "{rounded.action}"
    padding: "0.8rem 1.15rem"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.site-text}"
    rounded: "{rounded.action}"
    padding: "0.8rem 1.15rem"
  button-check:
    backgroundColor: "{colors.checker-accent}"
    textColor: "{colors.site-text}"
    rounded: "{rounded.action}"
    padding: "0.8rem 1.15rem"
  input-domain:
    backgroundColor: "{colors.site-bg}"
    textColor: "{colors.site-text}"
    rounded: "{rounded.field}"
    padding: "0.66rem 0.75rem"
---

# Design System: Glarion landing

## Overview

**Creative North Star: "The Agency Technical Journal"**

This records the built local landing proposal in `web/landing.html` and `web/landing.css`. It is not a user-approved brand replacement: audience and workflow preferences remain optional unanswered questions. The existing dark dashboard intentionally retains its earlier design and is outside this document's authority.

Ivory paper, forest ink and a literary display face give technical evidence room to be read. Ordinary controls stay compact and explicit, with thin rules organizing the page instead of decoration. The final CSS cascade, rather than superseded declarations earlier in the stylesheet, is the source of truth.

**Key Characteristics:**
- Warm paper and forest ink.
- Serif headlines paired with practical sans-serif controls.
- Flat evidence surfaces and visibly contrasting working areas.

## Colors

The primary palette combines dark green ink with warm neutral paper; semantic results retain separate clear, warning and alert colors.

### Primary
- Forest ink (`site-text`) anchors text, navigation actions and the checker surface.
- Pale leaf (`checker-accent`) identifies the check action and its focus ring on the dark surface.

### Neutral
- Ivory (`site-bg`) is the reading field and input surface.
- Layered paper (`site-surface`, `site-surface2`) supports secondary surfaces and hover states.
- Rule and soft rule (`site-line`, `site-soft`) separate information.
- Muted and quiet ink support descriptions and metadata; checker copy has its own lighter foreground.

**The Contextual Contrast Rule.** Dark working surfaces use their light text and focus treatments; paper surfaces use dark text and green focus treatments.

## Typography

**Display Font:** self-hosted Newsreader with Georgia and serif fallbacks. The normal variable font is served from `/fonts/newsreader.ttf`, with swap loading.

**Body Font:** platform sans-serif; explicit Segoe UI fallbacks are used for navigation and several labels. Monospace remains for technical result metadata, identifiers and finding numbers, not as the display voice.

Display and headline sizes are fluid, with a modest weight and tight tracking. Body text is comfortable and restrained; section descriptions use a 1.75 line height and up to 66ch, while the hero description uses 48ch. Newsreader also distinguishes report totals and plan prices; these numbers use tabular figures.

**The Reading Hierarchy Rule.** Serif typography establishes the main reading hierarchy; forms, navigation and technical annotations remain functional and direct.

## Layout

The main container is at most 78rem with 4rem total desktop gutters. Hero columns balance copy and evidence at 1.1:1; the checker spans both. Main sections use 4.5rem vertical padding and thin top dividers.

At 64rem, gaps and panel padding tighten. At 52rem, the hero, checker, evidence and workflow become single-column; gutters total 2.5rem and sections use 3rem padding. At 38rem, gutters total 2rem, the hero heading is 3.45rem, and the domain field and check action remain side by side with a shrinking field. The comparison keeps its 42rem table width inside a keyboard-focusable horizontal scroller, with a visible mobile hint. Report metrics stay in three columns. Pricing becomes stacked on small screens.

## Elevation & Depth

The visible landing is flat. The report preview and checker explicitly remove inherited shadows; paper boundaries, spacing and tonal contrast create separation. Do not derive a new shadow vocabulary from overridden legacy declarations.

## Shapes

Thin rules and mostly rectangular evidence dominate. Actions have softly rounded corners, fields use a smaller radius, and the checker and closing panel use the larger panel radius. The existing brand mark sits in a circular ink background. This mix reflects function rather than imposing one radius on everything.

## Components

### Buttons

Primary actions use forest ink on paper; secondary and ghost actions are transparent with a thin rule. The checker reverses the scheme with pale leaf on ink. Actions have a minimum height of 44px; the check action and input use 48px. Hover changes background and, for outlined actions, border color. Disabled buttons reduce opacity. Focus outlines remain visible; reduced-motion preferences disable transitions.

### Inputs / Fields

The public domain input uses an explicit visible label, paper background, dark text and caret, a descriptive note, and an error note with a contrasting light red treatment on the dark panel. The result region retains polite live announcements. Preserve these semantics alongside appearance.

### Navigation

The sticky ivory header is 80px high on desktop and 70px below 52rem. Ordinary links use muted sans-serif text; the account action is filled ink. Mobile retains sign-in and the account action while hiding secondary links.

### Evidence and containers

The fictional report is a flat paper sheet with ruled findings, visible textual severity, and a clearly marked sample badge. The working checker is a contrasting full-width panel. Workflow, pricing and FAQ use aligned rows and dividers. The FAQ keeps native disclosure semantics and a visible focus treatment.

## Do's and Don'ts

### Do:
- **Do** preserve the reading hierarchy and contextual contrast treatments.
- **Do** keep semantic status text alongside its color.
- **Do** retain mobile scrolling hints, keyboard focus and reduced-motion behavior.

### Don't:
- **Don't** apply this landing proposal automatically to the existing dark dashboard.
- **Don't** infer user-approved brand preferences from this local implementation.
- **Don't** revive overridden shadows or unused eyebrow styles as new house rules.
