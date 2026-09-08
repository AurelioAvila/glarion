# Glarion: acquisition experiment, 8 September 2026

## Baseline (checked 8 September, not an established trend)

- Cloudflare HTTP analytics, previous 24 hours: 188 unique IPs, about 1,170 requests. Not a count of qualified people. Web Analytics showed insufficient data.
- YouTube P0zn84DoQv8, since publication 7 September: 13 views, 7 seconds average watch time, 10% viewed, 4 thumbnail impressions. Do not interpret 25% CTR at this sample size.
- DEV article `turn-a-website-security-finding-into-a-client-ready-next-step-5cch`: fewer than 25 views, zero reactions/comments.
- Live landing/report still differed from the approved local Prism design.

## Measurement shipped in this candidate

Daily anonymous channel/operation counters. The browser sends only an allowlisted source category. No visitor IDs, raw URL, email or domain are saved in counters. Session storage retains the first channel for the tab; DNT/GPC, unavailable storage, local previews and `?growth=off` suppress browser measurement.

Use `scripts/growth-report.sql` privately against the application database. All-source confirmed accounts, currently verified domains and subscription statuses come from existing business tables; payment attribution is **not** inferred from browser redirects. Active/trialing/past-due statuses must remain separate. A subscription row does not prove a settled payment.

Counters begin only after deployment/migration, do not reconstruct past traffic and are not a person-level funnel. Repeat page loads/checks count again; ownership renewals count as new verification operations. Signup retries for an existing email do not count. Returning tabs and email-link round trips may lose channel attribution. Client labels can be spoofed; neither these counters nor an IP count proves a human visit. Writes have a short timeout and can undercount during outages. Page-event rate limiting uses the existing separate `growth` namespace. There is no public read endpoint.

## Two distinct demonstrations

1. Report decision: show one finding immediately, then impact, next step and evidence. CTA: sample report.
2. Workflow: verified domains, cadence and agency-branded reporting. CTA: limited public check; make the paid/full-scan boundary clear.

Use the approved existing voice/footage locally; no paid video generation. Each needs its own final review and duplicate check before release. Preserve fictional-data labels. Keep the existing introductory upload. For vertical Shorts, include literal #shorts in title/description.

## Agency feedback: five real conversations

Select agencies that maintain client sites; ask one person per agency. Do not claim they are customers or fabricate endorsements. No messages have been sent by this work.

English invitation:

> I’m building Glarion for agencies that maintain client websites. Could I ask for five minutes of candid feedback on a sample security report? I’d like to understand whether the next action is clear and how you currently explain findings to clients. No sales call required: https://glarion.app/sample-report.html?utm_source=referral

Interview prompts:

1. What would you do first after reading this report?
2. What would you need to verify before sending it to a client?
3. How do you handle this today, and what takes the most time?
4. Where would setup or ownership verification cause difficulty?
5. Would this fit your current workflow? What is missing?

Record anonymous themes and observed difficulties. Request separate permission before publishing a quote or logo.

## Seven-day decision

Review one complete week after the release, with deployment date recorded. Compare qualified feedback, completed checks, actual new accounts and verified domains; inspect errors before changing acquisition copy. Report raw denominators and avoid claiming causal improvement from tiny samples. Do not change pricing or buy ads on the current evidence.
