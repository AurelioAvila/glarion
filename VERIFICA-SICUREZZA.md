# Glarion — security review and corrections, 6 September 2026

This is a historical review. At the time of the initial checks, the changes were
local to `codex/restyle-security-20260906`, based on commit `372ea89`, and had
not been deployed. The deployment update at the end records the subsequent release.

Scope: code review, local tests and reading public website responses. No production
load testing or attacks were performed. This review does not certify immunity to attacks.

## Implemented corrections

| Finding | Previous behavior | Correction and evidence |
|---|---|---|
| Incomplete destination filtering | Some special-purpose addresses passed is_public_ip, including 0.1.2.3, IPv6 translation/transition addresses and reserved space. Actual routing depends on infrastructure; access to internal systems was not demonstrated. | Reject all of 0/8, handle IPv4-mapped addresses consistently, and use a conservative IPv6 policy: native global unicast with explicit exclusions. Boundary and public-address tests added. |
| Report CSP overwritten | The page wrapper replaced the report sandbox policy with the more permissive dashboard policy. No exploitable XSS was found; an additional defense was lost. | Apply the general policy only when no specific policy is present. Test responses through the wrapper. |
| API responses lacked an explicit cache prohibition | Results, profiles and session responses lacked a general storage prohibition. | Apply Cache-Control: no-store to the API router and verify unauthenticated responses. Static resources retain revalidation. |

The IPv6 policy deliberately excludes special-purpose, translation and tunnel
ranges, even where legitimate uses exist. It is a website-destination policy,
not a universal IANA classification library.
Reference: [IANA registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

## Validation evidence at the time of review

- 290 Rust tests passed against a dedicated local database, including 15 scan-gate
  tests, password recovery/change, email change and account deletion.
- Clippy passed across all targets without warnings; Rust formatting passed.
- 19 frontend tests, TypeScript checks and compilation passed.
- cargo audit and npm audit reported no known vulnerabilities at that check date.
- Automated secret scanning found no confirmed production secret. Two false
  positives were reviewed: a disposable CI database URL and a package SHA-512
  integrity value. This was not a full Git-history or service-secret review.
- The public check was exercised through the local preview against glarion.app:
  results and limitations were visible without an account or email submission.
- JSON-LD was preserved byte-for-byte from the base; the CSP-authorized hash still
  matched. No remote scripts, trackers or fonts were added.

## Boundaries and threats considered

Automated STRIDE models are generic checklists, not proven vulnerabilities.
Their scores are not product CVSS ratings. The Glarion maintainer owns mitigation;
operational checks must be completed before those controls are claimed as active.

| Boundary | Threats considered | Defenses and verification limits |
|---|---|---|
| Browser → authentication/API | Credential theft, token forgery, CSRF, brute force, escalation | Argon2, fixed-algorithm HMAC, token_version revocation, HttpOnly/Secure cookies, CSRF checks and shared rate limits. MFA/passkeys were not implemented in the reviewed project. |
| API → database | Injection, cross-user access, audit tampering | Parameterized queries and owner filters checked in reviewed flows; authorization and jobs written together. Production database privileges and backup protection were not inspected. |
| Worker → websites/DNS | SSRF, rebinding, scanner abuse, unavailability | Repeated ownership checks, validated addresses, pinning for internal requests, Nuclei local-network restriction, rates and timeouts. Operational worker egress rules still require confirmation. |
| Finding → report/browser | XSS, exfiltration, stored data | Escaping, report attachments, preserved report-specific CSP and no-store. |
| Proxy → API | IP forgery, bypassed or colliding rate limits, DDoS | Fly-Client-IP trusted only behind a trusted proxy; Cloudflare fronts the site. Verify the Cloudflare/Fly chain with multiple legitimate IPs and direct-origin access. Do not trust CF-Connecting-IP without proving the originating proxy. |
| Operators → infrastructure/providers | Account/key theft, deployment tampering, data loss | Cloud-account MFA, key rotation, least privilege, alerts and tested backup recovery were not verified in this session. |

The checklists include two generic threats with DREAD ≥7: credential theft (8.2)
and API impersonation (7.2). The first calls for planning MFA/passkeys and checking
cloud-service MFA. The second maps here to signing-secret and session protection:
no user API-key access mechanism was found in the product. Signatures, cookies
and revocation are covered by code; operational key custody remains to be checked.

## Operational priorities recorded by this review

1. Deploy the validated corrections and verify public responses after release.
2. Verify service MFA, backups with a restore test, error/abuse/dependency alerts,
   origin access and the worker network boundary.
3. Plan user MFA/passkeys and independent review of sensitive flows; verify
   resource limits and hashing under load in staging.

These activities were not declared complete by the initial review. A WAF or an
automated test does not replace authentication, isolation, updates and recoverability.
Reference: [OWASP REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).

## Deployment update — 7 September 2026

The corrections were deployed in Fly release v63, revision 087663c.
Unauthenticated access rejection and Cache-Control: no-store were verified on
the public domain. Report-specific CSP and destination filtering remained covered
by local tests; no new production attacks or scans were performed. The operational
checks above were not declared complete. Details and rollback: [Prism review](VERIFICA-PRISM.md).
