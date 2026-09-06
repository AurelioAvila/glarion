# Turn a website security finding into a client-ready next step

A scanner can identify an observation. It cannot, by itself, settle every business decision that follows.

For an agency managing client websites, a useful report needs to bridge that gap. The reader should be able to identify the affected website, understand the evidence and decide who should investigate next.

Here is a practical reporting structure we use in Glarion. The examples below are fictional and illustrate communication, not findings about a real customer's website.

## Start with the observation

Compare these two statements:

> Your website is insecure.

> The homepage response observed during this check did not include a Content-Security-Policy header.

The second statement is narrower, but more useful. It identifies an observable condition without claiming that an attack occurred or that the whole website has been assessed.

Include the domain, the check date and enough context to reproduce the observation. Avoid putting credentials, session tokens or unnecessary personal data into evidence that will be forwarded to a client.

## Explain the consequence separately

For a missing CSP, the explanation might be:

> This response did not declare a Content Security Policy through an HTTP header. Check whether the page supplies a policy through HTML before concluding that none exists. An appropriate policy can reduce the impact of injected content.

This explains why the finding matters without claiming that a single header prevents every attack. Severity is a useful signal, but it should not replace an explanation of the risk in the website's context.

## Make the next step concrete

A recommendation such as “fix security headers” leaves too much work to the reader.

A more useful next step is:

> Ask the development team to test a report-only Content Security Policy, review the resources the site needs and investigate violations before enforcing it.

Report-only mode lets the team observe violations without enforcing that policy. Centralized collection also requires reporting configuration; simply naming the mode is not an implementation plan. The [MDN reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only) covers the relevant header and reporting directives.

Agree on an owner and a follow-up check. Do not mark a finding resolved merely because a change was requested.

## Separate actions, decisions and reference observations

Not everything belongs in one list of problems:

- **Actions** have a concrete proposed fix or investigation.
- **Decisions** need context from the people responsible for the website. Publishing a security contact, for example, requires choosing a monitored address and a process for handling reports.
- **Reference observations** preserve useful context, such as an observed HTTPS endpoint. They are not a count of security tests passed.

Keeping these categories separate helps a client understand what requires a response. It also avoids inflating a report with information that looks more urgent than it is.

## Keep the limits visible

A report describes what was observed within a particular scope and at a particular time. A clean result is not proof that the website has no vulnerabilities today.

Keep this explanation close to the findings, and retain it in exported documents. A forwarded PDF should still make sense without the application that produced it.

## A checklist before sending

1. Can the reader identify the domain, date and scope?
2. Is each observation separated from assumptions?
3. Is the consequence understandable without scanner terminology?
4. Does each recommendation provide a next step?
5. Are context-dependent decisions distinct from reference observations?
6. Is there a way to verify the follow-up work?
7. Are the limits visible in both the web report and PDF?

We build Glarion for agencies that need this workflow. You can inspect the [fictional sample report without signing up](https://glarion.app/sample-report.html?utm_source=devto&utm_medium=organic&utm_campaign=agency_launch_202609&utm_content=client_report_article). Glarion provides a limited free public check; full scans require a paid plan and current proof of domain control. It does not replace a manual penetration test.

What information do you find most useful when turning a technical observation into work a client can approve?
