# Reporting a vulnerability

Email **aurelio_11@outlook.it**. That address is monitored; there is no
`security@` alias, because glarion.app publishes no MX records and mail to one
would bounce.

Include the URL or endpoint, what you did, and what came back. A request and a
response are worth more than a scanner's severity label. If you need to send
anything sensitive, say so first and we will agree on a channel.

You will get an acknowledgement within three working days and an assessment
within ten. If something is exploitable against live accounts it is fixed and
deployed before anything else in the queue.

## Scope

In scope: `glarion.app`, the API under `/api`, the dashboard under `/app`, and
this repository.

Out of scope: reports produced by running an automated scanner against the site
and pasting its output, missing headers on endpoints that return no HTML, rate
limits reached by exceeding them deliberately, and anything requiring a victim
to be running malware already.

Do not test against domains you do not own. Full scans are gated on proof of
ownership for that reason — the gate is the product, so please do not treat
bypassing it as an invitation to scan somebody else's site.

## What we ask

Give us a chance to ship a fix before you publish. We will credit you when the
fix goes out unless you would rather stay anonymous.

There is no bug bounty. This is a small product with one person behind it, and
promising money we have not set aside would be worse than saying so plainly.
