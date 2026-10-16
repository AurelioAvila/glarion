#!/usr/bin/env node
// Writes web/llms.txt and web/llms-full.txt (served by the static fallback like any file in web/).
//
// Plans, prices and the FAQ are read from the SoftwareApplication/FAQPage JSON-LD of web/pricing.html
// (the page that also renders them), the site allowances from Plan::max_targets in billing.rs, the page
// list and titles from web/sitemap.xml. `--check` fails when the committed files are out of date, so a
// price or allowance change cannot leave them behind:   node scripts/build-llms.mjs [--check]
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";

const ORIGIN = "https://glarion.app";
const root = new URL("../", import.meta.url);
const read = (f) => readFileSync(new URL(f, root), "utf8");
const unescapeHtml = (s) => s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");

const pricing = read("web/pricing.html");
const blocks = [...pricing.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map((m) => JSON.parse(m[1]));
const graph = blocks.flatMap((b) => b["@graph"] ?? [b]);
const app = graph.find((n) => n["@type"] === "SoftwareApplication");
const faq = graph.find((n) => n["@type"] === "FAQPage");
assert.ok(app && faq, "pricing.html lost its SoftwareApplication or FAQPage JSON-LD");

const billing = read("crates/api/src/billing.rs");
const sites = Object.fromEntries(
  [...billing.slice(billing.indexOf("pub fn max_targets")).matchAll(/Plan::(\w+) => (\d+),/g)].slice(0, 4).map((m) => [m[1], Number(m[2])]),
);
assert.deepEqual(Object.keys(sites), ["Free", "Solo", "Studio", "Agency"], "Plan::max_targets changed shape");

// Each offer must agree with the allowance the code enforces.
for (const offer of app.offers) {
  if (offer.name === "Free") continue;
  assert.ok(offer.description.toLowerCase().includes(numberWord(sites[offer.name])), `${offer.name}: JSON-LD site allowance differs from billing.rs (${sites[offer.name]})`);
}
function numberWord(n) {
  return { 1: "one", 5: "five", 10: "ten", 40: "forty" }[n] ?? String(n);
}

const titleOf = (path) => unescapeHtml(read(`web/${path}`).match(/<title>([^<]+)<\/title>/)[1]);
const pages = [...read("web/sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]).filter((u) => u !== `${ORIGIN}/`);
const pageLinks = pages.map((u) => `- [${titleOf(u.slice(ORIGIN.length + 1))}](${u})`);

const plan = (o) => `- ${o.name}: ${o.price === "0" ? "EUR 0" : `EUR ${o.price} a month`}. ${o.description}`;
const core = [
  "# Glarion",
  "",
  "> Glarion is website security monitoring for digital agencies and freelancers. It checks client websites on a schedule, separates actionable findings from scanner noise and produces reports under your own name and logo. It is operated by Aurelio Avila, an individual.",
  "",
  "## What it does",
  "",
  `- Free public check, no account: ${ORIGIN}/ . It makes three GET requests (the homepage, robots.txt and security.txt), reads the TLS certificate expiry and looks up SPF and DMARC records. It probes nothing and guesses no paths.`,
  "- Full scans: only on domains whose owner has proved control with a DNS TXT record or a hosted token file. The proof lasts 30 days and is checked again when a scan runs. Scans check for known vulnerability fingerprints, at most 20 requests per second, with intrusive, brute-force, fuzzing and denial-of-service template categories excluded, and at most six full scans per site per rolling 24 hours.",
  "- Weekly or monthly scheduled checks, email alerts when results change, and reports (self-contained HTML, printable to PDF) with the agency's name and logo.",
  "- Findings keep their evidence and are sorted into Act, Review and Inventory. Glarion is automated monitoring, not a penetration test, and it does not guarantee that a website is secure or apply fixes.",
  "",
  "## Plans (EUR, read from the structured data of the pricing page)",
  "",
  ...app.offers.map(plan),
  "",
  "Prices exclude VAT. Yearly billing is cheaper; the pricing page shows the yearly totals. Checkout and cancellation are hosted by Stripe, so no card detail reaches Glarion's servers. New Solo subscribers get a trial, with the terms shown before they pay.",
  "",
  "## Pages",
  "",
  ...pageLinks,
  "",
  "## Contact and policies",
  "",
  `- Contact: hello@glarion.app. Security reports: ${ORIGIN}/.well-known/security.txt`,
  `- [llms-full.txt](${ORIGIN}/llms-full.txt)`,
  "",
];
const full = [...core, "## Frequently asked questions", "", ...faq.mainEntity.flatMap((q) => [`### ${q.name}`, "", q.acceptedAnswer.text, ""])];
const files = { "web/llms.txt": core.join("\n"), "web/llms-full.txt": full.join("\n") };
for (const text of Object.values(files)) assert.doesNotMatch(text, /illustrative|anti-?cheat/i);

if (process.argv.includes("--check")) {
  for (const [file, text] of Object.entries(files)) {
    assert.equal(read(file).replace(/\r\n/g, "\n"), text, `${file} is out of date: run node scripts/build-llms.mjs`);
  }
  console.log("llms.txt and llms-full.txt are up to date.");
} else {
  for (const [file, text] of Object.entries(files)) writeFileSync(new URL(file, root), text);
  console.log("Wrote web/llms.txt and web/llms-full.txt.");
}
