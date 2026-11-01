import assert from "node:assert/strict";
import test from "node:test";
import type { ManagedSubscription } from "./api.js";
import { CANCEL_REASONS, cardLabel, confirmLine, endDate, isEnding, nextLine, priceLabel, statusPill } from "./manage-subscription.js";

const base: ManagedSubscription = {
  product: "glarion",
  plan: "studio",
  plan_name: "Studio",
  interval: "month",
  amount: 3900,
  currency: "eur",
  status: "active",
  trial_end: null,
  current_period_end: "2026-12-01T10:00:00Z",
  cancel_at_period_end: false,
  cancel_at: null,
  payment_method: { brand: "visa", last4: "4242" },
  lifetime: false,
  can_cancel: true,
  can_resume: false,
  sites_used: 3,
  max_sites: 10,
  portal: true,
};

test("the eight reasons are Stripe's own codes, Other last", () => {
  assert.deepEqual(CANCEL_REASONS.map(([code]) => code), [
    "too_expensive", "unused", "missing_features", "switched_service",
    "low_quality", "too_complex", "customer_service", "other",
  ]);
});

test("a renewing plan says when it renews and what it costs", () => {
  assert.equal(statusPill(base).text, "Active");
  assert.equal(priceLabel(base), "€39 / month");
  assert.equal(priceLabel({ ...base, amount: 35000, interval: "year" }), "€350 / year");
  assert.equal(priceLabel({ ...base, amount: 1950 }), "€19.50 / month");
  assert.equal(nextLine(base), "Renews on 1 December 2026.");
  assert.equal(cardLabel(base.payment_method!), "Visa ending in 4242");
  assert.equal(cardLabel({ brand: "link", last4: "0000" }), "Link ending in 0000");
});

test("a cancelled plan names the exact last day and promises no charge", () => {
  const ending = { ...base, cancel_at_period_end: true, cancel_at: "2027-03-12T09:00:00Z", can_cancel: false, can_resume: true };
  assert.equal(isEnding(ending), true);
  assert.equal(endDate(ending), "2027-03-12T09:00:00Z");
  assert.equal(statusPill(ending).text, "Cancelled");
  assert.equal(confirmLine(base), "You keep Studio until 1 December 2026. You won't be charged again.");
  assert.equal(nextLine(ending), "Ends on 12 March 2027. It won't renew and you won't be charged again.");
});

test("a trial ends at the trial's end with nothing charged", () => {
  const trial = { ...base, status: "trialing", trial_end: "2026-11-04T10:00:00Z", current_period_end: "2026-11-04T10:00:00Z" };
  assert.equal(statusPill(trial).text, "Free trial");
  assert.equal(nextLine(trial), "Your free trial ends on 4 November 2026, then €39 / month plus any VAT.");
  assert.equal(confirmLine(trial), "You keep Studio until your free trial ends on 4 November 2026. You won't be charged.");
});

test("no subscription and a failed payment read plainly", () => {
  const none = { ...base, plan: "free", plan_name: "Free", status: "none", amount: null, currency: null, interval: null, current_period_end: null, payment_method: null, can_cancel: false, portal: false };
  assert.equal(statusPill(none).text, "Free plan");
  assert.equal(priceLabel(none), null);
  assert.match(nextLine(none), /free plan/);
  assert.equal(statusPill({ ...base, status: "past_due" }).tone, "warn");
});
