import test from "node:test";
import assert from "node:assert/strict";
import { checkoutSettled, returnedFromCheckout } from "./checkout-return.js";

test("only Stripe's success return carries the checkout session", () => {
  assert.equal(returnedFromCheckout("#/plan?checkout=cs_live_a1"), true);
  assert.equal(returnedFromCheckout("#/plan?plan=studio&checkout=cs_live_a1"), true);
  assert.equal(returnedFromCheckout("#/plan"), false, "cancel_url");
  assert.equal(returnedFromCheckout("#/plan?plan=studio&interval=yearly"), false);
});

test("the page waits until a plan, a trial or a refused trial is recorded", () => {
  assert.equal(checkoutSettled({ plan: "free", state: "none" }), false, "webhook not here yet");
  assert.equal(checkoutSettled({ plan: "free", state: "blocked", blocked_reason: "canceled" }), false, "an earlier plan that ended");
  assert.equal(checkoutSettled({ plan: "studio", state: "active" }), true);
  assert.equal(checkoutSettled({ plan: "solo", state: "trialing" }), true);
  assert.equal(checkoutSettled({ plan: "free", state: "blocked", blocked_reason: "trial_already_used" }), true);
});
