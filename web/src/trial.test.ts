import assert from "node:assert/strict";
import test from "node:test";
import { firstChargeDate, longDate, parsePrices, priceFor, subscribeNowLine, timeLeft, trialLine, trialProgress } from "./trial.js";

const answer = {
  server_time: "2026-10-14T12:00:00.000Z",
  trial_enabled: true,
  trial_days: 3,
  prices: [
    { plan: "studio", interval: "monthly", amount: 3900, currency: "eur", tax_behavior: "exclusive" },
    { plan: "studio", interval: "yearly", amount: 35000, currency: "eur", tax_behavior: "exclusive" },
  ],
};

test("only a well-formed answer becomes a price list, and odd prices are dropped", () => {
  const list = parsePrices(answer)!;
  assert.equal(list.trialEnabled, true);
  assert.equal(priceFor(list, "studio", "yearly")?.amount, 35000);
  assert.equal(priceFor(list, "agency", "monthly"), null, "a price the server did not publish is not invented");
  for (const bad of [null, {}, { ...answer, trial_days: 0 }, { ...answer, trial_enabled: "yes" }, { ...answer, server_time: "now" }, { ...answer, prices: "x" }]) {
    assert.equal(parsePrices(bad), null, JSON.stringify(bad));
  }
  const odd = parsePrices({ ...answer, prices: [{ plan: "solo", interval: "monthly", amount: 19.5, currency: "eur" }, { plan: "solo", interval: "weekly", amount: 1900, currency: "eur" }, { plan: "solo", interval: "monthly", amount: 1900, currency: "usd" }] });
  assert.deepEqual(odd?.prices, []);
});

test("the first charge is three days after the server's now", () => {
  const list = parsePrices(answer)!;
  assert.equal(firstChargeDate(list).toISOString(), "2026-10-17T12:00:00.000Z");
  assert.equal(firstChargeDate(list, 60_000).toISOString(), "2026-10-17T12:01:00.000Z");
  assert.equal(firstChargeDate(list, -60_000).toISOString(), "2026-10-17T12:00:00.000Z", "a wrong clock cannot move it earlier");
  assert.equal(longDate(firstChargeDate(list)), "17 October 2026");
});

test("the trial line says what happens, when, and for how much", () => {
  const list = parsePrices(answer)!;
  const monthly = priceFor(list, "studio", "monthly")!;
  const on = firstChargeDate(list);
  assert.equal(trialLine(3, monthly, on), "Free for 3 days, then €39/month from 17 October 2026. Cancel before then and nothing is charged.");
  assert.equal(subscribeNowLine(monthly), "Or subscribe now: €39 charged today, no trial.");
  const promo = { plan: "studio", interval: "monthly" as const, regular: 3900, reference: 3900, price: 1900 };
  assert.equal(trialLine(3, monthly, on, promo), "Free for 3 days, then €19 for the first month, charged on 17 October 2026, and €39/month after that. Cancel before then and nothing is charged.");
  assert.equal(subscribeNowLine(monthly, promo), "Or subscribe now: €19 charged today for the first month, no trial.");
  // An "offer" that is not below the Stripe price is ignored.
  assert.equal(trialLine(3, monthly, on, { ...promo, price: 3900 }), trialLine(3, monthly, on));
  const yearly = priceFor(list, "studio", "yearly")!;
  assert.match(trialLine(3, yearly, on), /€350\/year from 17 October 2026/);
});

test("time left and progress read plainly", () => {
  const end = "2026-10-17T12:00:00.000Z";
  const at = (iso: string) => Date.parse(iso);
  assert.equal(timeLeft(end, at("2026-10-15T07:00:00.000Z")), "2 days 5 hours left");
  assert.equal(timeLeft(end, at("2026-10-16T12:00:00.000Z")), "1 day left");
  assert.equal(timeLeft(end, at("2026-10-17T07:30:00.000Z")), "4 hours left");
  assert.equal(timeLeft(end, at("2026-10-17T11:30:00.000Z")), "Less than an hour left");
  assert.equal(timeLeft(end, at("2026-10-18T00:00:00.000Z")), "Ending now");
  assert.equal(trialProgress(end, 3, at("2026-10-14T12:00:00.000Z")), 0);
  assert.equal(trialProgress(end, 3, at("2026-10-16T00:00:00.000Z")), 0.5);
  assert.equal(trialProgress(end, 3, at("2026-10-20T00:00:00.000Z")), 1);
});
