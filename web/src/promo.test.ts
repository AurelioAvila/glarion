import assert from "node:assert/strict";
import test from "node:test";
import { euro, msUntil, parsePromo, promoClock, promoEndLabel, promoPercent, promoThen } from "./promo.js";

const offer = { plan: "solo", interval: "monthly", currency: "eur", regular: 1900, reference: 1900, price: 900, percentOff: 52, firstPeriodOnly: true };
const active = { serverTime: "2026-11-06T22:59:00.000Z", id: "halloween50-2026", status: "active", startsAt: "2026-10-10T00:00:00Z", endsAt: "2026-11-06T23:00:00Z", offers: [offer] };

test("a server response becomes an offer, nothing else does", () => {
  assert.equal(parsePromo(active)?.offers.length, 1);
  for (const bad of [null, {}, "active", { ...active, status: "disabled" }, { ...active, endsAt: "soon" }, { ...active, offers: "x" }, { ...active, id: 7 }]) {
    assert.equal(parsePromo(bad), null, JSON.stringify(bad));
  }
  assert.deepEqual(parsePromo({ ...active, status: "scheduled" })?.offers, [], "a scheduled offer publishes no prices");
});

test("a discount that is not real, or not in euro cents, is never drawn, and nothing valid means no offer", () => {
  for (const broken of [{ price: 1900 }, { price: 1901 }, { reference: 2000 }, { price: 900.5 }, { currency: "usd" }, { interval: "weekly" }, { firstPeriodOnly: false }]) {
    assert.equal(parsePromo({ ...active, offers: [{ ...offer, ...broken }] }), null, JSON.stringify(broken));
  }
});

test("prices and percentages read honestly", () => {
  assert.equal(promoPercent(offer), 52);
  assert.equal(promoPercent({ reference: 1000, price: 801 }), 19, "rounded down, never up");
  assert.equal(euro(950), "€9.50");
  assert.equal(euro(17000), "€170");
  assert.equal(promoThen({ ...offer, interval: "monthly" }), "First month, then €19/month.");
  assert.equal(promoThen({ ...offer, interval: "yearly", regular: 35000 }), "First year, then €350/year.");
});

test("the deadline is the last minute on sale, Rome time, on the server's clock", () => {
  const rome = new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Rome", dateStyle: "short", timeStyle: "medium" });
  assert.equal(rome.format(Date.parse(active.endsAt) - 1000), "06/11/2026, 23:59:59");
  assert.match(promoEndLabel(active), /^6 November 2026/);
  assert.equal(msUntil(active, active.endsAt, 0), 60_000);
  assert.ok(msUntil(active, active.endsAt, 60_000) <= 0);
  assert.equal(msUntil(active, active.endsAt, -5_000), 60_000, "negative elapsed time cannot extend the offer");
  assert.deepEqual(promoClock(27 * 86_400_000 + 13 * 3_600_000 + 5 * 60_000 + 12_000), ["27", "13", "05", "12"]);
  for (const ms of [999, -5000, Number.NaN]) assert.deepEqual(promoClock(ms), ["00", "00", "00", "00"]);
});
