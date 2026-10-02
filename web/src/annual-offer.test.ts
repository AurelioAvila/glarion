import assert from "node:assert/strict";
import test from "node:test";
import { annualOffer } from "./annual-offer.js";
import { readFileSync } from "node:fs";

test("annual offers compare real totals, save at least 25%, and match both marketing pages", () => {
  const offers = [
    ["solo", 19, 170, 228, 58, 25, "14.17"],
    ["studio", 39, 350, 468, 118, 25, "29.17"],
    ["agency", 99, 750, 1188, 438, 36, "62.50"],
  ] as const;
  for (const [plan, monthly, yearly, standardYear, saving, discount, monthlyEquivalent] of offers) {
    assert.deepEqual(annualOffer(monthly, yearly), { standardYear, saving, discount, monthlyEquivalent });
    assert.ok(yearly <= monthly * 12 * .75);
    for (const page of ["landing.html", "pricing.html"]) {
      const html = readFileSync(new URL(`../${page}`, import.meta.url), "utf8");
      assert.ok(html.includes(`data-plan="${plan}" data-monthly="${monthly}" data-yearly="${yearly}"`));
      assert.ok(html.includes(`Cost of 12 monthly payments: <s data-original>€${standardYear}</s>`));
      assert.ok(/<script type="module" src="\/plans\.js\?/.test(html));
    }
  }
  for (const prices of [[0, 170], [19, 0], [19, 228], [NaN, 170], [19, Infinity]]) {
    assert.throws(() => annualOffer(prices[0]!, prices[1]!), RangeError);
  }
});
