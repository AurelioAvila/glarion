import assert from "node:assert/strict";
import test from "node:test";
import { accountDestination, cleanPlanChoice, readPlanChoice, rememberPlanChoice } from "./plan-choice.js";

test("a validated plan survives email confirmation until review; stale or hostile choices cannot reach billing", () => {
  const values = new Map<string, string>();
  Object.assign(globalThis, { localStorage: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  } });
  for (const plan of ["solo", "studio", "agency"]) {
    for (const interval of ["monthly", "yearly"]) {
      const choice = cleanPlanChoice(plan, interval);
      assert.ok(choice);
      rememberPlanChoice(choice);
      assert.deepEqual(readPlanChoice(), choice);
      assert.deepEqual(readPlanChoice(), choice, "a page reload must not lose the confirmation round-trip");
      assert.equal(accountDestination(choice), "#/plan", "review the choice; never open checkout on login");
    }
  }
  for (const [plan, interval] of [["free", "monthly"], ["<script>", "yearly"], ["solo", "invalid"], ["solo", null]]) {
    assert.equal(cleanPlanChoice(plan, interval), null);
  }
  for (const at of [Date.now() - 8 * 86400000, Date.now() + 86400000]) {
    values.set("glarion.signup.plan", JSON.stringify({ plan: "solo", interval: "monthly", at }));
    assert.equal(readPlanChoice(), null);
  }
  values.set("glarion.signup.plan", "broken json");
  assert.equal(readPlanChoice(), null);
  rememberPlanChoice(null);
  assert.equal(values.has("glarion.signup.plan"), false);
  assert.equal(accountDestination(null), "#/targets");
  Object.assign(globalThis, { localStorage: {
    getItem: () => { throw new Error("blocked"); },
    setItem: () => { throw new Error("blocked"); },
    removeItem: () => { throw new Error("blocked"); },
  } });
  assert.equal(readPlanChoice(), null);
  assert.doesNotThrow(() => rememberPlanChoice({ plan: "solo", interval: "monthly" }));
});
