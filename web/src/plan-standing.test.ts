import test from "node:test";
import assert from "node:assert/strict";
import { planStanding, trialBand } from "./trial.js";

// Owner report 23 Oct 2026: with a higher plan held, the lower ones must read
// "Included in your plan", the held one "Current plan", higher ones upgrade.
test("every plan below the held one is included, the held one current, the rest upgrades", () => {
  const plans = ["free", "solo", "studio", "agency"];
  const table = Object.fromEntries(plans.map((held) => [held, plans.map((p) => planStanding(p, held))]));
  assert.deepEqual(table, {
    free: ["current", "upgrade", "upgrade", "upgrade"],
    solo: ["included", "current", "upgrade", "upgrade"],
    studio: ["included", "included", "current", "upgrade"],
    agency: ["included", "included", "included", "current"],
  });
});

test("the trial band offers, reports or explains the trial and never reaches a paying account", () => {
  const free = { trial_enabled: true, state: "none", manageable: false, can_start_trial: true };
  assert.equal(trialBand(free, true), "offer");
  assert.equal(trialBand({ ...free, can_start_trial: false }, false), "used");
  assert.equal(trialBand({ ...free, state: "blocked", blocked_reason: "trial_already_used", can_start_trial: false }, false), "used");
  assert.equal(trialBand({ ...free, state: "trialing", trial_ends_at: "2026-10-26T10:00:00Z", manageable: true, can_start_trial: false }, false), "running");
  assert.equal(trialBand({ ...free, state: "active", manageable: true, can_start_trial: false }, false), null, "monthly or yearly subscriber");
  assert.equal(trialBand({ ...free, state: "active", manageable: true, can_start_trial: true }, false), null, "never offered to a paying account");
  assert.equal(trialBand({ ...free, trial_enabled: false }, true), null, "switch off");
});
