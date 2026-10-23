import test from "node:test";
import assert from "node:assert/strict";
import { trialEntry } from "./trial-entry.js";

// Owner, 23 Oct 2026: the free trial must be visible in the main window and at
// every locked point, on the same terms everywhere, and never shown to a payer.
const free = { trial_enabled: true, trial_days: 3, state: "none", manageable: false, can_start_trial: true };

test("the navigation and the locked points offer the trial only while the server allows it", () => {
  assert.equal(trialEntry(null), null, "subscription not read yet: nothing, so a payer never sees it flash");
  assert.deepEqual(trialEntry(free), { kind: "offer", days: 3 });
  assert.deepEqual(trialEntry({ ...free, trial_days: undefined }), { kind: "offer", days: 3 }, "older API without trial_days");
  assert.equal(trialEntry({ ...free, can_start_trial: false }), null, "trial already used");
  assert.equal(trialEntry({ ...free, state: "blocked", blocked_reason: "trial_already_used", can_start_trial: false } as typeof free), null, "trial refused");
  assert.equal(trialEntry({ ...free, trial_enabled: false }), null, "switch off");
  assert.equal(trialEntry({ ...free, trial_enabled: undefined }), null, "API from before the trial");
});

test("a running trial is counted down; paying and paused accounts never see the trial", () => {
  const ends = "2026-10-26T10:00:00Z";
  assert.deepEqual(trialEntry({ ...free, state: "trialing", trial_ends_at: ends, manageable: true, can_start_trial: false }), { kind: "running", endsAt: ends });
  for (const plan of ["solo monthly", "studio yearly", "agency"]) {
    assert.equal(trialEntry({ ...free, state: "active", manageable: true, can_start_trial: false }), null, plan);
    assert.equal(trialEntry({ ...free, state: "active", manageable: true, can_start_trial: true }), null, `${plan}: whatever the eligibility flag says`);
    assert.equal(trialEntry({ ...free, state: "active", manageable: false, can_start_trial: true }), null, `${plan} without a portal`);
  }
  assert.equal(trialEntry({ ...free, state: "blocked", manageable: true, can_start_trial: false }), null, "payment failed");
});
