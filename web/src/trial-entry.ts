// The free trial in the navigation and at every locked point (owner, 23 Oct
// 2026). Display only: checkout still asks the server whether a trial applies.

export type TrialEntry = { kind: "offer"; days: number } | { kind: "running"; endsAt: string } | null;

/** Offered while the server lets this account start a trial, counted down
 *  while one runs, and nothing for a paying or paused account or before the
 *  subscription has been read. */
export function trialEntry(s: {
  trial_enabled?: boolean;
  trial_days?: number;
  state?: string;
  trial_ends_at?: string | null;
  can_start_trial?: boolean;
  manageable: boolean;
} | null): TrialEntry {
  if (!s) return null;
  if (s.state === "trialing" && s.trial_ends_at) return { kind: "running", endsAt: s.trial_ends_at };
  if (s.trial_enabled === true && s.can_start_trial === true && !s.manageable && s.state !== "active") {
    return { kind: "offer", days: Number.isInteger(s.trial_days) && (s.trial_days as number) > 0 ? (s.trial_days as number) : 3 };
  }
  return null;
}
