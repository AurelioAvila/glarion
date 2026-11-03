// Back from Stripe Checkout. Stripe sends a paying customer to
// `#/plan?checkout=cs_…` at once, while the plan itself arrives with Stripe's
// webhook a few seconds later. Until then the page must not offer the plans
// again: a second click there is a second subscription.

/// How often, and how many times, the plan page asks before saying so.
export const CHECKOUT_POLL_MS = 3000;
export const CHECKOUT_POLLS = 30;

/// Whether this route is the return from a paid checkout.
export function returnedFromCheckout(hash: string): boolean {
  const separator = hash.indexOf("?");
  return separator !== -1 && new URLSearchParams(hash.slice(separator + 1)).has("checkout");
}

/// Whether Stripe's confirmation has reached the account: a paid plan or a
/// trial is in force, or a refused trial the plan page explains. A plan that
/// ended before ("canceled") is what a returning customer had before paying,
/// so it is not an answer.
export function checkoutSettled(s: { plan: string; state?: string; blocked_reason?: string }): boolean {
  return s.plan !== "free" || (s.state === "blocked" && s.blocked_reason === "trial_already_used");
}
