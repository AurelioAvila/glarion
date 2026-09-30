// Keep the choice across the confirmation email, including a new tab.
// It is a preference only: prices and permission to pay remain server-owned.
export type PlanChoice = { plan: "solo" | "studio" | "agency"; interval: "monthly" | "yearly" };
const KEY = "glarion.signup.plan";
const TTL = 7 * 24 * 60 * 60 * 1000;

export function cleanPlanChoice(plan: unknown, interval: unknown): PlanChoice | null {
  if (plan !== "solo" && plan !== "studio" && plan !== "agency") return null;
  if (interval !== "monthly" && interval !== "yearly") return null;
  return { plan, interval };
}

export function rememberPlanChoice(choice: PlanChoice | null): void {
  try {
    if (choice) localStorage.setItem(KEY, JSON.stringify({ ...choice, at: Date.now() }));
    else localStorage.removeItem(KEY);
  } catch { /* Account entry still works when storage is blocked. */ }
}

export function readPlanChoice(): PlanChoice | null {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) ?? "null");
    if (stored && Number.isFinite(stored.at) && stored.at <= Date.now() && Date.now() - stored.at <= TTL) {
      const choice = cleanPlanChoice(stored.plan, stored.interval);
      if (choice) return choice;
    }
    rememberPlanChoice(null);
  } catch { rememberPlanChoice(null); }
  return null;
}

export function accountDestination(choice: PlanChoice | null): string {
  return choice ? "#/plan" : "#/targets";
}
