// The three-day free trial as the server publishes it (GET /api/billing/prices).
// Display only: checkout decides whether a trial is granted. Every amount on
// the trial line comes from the Stripe Prices behind that endpoint, never from
// a number written in a page; without them there is no trial line at all.

import { euro, type PromoOffer } from "./promo.js";

export type Interval = "monthly" | "yearly";

export type PlanPrice = {
  plan: string;
  interval: Interval;
  /** Minor units (cents) excluding VAT, as the Stripe Price has it. */
  amount: number;
  currency: string;
};

export type PriceList = {
  serverTime: string;
  trialEnabled: boolean;
  trialDays: number;
  prices: PlanPrice[];
};

/** Null for anything malformed. Prices that are not plain euro amounts are dropped. */
export function parsePrices(value: unknown): PriceList | null {
  const v = value as Record<string, unknown> | null;
  if (!v || typeof v !== "object") return null;
  if (typeof v.server_time !== "string" || !Number.isFinite(Date.parse(v.server_time))) return null;
  if (typeof v.trial_enabled !== "boolean" || !Number.isInteger(v.trial_days) || (v.trial_days as number) < 1 || !Array.isArray(v.prices)) return null;
  const prices = (v.prices as Record<string, unknown>[])
    .filter((p) => p && typeof p.plan === "string" && (p.interval === "monthly" || p.interval === "yearly")
      && Number.isInteger(p.amount) && (p.amount as number) > 0 && p.currency === "eur")
    .map((p) => ({ plan: p.plan, interval: p.interval, amount: p.amount, currency: p.currency }) as PlanPrice);
  return { serverTime: v.server_time, trialEnabled: v.trial_enabled, trialDays: v.trial_days as number, prices };
}

export function priceFor(list: PriceList | null, plan: string, interval: Interval): PlanPrice | null {
  return list?.prices.find((p) => p.plan === plan && p.interval === interval) ?? null;
}

/** When a trial started now would take its first payment: the server's clock
 *  plus the trial, plus the time since the answer arrived. */
export function firstChargeDate(list: Pick<PriceList, "serverTime" | "trialDays">, elapsedMs = 0): Date {
  return new Date(Date.parse(list.serverTime) + list.trialDays * 86_400_000 + Math.max(0, elapsedMs));
}

/** "17 October 2026". */
export function longDate(date: Date | string): string {
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "long", year: "numeric" }).format(typeof date === "string" ? new Date(date) : date);
}

const per = (interval: Interval) => (interval === "yearly" ? "year" : "month");

/** The line under "Start 3-day free trial": what is needed, what happens,
 *  when, for how much (excluding VAT, as the Stripe Prices are) and how it
 *  renews. */
export function trialLine(days: number, price: PlanPrice, chargeOn: Date, promo: PromoOffer | null = null): string {
  const unit = per(price.interval);
  const regular = `${euro(price.amount)}/${unit} excl. VAT`;
  const need = "Card or other payment method required.";
  const stop = "Cancel before then and nothing is charged.";
  if (promo && promo.price < price.amount) {
    return `${need} Free for ${days} days, then ${euro(promo.price)} excl. VAT for the first ${unit}, charged on ${longDate(chargeOn)}, and ${regular} after that, renewing until you cancel. ${stop}`;
  }
  return `${need} Free for ${days} days, then ${regular} from ${longDate(chargeOn)}, renewing every ${unit} until you cancel. ${stop}`;
}

/** The line under "Subscribe now". */
export function subscribeNowLine(price: PlanPrice, promo: PromoOffer | null = null): string {
  if (promo && promo.price < price.amount) {
    return `Or subscribe now: ${euro(promo.price)} charged today for the first ${per(price.interval)}, no trial.`;
  }
  return `Or subscribe now: ${euro(price.amount)} charged today, no trial.`;
}

/** "2 days 5 hours left", "5 hours left", "less than an hour left". */
export function timeLeft(endsAt: string, now: number = Date.now()): string {
  const ms = Date.parse(endsAt) - now;
  if (!Number.isFinite(ms) || ms <= 0) return "Ending now";
  const hours = Math.floor(ms / 3_600_000);
  const days = Math.floor(hours / 24);
  const rest = hours % 24;
  const part = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`;
  if (days > 0) return `${part(days, "day")}${rest ? ` ${part(rest, "hour")}` : ""} left`;
  if (hours > 0) return `${part(hours, "hour")} left`;
  return "Less than an hour left";
}

/** How much of the trial has gone, 0 to 1, for the progress bar. */
export function trialProgress(endsAt: string, days: number, now: number = Date.now()): number {
  const end = Date.parse(endsAt);
  if (!Number.isFinite(end)) return 0;
  const start = end - days * 86_400_000;
  return Math.min(1, Math.max(0, (now - start) / (end - start)));
}

let pending: Promise<PriceList | null> | null = null;

/** Reads the published prices once per page, however many scripts ask; null
 *  when the server cannot say. */
export function loadPrices(): Promise<PriceList | null> {
  pending ??= (async () => {
    try {
      const response = await fetch("/api/billing/prices", { cache: "no-store", signal: AbortSignal.timeout(8000) });
      return response.ok ? parsePrices(await response.json()) : null;
    } catch {
      return null;
    }
  })();
  return pending;
}

const TIERS = ["free", "solo", "studio", "agency"];

/** Where a plan stands against the one held: the held one is current, every
 *  plan below it is included in it, the ones above are upgrades. */
export function planStanding(plan: string, held: string): "current" | "included" | "upgrade" {
  if (plan === held) return "current";
  const rank = TIERS.indexOf(plan), mine = TIERS.indexOf(held);
  return rank >= 0 && mine >= 0 && rank < mine ? "included" : "upgrade";
}

/** The trial band above the plans: offered to an account the server lets
 *  start one, reported while it runs, explained once used; never shown to a
 *  paying account. */
export function trialBand(s: { trial_enabled?: boolean; state?: string; trial_ends_at?: string | null; can_start_trial?: boolean; manageable: boolean; blocked_reason?: string }, offered: boolean): "offer" | "running" | "used" | null {
  if (s.trial_enabled !== true) return null;
  if (s.state === "trialing" && s.trial_ends_at) return "running";
  if (offered) return "offer";
  if (s.blocked_reason === "trial_already_used" || (!s.manageable && s.can_start_trial === false && s.state !== "active")) return "used";
  return null;
}
