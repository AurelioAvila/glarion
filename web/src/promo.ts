// The Halloween offer as published by GET /api/promo. Display only: the
// server decides the discount at checkout, from its own clock. Anything
// malformed, missing or late means regular prices.

import { HALLOWEEN_DECOR_LEFT, HALLOWEEN_DECOR_RIGHT } from "./halloween-decor.js";

export type PromoOffer = {
  plan: string;
  interval: "monthly" | "yearly";
  /** Euro cents excluding VAT, like the Stripe Prices. */
  regular: number;
  /** The lowest price of the previous 30 days: the only one that may be struck through. */
  reference: number;
  price: number;
};

export type Promo = { serverTime: string; id: string; status: "scheduled" | "active"; startsAt: string; endsAt: string; offers: PromoOffer[] };

const cents = (v: unknown): v is number => Number.isInteger(v) && (v as number) > 0;
const time = (v: unknown): v is string => typeof v === "string" && Number.isFinite(Date.parse(v));

/** Null for "no offer" and for anything malformed: a broken payload must never
 *  draw a struck price. An offer that is not a real reduction is dropped. */
export function parsePromo(value: unknown): Promo | null {
  const v = value as Record<string, unknown> | null;
  if (!v || typeof v !== "object" || (v.status !== "active" && v.status !== "scheduled")) return null;
  if (typeof v.id !== "string" || !time(v.serverTime) || !time(v.startsAt) || !time(v.endsAt) || !Array.isArray(v.offers)) return null;
  const offers = (v.offers as Record<string, unknown>[])
    .filter((o) => o && typeof o.plan === "string" && (o.interval === "monthly" || o.interval === "yearly") && o.currency === "eur"
      && cents(o.regular) && cents(o.reference) && cents(o.price)
      && (o.price as number) < (o.reference as number) && (o.reference as number) <= (o.regular as number)
      && o.firstPeriodOnly === true)
    .map((o) => ({ plan: o.plan, interval: o.interval, regular: o.regular, reference: o.reference, price: o.price }) as PromoOffer);
  // "Active" with nothing valid to sell is not an offer: never a banner without prices.
  if (v.status === "active" && offers.length === 0) return null;
  return { serverTime: v.serverTime, id: v.id, status: v.status, startsAt: v.startsAt, endsAt: v.endsAt, offers: v.status === "active" ? offers : [] };
}

/** Rounded down, so the badge never claims more than the real discount. */
export function promoPercent(offer: Pick<PromoOffer, "reference" | "price">): number {
  return Math.floor(((offer.reference - offer.price) * 100) / offer.reference);
}

/** Milliseconds until `iso` on the server's clock plus the time elapsed since
 *  the response arrived, so a wrong device clock cannot extend the offer. */
export function msUntil(promo: Pick<Promo, "serverTime">, iso: string, elapsedMs: number): number {
  return Date.parse(iso) - Date.parse(promo.serverTime) - Math.max(0, elapsedMs);
}

/** Days, hours, minutes and seconds left; zero at and after the deadline. */
export function promoClock(ms: number): [string, string, string, string] {
  const s = Number.isFinite(ms) ? Math.max(0, Math.floor(ms / 1000)) : 0;
  return [Math.floor(s / 86_400), Math.floor((s % 86_400) / 3600), Math.floor((s % 3600) / 60), s % 60]
    .map((value) => String(value).padStart(2, "0")) as [string, string, string, string];
}

/** €19, €9.50: whole euros stay short, anything else shows cents. */
export function euro(value: number): string {
  return new Intl.NumberFormat("en-IE", { style: "currency", currency: "EUR", minimumFractionDigits: value % 100 ? 2 : 0 }).format(value / 100);
}

/** "6 November 2026 at 23:59 CET" in the reader's own zone, named so it
 *  cannot be misread: the last minute on sale, not the exclusive deadline. */
export function promoEndLabel(promo: Pick<Promo, "endsAt">): string {
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" })
    .format(new Date(Date.parse(promo.endsAt) - 60_000));
}

/** "First month, then €19/month." */
export function promoThen(offer: PromoOffer): string {
  return offer.interval === "yearly" ? `First year, then ${euro(offer.regular)}/year.` : `First month, then ${euro(offer.regular)}/month.`;
}

export type PromoView = { promo: Promo | null; remaining: number; offer(plan: string, interval: string): PromoOffer | null };

/** Until this instant the pricing area keeps room for the banner while the
 *  server answers, so the plans do not jump when it appears. It only reserves
 *  space: nothing about the offer is shown without the server. */
export const PROMO_LAYOUT_UNTIL = Date.parse("2026-11-06T23:00:00.000Z");

/** Reads the offer and calls `render` on the first answer, once a second
 *  while an offer runs, and once more when it ends or the server withdraws
 *  it. Re-read every five minutes and whenever the window regains focus. */
export function watchPromo(render: (view: PromoView) => void): void {
  const clock = () => ({ perf: performance.now(), wall: Date.now() });
  let received: { promo: Promo; at: ReturnType<typeof clock> } | null = null;
  let answered = false;
  // null until the first answer has been rendered, then whether an offer is showing.
  let shown: boolean | null = null;
  const tick = (): void => {
    if (!answered) return;
    const promo = received?.promo ?? null;
    const now = clock();
    // Whichever clock advanced more: a paused (sleep) or wrong clock can only shorten the offer.
    const elapsed = received ? Math.max(now.perf - received.at.perf, now.wall - received.at.wall) : 0;
    const active = Boolean(promo && promo.status === "active" && msUntil(promo, promo.startsAt, elapsed) <= 0 && msUntil(promo, promo.endsAt, elapsed) > 0);
    if (!active && shown === false) return;
    shown = active;
    render({
      promo: active ? promo : null,
      remaining: active && promo ? msUntil(promo, promo.endsAt, elapsed) : 0,
      offer: (plan, interval) => (active && promo?.offers.find((o) => o.plan === plan && o.interval === interval)) || null,
    });
  };
  const read = async (): Promise<void> => {
    try {
      const response = await fetch("/api/promo", { cache: "no-store", signal: AbortSignal.timeout(8000) });
      const promo = response.ok ? parsePromo(await response.json()) : null;
      received = promo ? { promo, at: clock() } : null;
    } catch {
      received = null;
    }
    answered = true;
    tick();
  };
  void read();
  window.setInterval(tick, 1000);
  window.setInterval(() => void read(), 5 * 60_000);
  window.addEventListener("focus", () => void read());
}

const UNITS = ["Days", "Hours", "Minutes", "Seconds"] as const;
const FINE = "Struck-through prices are our lowest in the 30 days before the offer. New subscriptions only; renewals are at the regular price, and new Solo subscribers still start with the 14-day free trial. Prices exclude VAT.";

export type PromoBanner = { element: HTMLElement; show(promo: Promo): void; tick(remaining: number): void };

/** The Halloween banner shared with PC Tweaker (carved pumpkins, countdown
 *  cells), as plain DOM. Starts reserved: invisible, holding its exact place
 *  until `show`. Only static strings and numbers reach it. */
export function createPromoBanner(): PromoBanner {
  const element = document.createElement("section");
  element.className = "hw-offer hw-offer-reserved";
  element.style.visibility = "hidden";
  element.setAttribute("aria-hidden", "true");
  element.innerHTML = `<div class="hw-offer-inner">`
    + `<span class="hw-offer-decor hw-offer-decor-left" aria-hidden="true">${HALLOWEEN_DECOR_LEFT}</span>`
    + `<span class="hw-offer-decor hw-offer-decor-right" aria-hidden="true">${HALLOWEEN_DECOR_RIGHT}</span>`
    + `<div class="hw-offer-copy"><p class="hw-offer-kicker">Halloween offer</p><p class="hw-offer-heading" id="glarion-promo-title"></p><p class="hw-offer-fine"></p></div>`
    + `<div class="hw-offer-timer"><span aria-hidden="true">Ends in</span><div class="hw-offer-cells" role="timer" aria-live="off">`
    + UNITS.map((unit) => `<div class="hw-offer-cell" aria-hidden="true"><strong>00</strong><small>${unit}</small></div>`).join("")
    + `</div></div></div>`;
  const heading = (promo: Pick<Promo, "endsAt">, percent: number) => {
    element.querySelector(".hw-offer-heading")!.textContent = `${percent}% off your first month or year. Ends ${promoEndLabel(promo)}.`;
  };
  heading({ endsAt: new Date(PROMO_LAYOUT_UNTIL).toISOString() }, 50);
  element.querySelector(".hw-offer-fine")!.textContent = FINE;
  return {
    element,
    show(promo) {
      heading(promo, Math.min(...promo.offers.map(promoPercent)));
      element.style.removeProperty("visibility");
      element.classList.remove("hw-offer-reserved");
      element.removeAttribute("aria-hidden");
      element.setAttribute("aria-labelledby", "glarion-promo-title");
    },
    tick(remaining) {
      const values = promoClock(remaining);
      element.querySelectorAll(".hw-offer-cell strong").forEach((cell, i) => { if (cell.textContent !== values[i]) cell.textContent = values[i]!; });
      element.querySelector(".hw-offer-cells")!.setAttribute("aria-label", `Ends in ${values.slice(0, 3).map((v, i) => `${Number(v)} ${UNITS[i]!.toLowerCase()}`).join(", ")}`);
    },
  };
}

/** Puts a banner where `place` says, reserved until the server answers, keeps
 *  it in step with the offer, and calls `onChange` when the offer first
 *  becomes known, starts or stops. */
export function mountPromo(place: (banner: HTMLElement) => void, onChange: (view: PromoView) => void): void {
  const banner = createPromoBanner();
  let view: PromoView | null = null;
  // Room is kept only for someone who last saw the offer running: while it is
  // off, nobody's pricing jumps on load.
  const KEY = "glarion.promo.last-seen";
  let lastSeen = false;
  try { lastSeen = localStorage.getItem(KEY) === "active"; } catch { /* storage blocked: no reservation */ }
  if (lastSeen && Date.now() < PROMO_LAYOUT_UNTIL) place(banner.element);
  watchPromo((next) => {
    const changed = view === null || Boolean(view.promo) !== Boolean(next.promo);
    view = next;
    if (changed) {
      try { localStorage.setItem(KEY, next.promo ? "active" : "off"); } catch { /* best effort */ }
      if (next.promo) {
        banner.show(next.promo);
        if (!banner.element.isConnected) place(banner.element);
      } else {
        banner.element.remove();
      }
      onChange(next);
    }
    if (next.promo) banner.tick(next.remaining);
  });
}
