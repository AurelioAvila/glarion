// The Halloween offer as published by GET /api/promo. Display only: the
// server decides the discount at checkout, from its own clock. Anything
// malformed, missing or late means regular prices.

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

/** Reads the offer and calls `render` once a second while one runs, and once
 *  more when it ends or the server withdraws it. Re-read every five minutes
 *  and whenever the window regains focus. */
export function watchPromo(render: (view: PromoView) => void): void {
  const clock = () => ({ perf: performance.now(), wall: Date.now() });
  let received: { promo: Promo; at: ReturnType<typeof clock> } | null = null;
  let shown = false;
  const tick = (): void => {
    const promo = received?.promo ?? null;
    const now = clock();
    // Whichever clock advanced more: a paused (sleep) or wrong clock can only shorten the offer.
    const elapsed = received ? Math.max(now.perf - received.at.perf, now.wall - received.at.wall) : 0;
    const active = Boolean(promo && promo.status === "active" && msUntil(promo, promo.startsAt, elapsed) <= 0 && msUntil(promo, promo.endsAt, elapsed) > 0);
    if (!active && !shown) return;
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
    tick();
  };
  void read();
  window.setInterval(tick, 1000);
  window.setInterval(() => void read(), 5 * 60_000);
  window.addEventListener("focus", () => void read());
}

const PUMPKIN = '<svg class="promo-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 7.5c-1.6-1-4.4-1.2-6.2.4C3.6 9.8 3.4 14 4.6 16.6c1.3 2.8 4.3 3.6 7.4 2.6 3.1 1 6.1.2 7.4-2.6 1.2-2.6 1-6.8-1.2-8.7-1.8-1.6-4.6-1.4-6.2-.4Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 7.5c-1.3 2.4-1.3 9.3 0 11.7m0-11.7c1.3 2.4 1.3 9.3 0 11.7M12 7.5c0-1.6.6-3 2-3.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
const UNITS = ["days", "hours", "min", "sec"] as const;

/** The large countdown banner. Static strings and numbers only: nothing from
 *  the network reaches the markup except parsed cents and a parsed date. */
export function promoBanner(promo: Promo, trial: boolean): HTMLElement {
  const percent = Math.min(...promo.offers.map(promoPercent));
  const banner = document.createElement("aside");
  banner.className = "promo";
  banner.setAttribute("aria-label", "Halloween offer");
  banner.innerHTML = `<div class="promo-copy"><p class="promo-title">${PUMPKIN}<span>Halloween offer</span></p><p class="promo-lead"></p><p class="promo-ends"></p></div>`
    + `<div class="promo-timer"><p class="promo-ends-in">Ends in</p><div class="promo-clock" role="timer" aria-live="off">${UNITS.map((unit) => `<div><strong>00</strong><span>${unit}</span></div>`).join("")}</div></div>`
    + `<p class="promo-terms"></p>`;
  banner.querySelector(".promo-lead")!.textContent = `${percent}% off your first month or year of Solo, Studio and Agency.`;
  banner.querySelector(".promo-ends")!.textContent = `Ends ${promoEndLabel(promo)}.`;
  banner.querySelector(".promo-terms")!.textContent = "Struck-through prices are the lowest we charged in the 30 days before the offer began. The discount applies to the first paid month or year only; renewals are at the regular price."
    + (trial ? " New Solo subscribers still start with the 14-day free trial." : "")
    + " Prices exclude VAT, which is added at checkout where applicable.";
  return banner;
}

export function updatePromoClock(banner: HTMLElement, remaining: number): void {
  const values = promoClock(remaining);
  banner.querySelectorAll(".promo-clock strong").forEach((cell, i) => { if (cell.textContent !== values[i]) cell.textContent = values[i]!; });
  banner.querySelector(".promo-clock")!.setAttribute("aria-label", values.map((v, i) => `${v} ${UNITS[i]}`).join(", "));
}
