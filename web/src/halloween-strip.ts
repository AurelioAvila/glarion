// The Halloween strip and the hero offer card, for the pages that do not
// mount the plans themselves. Everything shown comes from GET /api/promo
// through watchPromo(): no price, percentage or date is written here, and
// when the server says there is no offer (ended, withdrawn, PROMO_DISABLED)
// nothing is drawn. Only static strings and server numbers reach innerHTML.

import { HALLOWEEN_MARK_EMBER } from "./halloween-decor.js";
import { euro, promoClock, promoEndLabel, promoPercent, promoThen, watchPromo, type PromoOffer, type PromoView } from "./promo.js";

const LAST_SEEN = "glarion.promo.last-seen";
const UNITS = ["Days", "Hours", "Minutes", "Seconds"];

const store = {
  get(key: string): string | null {
    try { return localStorage.getItem(key); } catch { return null; }
  },
  set(key: string, value: string): void {
    try { localStorage.setItem(key, value); } catch { /* storage blocked: the strip simply shows */ }
  },
};

function make(tag: string, className: string, html = ""): HTMLElement {
  const node = document.createElement(tag);
  node.className = className;
  if (html) node.innerHTML = html;
  return node;
}

/** The cheapest monthly offer, shown on the card: the plan a newcomer starts with. */
function headline(view: PromoView): PromoOffer | null {
  const offers = view.promo?.offers.filter((o) => o.interval === "monthly") ?? [];
  return offers.sort((a, b) => a.price - b.price)[0] ?? null;
}

export function mountHalloween(): void {
  const header = document.querySelector("header.top");
  if (!header) return;
  const onLanding = location.pathname === "/";
  const target = onLanding ? "#pricing" : document.querySelector("#plans") ? "#plans" : "/pricing.html";
  const wasActive = store.get(LAST_SEEN) === "active";

  // Strip: reserved (same 40px, invisible) for someone who last saw the offer running, so the page does not jump.
  const strip = make("div", "hw-strip hw-strip-reserved");
  strip.setAttribute("aria-hidden", "true");
  strip.innerHTML = `<div class="hw-strip-inner"><span class="hw-strip-pumpkin" aria-hidden="true">${HALLOWEEN_MARK_EMBER}</span>`
    + `<strong class="hw-strip-label"><span class="hw-strip-full"></span><span class="hw-strip-short"></span></strong>`
    + `<span class="hw-strip-timer" role="timer" aria-live="off"><span class="hw-strip-ends" aria-hidden="true">Ends in </span><span class="hw-strip-digits" aria-hidden="true"></span></span>`
    + `<a class="hw-strip-cta" href="${target}">See the offer</a>`
    + `<button type="button" class="hw-strip-close" aria-label="Dismiss the Halloween offer banner"><svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" focusable="false"><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>`;

  // Card (landing only): beside the headline, under the hero copy.
  const micro = onLanding ? document.querySelector(".hero-copy .micro") : null;
  const card = micro ? make("aside", "hw-card hw-card-reserved") : null;
  if (card && micro) {
    card.setAttribute("aria-hidden", "true");
    card.innerHTML = `<span class="hw-card-mark" aria-hidden="true">${HALLOWEEN_MARK_EMBER.replaceAll("hwme", "hwmc")}</span><span class="hw-card-tag">HALLOWEEN</span>`
      + `<div class="hw-card-row"><span class="hw-card-now">€0</span><s class="hw-card-was">€0</s><span class="hw-card-pct">−0%</span></div>`
      + `<span class="hw-card-plan">Solo, first month</span>`
      + `<div class="hw-card-foot"><span class="hw-card-note">Ends</span><a class="hw-card-cta" href="${target}">See the offer<svg viewBox="0 0 14 10" width="14" height="10" aria-hidden="true" focusable="false"><path d="M1 5h11M8 1l4 4-4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></a></div>`;
    if (wasActive) micro.after(card);
  }

  let dismissed = false;
  let shown = false;
  const q = (root: HTMLElement, sel: string) => root.querySelector(sel) as HTMLElement;

  strip.querySelector(".hw-strip-close")!.addEventListener("click", () => {
    dismissed = true;
    store.set(`glarion.halloween-strip.${strip.dataset.promo ?? ""}`, "1");
    strip.remove();
  });

  if (wasActive) header.before(strip);

  watchPromo((view) => {
    const promo = view.promo;
    store.set(LAST_SEEN, promo ? "active" : "off");
    if (!promo) {
      strip.remove();
      card?.remove();
      shown = false;
      return;
    }
    strip.dataset.promo = promo.id;
    if (store.get(`glarion.halloween-strip.${promo.id}`) === "1") dismissed = true;
    const percent = Math.min(...promo.offers.map(promoPercent));
    if (!dismissed) {
      if (!strip.isConnected) header.before(strip);
      q(strip, ".hw-strip-full").textContent = `Halloween offer · at least ${percent}% off`;
      q(strip, ".hw-strip-short").textContent = `Halloween · ${percent}%+ off`;
      const [d, h, m, s] = promoClock(view.remaining);
      q(strip, ".hw-strip-digits").textContent = `${Number(d)}d ${h}h ${m}m ${s}s`;
      q(strip, ".hw-strip-timer").setAttribute("aria-label", `Ends in ${[d, h, m].map((v, i) => `${Number(v)} ${UNITS[i]!.toLowerCase()}`).join(", ")}`);
      if (!shown) {
        strip.classList.remove("hw-strip-reserved");
        strip.removeAttribute("aria-hidden");
        strip.setAttribute("role", "region");
        strip.setAttribute("aria-label", "Halloween offer");
      }
    }
    const offer = headline(view);
    if (card && micro && offer) {
      if (!card.isConnected) micro.after(card);
      q(card, ".hw-card-now").textContent = euro(offer.price);
      q(card, ".hw-card-was").textContent = euro(offer.reference);
      q(card, ".hw-card-pct").textContent = `−${promoPercent(offer)}%`;
      q(card, ".hw-card-plan").textContent = `${offer.plan[0]!.toUpperCase()}${offer.plan.slice(1)} · ${promoThen(offer).replace(/\.$/, "")}`;
      q(card, ".hw-card-note").textContent = `Ends ${promoEndLabel(promo)}`;
      if (!shown) {
        card.classList.remove("hw-card-reserved");
        card.removeAttribute("aria-hidden");
        card.setAttribute("aria-label", `Halloween offer, ${promoPercent(offer)}% off`);
      }
    }
    shown = true;
  });
}

mountHalloween();
