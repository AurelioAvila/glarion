// Manage subscription (owner, 1 November 2026): the account menu's panel.
// What this account pays for, and cancelling it at the end of the paid period
// or resuming it, without leaving the dashboard. Cancelling is two short
// steps, an optional reason and a confirmation that names the last day, and
// never harder than subscribing: no retention offers, nothing to argue past.

import { api, ApiError, type CancelReason, type ManagedSubscription } from "./api.js";
import { el, on } from "./dom.js";
import { longDate } from "./trial.js";

export const CANCEL_REASONS: ReadonlyArray<readonly [CancelReason, string]> = [
  ["too_expensive", "Too expensive"],
  ["unused", "I don't use it enough"],
  ["missing_features", "Missing a feature I need"],
  ["switched_service", "Switching to another tool"],
  ["low_quality", "Technical problems / bugs"],
  ["too_complex", "Too complicated to use"],
  ["customer_service", "Problems with support"],
  ["other", "Other"],
];

export const COMMENT_MAX = 500;

/** Whether it is set to end rather than renew. */
export function isEnding(s: ManagedSubscription): boolean {
  return s.cancel_at_period_end || s.cancel_at !== null;
}

/** The last day of access once it is set to end, else the renewal date. */
export function endDate(s: ManagedSubscription): string | null {
  return s.cancel_at ?? s.current_period_end;
}

/** "€39 / month", from Stripe's minor units. */
export function priceLabel(s: ManagedSubscription): string | null {
  if (s.amount === null || !s.currency) return null;
  const money = new Intl.NumberFormat("en-IE", {
    style: "currency",
    currency: s.currency.toUpperCase(),
    minimumFractionDigits: s.amount % 100 ? 2 : 0,
  }).format(s.amount / 100);
  return s.interval ? `${money} / ${s.interval}` : money;
}

/** The short state shown next to the plan's name. */
export function statusPill(s: ManagedSubscription): { text: string; tone: "ok" | "info" | "warn" } {
  if (s.status === "none") return { text: "Free plan", tone: "info" };
  if (s.status === "past_due" || s.status === "unpaid") return { text: "Payment due", tone: "warn" };
  if (s.status === "paused") return { text: "Paused", tone: "warn" };
  if (isEnding(s)) return { text: "Cancelled", tone: "warn" };
  if (s.status === "trialing") return { text: "Free trial", tone: "info" };
  return { text: "Active", tone: "ok" };
}

/** One sentence on what happens next, with the exact date. */
export function nextLine(s: ManagedSubscription): string {
  const end = endDate(s);
  if (s.status === "none") return "You're on the free plan: one site, no scheduled scans.";
  if (s.status === "past_due" || s.status === "unpaid") return "Your last payment didn't go through. Update your payment method to keep full scans and scheduled checks.";
  if (s.status === "paused") return "This subscription is paused. Open payment method & invoices to restart it.";
  if (!end) return "";
  if (isEnding(s)) {
    return s.status === "trialing"
      ? `Your free trial ends on ${longDate(end)}. You won't be charged.`
      : `Ends on ${longDate(end)}. It won't renew and you won't be charged again.`;
  }
  if (s.status === "trialing") {
    const price = priceLabel(s);
    return `Your free trial ends on ${longDate(s.trial_end ?? end)}${price ? `, then ${price} plus any VAT` : ""}.`;
  }
  return `Renews on ${longDate(end)}.`;
}

/** The confirmation's promise: the exact last day, and no further charge. */
export function confirmLine(s: ManagedSubscription): string {
  const end = endDate(s);
  const day = end ? longDate(end) : "the end of the current period";
  return s.status === "trialing"
    ? `You keep ${s.plan_name} until your free trial ends on ${day}. You won't be charged.`
    : `You keep ${s.plan_name} until ${day}. You won't be charged again.`;
}

export function cardLabel(card: { brand: string; last4: string }): string {
  const names: Record<string, string> = {
    amex: "American Express",
    diners: "Diners Club",
    discover: "Discover",
    jcb: "JCB",
    mastercard: "Mastercard",
    unionpay: "UnionPay",
    visa: "Visa",
  };
  const brand = names[card.brand] ?? card.brand.charAt(0).toUpperCase() + card.brand.slice(1);
  return `${brand} ending in ${card.last4}`;
}

function failure(error: unknown): string {
  if (typeof navigator !== "undefined" && navigator.onLine === false) return "You're offline. Reconnect, then try again.";
  if (error instanceof ApiError && error.status === 429) return "Too many attempts. Wait a few minutes, then try again.";
  if (error instanceof ApiError && error.status === 404) return "There's no subscription on this account to change.";
  return "Couldn't reach billing. Try again.";
}

export interface PanelHooks {
  /** After a cancel or resume, so the rest of the app re-reads the plan. */
  changed(): void;
}

let openDialog: HTMLDialogElement | null = null;

/** Opens the panel. One at a time; it removes itself when closed. */
export function openManageSubscription(hooks: PanelHooks): void {
  if (openDialog) return;
  const dialog = el("dialog", { class: "manage", "aria-labelledby": "manage-title" });
  const body = el("div", { class: "manage-body" });
  const close = el("button", { class: "manage-close", type: "button", "aria-label": "Close" }, ["×"]);
  on(close, "click", () => dialog.close());
  dialog.append(
    el("div", { class: "manage-head" }, [el("h2", { id: "manage-title", text: "Manage subscription" }), close]),
    body,
  );
  on(dialog, "close", () => {
    dialog.remove();
    openDialog = null;
  });
  // A click on the backdrop lands on the dialog itself.
  on(dialog, "click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  document.body.append(dialog);
  openDialog = dialog;
  dialog.showModal();

  const focusFirst = () => body.querySelector<HTMLElement>("h3, [data-focus], button, input, a")?.focus();

  const load = async (flash: string | null = null): Promise<void> => {
    body.replaceChildren(
      el("div", { class: "manage-loading", role: "status", "aria-live": "polite" }, [
        el("span", { class: "manage-spinner", "aria-hidden": "true" }),
        "Loading your subscription…",
      ]),
    );
    body.setAttribute("aria-busy", "true");
    try {
      overview(await api.manageSubscription(), flash);
    } catch (error) {
      const retry = el("button", { class: "ghost", type: "button", text: "Try again" });
      on(retry, "click", () => void load());
      body.replaceChildren(
        el("p", { class: "notice notice-error", role: "alert", text: failure(error) }),
        el("div", { class: "manage-actions" }, [retry]),
      );
      retry.focus();
    } finally {
      body.removeAttribute("aria-busy");
    }
  };

  const portalLink = (s: ManagedSubscription, primary: boolean): HTMLElement | null => {
    if (!s.portal) return null;
    const button = el("button", { class: primary ? "primary" : "manage-link", type: "button", text: "Payment method & invoices" });
    const note = el("span", { class: "manage-portal-note", text: "Opens Stripe" });
    on(button, "click", () => {
      button.disabled = true;
      api.billingPortal().then(
        (result) => {
          window.location.href = result.url;
        },
        (error) => {
          button.disabled = false;
          note.textContent = failure(error);
          note.classList.add("manage-portal-error");
        },
      );
    });
    return el("div", { class: "manage-portal" }, [button, note]);
  };

  const overview = (s: ManagedSubscription, flash: string | null): void => {
    const pill = statusPill(s);
    const rows: HTMLElement[] = [];
    const row = (label: string, value: string) => rows.push(el("div", { class: "manage-row" }, [el("dt", { text: label }), el("dd", { text: value })]));
    const price = priceLabel(s);
    if (price) row("Price", `${price} · excl. VAT`);
    row("Sites", `${s.sites_used} of ${s.max_sites} in use`);
    if (s.status !== "none") {
      const end = endDate(s);
      if (s.status === "trialing" && !isEnding(s) && s.trial_end) row("Trial ends", longDate(s.trial_end));
      else if (end) row(isEnding(s) ? "Access until" : "Renews on", longDate(end));
    }
    if (s.payment_method) row("Payment method", cardLabel(s.payment_method));

    const actions = el("div", { class: "manage-actions" });
    const message = el("div", { "aria-live": "polite" });
    if (s.can_resume) {
      const resume = el("button", { class: "primary", type: "button", text: "Resume subscription" });
      on(resume, "click", () => {
        resume.disabled = true;
        resume.textContent = "Resuming…";
        api.resumeSubscription().then(
          (next) => {
            hooks.changed();
            const renews = endDate(next);
            overview(next, renews ? `Your subscription is back on. It renews on ${longDate(renews)}.` : "Your subscription is back on.");
          },
          (error) => {
            resume.disabled = false;
            resume.textContent = "Resume subscription";
            message.replaceChildren(el("p", { class: "notice notice-error", role: "alert", text: failure(error) }));
          },
        );
      });
      actions.append(resume);
    }
    const pastDue = s.status === "past_due" || s.status === "unpaid";
    const portal = portalLink(s, pastDue && !s.can_resume);
    if (s.status === "none") {
      actions.append(el("a", { class: "primary", href: "#/plan", text: "See plans" }));
    }
    if (s.can_cancel) {
      const cancel = el("button", { class: "manage-cancel", type: "button", text: "Cancel subscription" });
      on(cancel, "click", () => reasons(s));
      actions.append(cancel);
    }

    body.replaceChildren(
      ...(flash ? [el("p", { class: "notice notice-ok", role: "status", text: flash })] : []),
      el("section", { class: "manage-summary", "aria-label": "Current plan" }, [
        el("div", { class: "manage-plan" }, [
          el("span", { class: "manage-product", text: "Glarion" }),
          el("h3", { tabindex: "-1", "data-focus": true, text: s.plan_name }),
          el("span", { class: `manage-pill manage-pill-${pill.tone}`, text: pill.text }),
        ]),
        el("p", { class: "manage-next", text: nextLine(s) }),
      ]),
      el("dl", { class: "manage-rows" }, rows),
      message,
      ...[actions.childElementCount ? actions : null, portal].filter((node): node is HTMLElement => node !== null),
    );
    if (s.status === "none" && s.portal === false) {
      body.append(el("p", { class: "manage-fine", text: "Subscriptions, invoices and your payment method appear here once you subscribe." }));
    }
    focusFirst();
  };

  // Step 1: an optional reason. Skipping is as easy as choosing.
  const reasons = (s: ManagedSubscription, chosen: CancelReason | null = null, comment = ""): void => {
    const legend = el("legend", { text: "Before you go — what's the main reason?" });
    const hint = el("p", { class: "manage-fine", id: "manage-reason-hint", text: "Optional. It helps us improve Glarion." });
    const fieldset = el("fieldset", { class: "manage-reasons" }, [legend, hint]);
    const label = el("label", { for: "manage-comment" });
    const box = el("textarea", { id: "manage-comment", maxlength: COMMENT_MAX, rows: 3 });
    box.value = comment;
    const count = el("span", { class: "manage-count", "aria-live": "polite" });
    const commentWrap = el("div", { class: "manage-comment" }, [label, box, count]);
    const paintComment = () => {
      const other = chosen === "other";
      commentWrap.hidden = chosen === null;
      label.textContent = other ? "Tell us more" : "Anything we could do better?";
      box.placeholder = other ? "Tell us more (optional)" : "Optional";
      count.textContent = `${box.value.length} / ${COMMENT_MAX}`;
    };
    on(box, "input", paintComment);
    for (const [code, text] of CANCEL_REASONS) {
      const input = el("input", { type: "radio", name: "manage-reason", value: code, id: `manage-reason-${code}` });
      input.checked = chosen === code;
      on(input, "change", () => {
        chosen = code;
        paintComment();
      });
      fieldset.append(el("label", { class: "manage-reason", for: `manage-reason-${code}` }, [input, el("span", { text })]));
    }
    fieldset.setAttribute("aria-describedby", "manage-reason-hint");
    paintComment();

    const next = el("button", { class: "primary", type: "button", text: "Continue" });
    on(next, "click", () => confirm(s, chosen, chosen ? box.value : ""));
    const skip = el("button", { class: "ghost", type: "button", text: "Skip" });
    on(skip, "click", () => confirm(s, null, ""));
    const back = el("button", { class: "manage-link manage-back", type: "button", text: "← Keep my subscription" });
    on(back, "click", () => overview(s, null));

    body.replaceChildren(
      el("p", { class: "manage-step", text: "Step 1 of 2" }),
      fieldset,
      commentWrap,
      el("div", { class: "manage-actions" }, [next, skip]),
      back,
    );
    (fieldset.querySelector<HTMLInputElement>("input:checked") ?? fieldset.querySelector<HTMLInputElement>("input"))?.focus();
  };

  // Step 2: the exact last day, then the button that does it.
  const confirm = (s: ManagedSubscription, reason: CancelReason | null, comment: string): void => {
    const message = el("div", { "aria-live": "polite" });
    const go = el("button", { class: "danger", type: "button", text: "Cancel subscription" });
    const keep = el("button", { class: "ghost", type: "button", text: "Keep subscription" });
    on(keep, "click", () => overview(s, null));
    const back = el("button", { class: "manage-link manage-back", type: "button", text: "← Back" });
    on(back, "click", () => reasons(s, reason, comment));
    on(go, "click", () => {
      go.disabled = true;
      keep.disabled = true;
      go.textContent = "Cancelling…";
      api.cancelSubscription(reason, comment).then(
        (next) => {
          hooks.changed();
          const end = endDate(next);
          overview(next, end ? `Your subscription is cancelled. You keep ${next.plan_name} until ${longDate(end)}.` : "Your subscription is cancelled.");
        },
        (error) => {
          go.disabled = false;
          keep.disabled = false;
          go.textContent = "Cancel subscription";
          message.replaceChildren(el("p", { class: "notice notice-error", role: "alert", text: failure(error) }));
        },
      );
    });

    body.replaceChildren(
      el("p", { class: "manage-step", text: "Step 2 of 2" }),
      el("h3", { class: "manage-confirm-title", tabindex: "-1", "data-focus": true, text: `Cancel your ${s.plan_name} subscription?` }),
      el("p", { class: "manage-confirm", text: confirmLine(s) }),
      el("p", { class: "manage-fine", text: "Your sites, verifications and reports stay in your account. You can resume any time before that date." }),
      message,
      el("div", { class: "manage-actions" }, [go, keep]),
      back,
    );
    focusFirst();
  };

  void load();
}
