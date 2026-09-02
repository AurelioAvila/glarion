/*
  The domain from the free check, carried across the signup round-trip.

  Somebody who has just watched the check run on a client's site arrives at
  the signup form with that domain in mind, and the form used to throw it
  away: they filled in seven fields, confirmed an address, came back, and
  were shown an empty box asking for the thing they had typed ninety seconds
  earlier on the front page.

  localStorage rather than the URL, because the way back in is a link in an
  email — which often opens a different tab and sometimes a different
  browser. This survives the round trip on the same device, which is the
  common case, and simply does not fire otherwise. Every access is guarded:
  a private window, or a browser set to block site data, throws on the
  accessor itself, and the form has to keep working when it does.
*/

const KEY = "glarion.signup.domain";

/// A week. A domain from a signup somebody abandoned three weeks ago is
/// noise in the box rather than a helpful default.
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

/// Deliberately strict, and applied before the value is either stored or
/// shown. `#/signup?d=` is a URL anybody can write, and the page says the
/// domain back to the reader: without this, that sentence is a free line of
/// attacker-chosen text on our origin, under our name. Nothing that is not
/// shaped like a hostname gets past here.
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/// Normalizes what arrived in the query string, or rejects it.
export function cleanDomain(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const domain = raw.trim().toLowerCase().replace(/\.$/, "");
  return domain.length <= 253 && HOSTNAME.test(domain) ? domain : null;
}

export function rememberDomain(domain: string): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ domain, at: Date.now() }));
  } catch {
    // Storage refused. Nothing is carried, and the form is unchanged.
  }
}

export function forgetRememberedDomain(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    // Nothing to do about it, and nothing depends on it having worked.
  }
}

/// Reads it once. Consumed on the way out whether or not it was still
/// fresh, so a stale entry cannot sit there being offered on every visit.
///
/// Call this once per page load and hold the answer. Calling it from a
/// render is what the first version of this did, and a view here can render
/// more than once for a single arrival — the signed-in path bounces
/// `#/signup` to `#/targets`, which renders, and a value consumed by a
/// render whose DOM is then thrown away is a value lost.
export function takeRememberedDomain(): string | null {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(KEY);
    localStorage.removeItem(KEY);
  } catch {
    return null;
  }
  if (!stored) return null;

  try {
    const { domain, at } = JSON.parse(stored) as { domain?: unknown; at?: unknown };
    if (typeof domain !== "string" || typeof at !== "number") return null;
    if (Date.now() - at > TTL_MS) return null;
    return cleanDomain(domain);
  } catch {
    // Somebody else's key, or a half-written value. Not worth a failure.
    return null;
  }
}
