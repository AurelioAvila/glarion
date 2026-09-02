// The dashboard.
//
// Plain TypeScript with hash routing and no framework, matching the rest of
// the portfolio. Views render into a single root element; each render
// rebuilds its subtree rather than patching it, which is fast enough for a
// handful of screens and removes a whole class of stale-DOM bugs.
//
// Two ideas run through the layouts, both from what this product is for.
//
// Colour is reserved for security state. The chrome is achromatic, so the
// only coloured marks on a page are the ones that mean something is wrong,
// needs a decision, or is fine. See the note at the top of index.html.
//
// Change is the subject, not inventory. An agency's job is noticing that a
// site got worse, so the sites view leads with a written assessment and
// carries a run of recent scans per site rather than a single current
// number, which would hide exactly the thing worth seeing.

import { api, ApiError, rememberedEmail, session } from "./api.js";
import type {
  Cadence,
  Subscription,
  PreviewResult,
  ScanDetail,
  ScanSummary,
  Target,
  TriagedFinding,
} from "./api.js";
import { cleanDomain, rememberDomain, takeRememberedDomain } from "./carry.js";
import { append, byId, clear, copyableValue, el, on } from "./dom.js";
import { countOf, relativeTime, shortDate } from "./format.js";
import * as palette from "./palette.js";
import { postureChart, proportionBar } from "./chart.js";
import { siteProfile } from "./profile.js";

const root = () => byId<HTMLElement>("view");

/// How often to re-check a scan that is still running.
///
/// A full scan takes on the order of twenty minutes, so polling every few
/// seconds would be thousands of pointless requests. Ten seconds keeps the
/// page feeling live without that.
const SCAN_POLL_MS = 10_000;

/// How many past scans the history strip shows.
const HISTORY_LENGTH = 8;

let pollTimer: number | undefined;

function stopPolling(): void {
  if (pollTimer !== undefined) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

// --- shared pieces ---------------------------------------------------------

function notice(kind: "error" | "ok" | "info", message: string): HTMLElement {
  return el("p", { class: `notice notice-${kind}`, role: "status", text: message });
}

/// Turns a thrown value into something worth showing.
///
/// An expired session is handled rather than displayed: telling someone
/// "unauthorized" when the fix is to sign in again is a worse experience
/// than simply taking them there.
///
/// The two cases have to be told apart, though. Sign-in answers a wrong
/// password with 401 as well, and treating that as an expired session
/// showed "Your session expired" to someone who had simply mistyped —
/// while clearing a session they did not have. Only a request made *with*
/// a session can have had one expire.
function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "invalid_credentials") {
      return "That email and password do not match.";
    }

    if (error.isAuthFailure && session.isSignedIn) {
      session.clear();
      window.location.hash = "#/signin";
      return "Your session expired. Please sign in again.";
    }

    return error.message;
  }
  return "Something went wrong.";
}

function field(label: string, input: HTMLElement, hint?: HTMLElement | null): HTMLElement {
  return el("label", {}, [el("span", { class: "label-text", text: label }), input, hint ?? null]);
}

function submitButton(label: string): HTMLButtonElement {
  return el("button", { class: "primary", type: "submit", text: label });
}

/// Runs an async action while showing progress on the button that started
/// it, so a slow request cannot be mistaken for a dead one.
async function withPending<T>(
  button: HTMLButtonElement,
  pendingLabel: string,
  action: () => Promise<T>,
): Promise<T | undefined> {
  const original = button.textContent ?? "";
  button.disabled = true;
  button.textContent = pendingLabel;
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/// The placeholder shown while a view is fetching.
///
/// A shape rather than the word "loading": it occupies roughly what the
/// real content will, so the page does not jump when the data lands.
function skeleton(): HTMLElement {
  return el("ul", { class: "skeleton", "aria-label": "Loading" }, [
    el("li"),
    el("li"),
    el("li"),
  ]);
}

function sectionRule(title: string, count?: string): HTMLElement {
  return el("div", { class: "section-rule" }, [
    el("h2", { text: title }),
    count ? el("span", { class: "count", text: count }) : null,
  ]);
}

// --- sign in ---------------------------------------------------------------

function renderSignIn(): void {
  const container = root();
  clear(container);

  const message = el("div");
  const saved = rememberedEmail.get();

  const email = el("input", {
    type: "email",
    required: true,
    autocomplete: "email",
    value: saved ?? "",
  });
  const password = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const remember = el("input", { type: "checkbox", checked: saved !== null });
  const reveal = el("input", { type: "checkbox" });
  on(reveal, "change", () => {
    password.type = reveal.checked ? "text" : "password";
  });
  const button = submitButton("Sign in");

  const form = el("form", { class: "auth" }, [
    el("h1", { text: "Sign in" }),
    message,
    field("Email", email),
    field("Password", password),
    el("label", { class: "checkbox checkbox-compact" }, [reveal, "Show password"]),
    el("label", { class: "checkbox" }, [remember, "Remember my email on this device"]),
    button,
    el("p", { class: "switch" }, [
      "No account yet? ",
      el("a", { class: "inline", href: "#/signup", text: "Create one" }),
    ]),
    el("p", { class: "switch" }, [
      el("a", { class: "inline", href: "#/forgot", text: "Forgot your password?" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Signing in…", async () => {
      try {
        await api.login(email.value, password.value);
        rememberedEmail.set(remember.checked ? email.value.trim() : null);
        session.set();
        window.location.hash = "#/targets";
      } catch (error) {
        // An unconfirmed address is not a dead end: offer the way out
        // rather than only naming the problem.
        if (error instanceof ApiError && error.code === "email_not_verified") {
          message.replaceChildren(unconfirmedNotice(email.value));
          return;
        }
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  container.append(form);
  (saved ? password : email).focus();
}

/// Shown when the password was right but the address was never confirmed.
function unconfirmedNotice(email: string): HTMLElement {
  const wrapper = el("div");
  const resend = el("button", { class: "linklike", type: "button", text: "Send it again" });

  on(resend, "click", () => {
    void withPending(resend, "Sending…", async () => {
      try {
        const result = await api.resendVerification(email);
        wrapper.replaceChildren(notice("ok", result.message));
      } catch (error) {
        wrapper.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  wrapper.append(
    notice("info", "Confirm your email address before signing in."),
    // The spam folder is named before they go looking rather than after
    // they have given up. Mail from a domain that only recently started
    // sending is filtered often enough that leaving this to be discovered
    // turns a working product into a support ticket.
    el("p", { class: "switch", style: "margin:.9rem 0 2rem" }, [
      "Check your spam folder — a first message from a new sender often lands there. Still nothing? ",
      resend,
    ]),
  );
  return wrapper;
}

// --- sign up ---------------------------------------------------------------

/// `carried` is the domain the visitor checked on the front page, if they
/// arrived from that result rather than from a bare link. Saying it back to
/// them is the point: this form asks for seven fields and an email
/// round-trip, and the reason to fill it in is the site they were just
/// looking at. Held on to here so the first thing the account asks for is
/// already answered.
function renderSignUp(carried: string | null): void {
  const container = root();
  clear(container);

  if (carried) rememberDomain(carried);

  const message = el("div");
  const firstName = el("input", { type: "text", required: true, autocomplete: "given-name" });
  const lastName = el("input", { type: "text", required: true, autocomplete: "family-name" });
  const dateOfBirth = el("input", { type: "date", required: true, autocomplete: "bday" });
  const email = el("input", { type: "email", required: true, autocomplete: "email" });
  const password = el("input", {
    type: "password",
    required: true,
    autocomplete: "new-password",
    minlength: 12,
  });
  const confirmation = el("input", { type: "password", required: true, autocomplete: "new-password" });
  const reveal = el("input", { type: "checkbox" });
  const acceptedTerms = el("input", { type: "checkbox", required: true });
  const button = submitButton("Create account");

  on(reveal, "change", () => {
    const type = reveal.checked ? "text" : "password";
    password.type = type;
    confirmation.type = type;
  });

  // Checked as the user types rather than only on submit, so a mismatch is
  // caught before the form is sent and everything has to be retyped.
  const mismatch = el("span", { class: "hint hint-error", hidden: true });
  const checkMatch = (): void => {
    const differ = confirmation.value !== "" && confirmation.value !== password.value;
    mismatch.hidden = !differ;
    mismatch.textContent = differ ? "The passwords do not match." : "";
  };
  on(password, "input", checkMatch);
  on(confirmation, "input", checkMatch);

  const form = el("form", { class: "auth" }, [
    el("h1", { text: "Create your account" }),
    ...(carried
      ? [
          el("p", {
            class: "blurb",
            text: `${carried} will be waiting as your first site. Proving it is yours takes one DNS record.`,
          }),
        ]
      : []),
    message,
    el("div", { class: "field-pair" }, [
      field("First name", firstName),
      field("Last name", lastName),
    ]),
    field(
      "Date of birth",
      dateOfBirth,
      el("span", {
        class: "hint",
        text: "Required only to confirm that you can enter a commercial contract. It is not shown publicly and is removed when the account is deleted.",
      }),
    ),
    field("Email", email),
    field("Password", password, el("span", { class: "hint", text: "At least 12 characters." })),
    field("Repeat password", confirmation, mismatch),
    el("label", { class: "checkbox checkbox-compact" }, [reveal, "Show passwords"]),
    el("label", { class: "checkbox terms-check" }, [
      acceptedTerms,
      el("span", {}, [
        "I agree to the ",
        el("a", { class: "inline", href: "/terms.html", text: "Terms" }),
        " and acknowledge the ",
        el("a", { class: "inline", href: "/privacy.html", text: "Privacy Notice" }),
        ".",
      ]),
    ]),
    button,
    el("p", { class: "switch" }, [
      "Already have an account? ",
      el("a", { class: "inline", href: "#/signin", text: "Sign in" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    if (password.value !== confirmation.value) {
      checkMatch();
      confirmation.focus();
      return;
    }

    void withPending(button, "Creating…", async () => {
      try {
        const result = await api.signup({
          firstName: firstName.value,
          lastName: lastName.value,
          dateOfBirth: dateOfBirth.value,
          email: email.value,
          password: password.value,
          passwordConfirmation: confirmation.value,
        });
        renderCheckYourEmail(result.email, result.delivered);
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  container.append(form);
  firstName.focus();
}

/// The screen after signing up.
///
/// The account exists but cannot be used yet, so this says what happened
/// and what to do about it rather than dropping the user back at a sign-in
/// form that would refuse them.
function renderCheckYourEmail(email: string, delivered: boolean): void {
  const container = root();
  clear(container);

  const message = el("div");
  const resend = el("button", { class: "linklike", type: "button", text: "Send it again" });

  on(resend, "click", () => {
    clear(message);
    void withPending(resend, "Sending…", async () => {
      try {
        const result = await api.resendVerification(email);
        message.replaceChildren(notice("ok", result.message));
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  container.append(
    el("div", { class: "auth" }, [
      el("h1", { text: "Confirm your email" }),
      ...(delivered
        ? [
            el("p", {
              class: "blurb",
              text: `We sent a link to ${email}. Open it to finish setting up your account.`,
            }),
            // See unconfirmedNotice: said up front, because the message being
            // filtered is the common case rather than the unlucky one.
            el("p", {
              class: "muted",
              style: "margin:-1.5rem 0 2rem",
              text:
                "If it is not in your inbox within a minute, look in the spam folder — " +
                "a first message from a new sender often lands there.",
            }),
          ]
        : [
            // Nothing was sent, so telling somebody to watch their inbox
            // would leave them waiting on a message that is not coming.
            notice(
              "error",
              `We could not send the link to ${email}. The account exists — ` +
                "try again in a few minutes, or use the contact address at the " +
                "foot of glarion.app.",
            ),
          ]),
      message,
      el("p", { class: "switch" }, ["Nothing arrived? ", resend]),
      // A way out.
      //
      // Resending deliberately answers the same way whether or not the
      // address still needs confirming, so somebody who has already
      // followed the link — in another tab, or on their phone — is told
      // "a new link is on its way" and has nowhere to go.
      el("p", { class: "switch" }, [
        "Already confirmed? ",
        el("a", { class: "inline", href: "#/signin", text: "Sign in" }),
      ]),
    ]),
  );
}

/// Landing page for the link in the confirmation email.
async function renderVerify(token: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Confirming" }));

  try {
    await api.verifyEmail(token);
    // Signed in straight away: they have just proved they control the
    // address, so asking for the password again adds nothing.
    session.set();
    window.location.hash = "#/targets";
  } catch (error) {
    clear(container);
    container.append(
      el("div", { class: "auth" }, [
        el("h1", { text: "That link did not work" }),
        notice("error", describeError(error)),
        el("p", { class: "switch" }, [
          "You can ",
          el("a", { class: "inline", href: "#/signin", text: "sign in" }),
          " to request a new one.",
        ]),
      ]),
    );
  }
}

/// Asks for the address to send a reset link to.
///
/// The confirmation shown afterwards is deliberately the same sentence
/// whatever happened — sent, not sent, no such account. The API answers that
/// way for a reason (it must not become a way to test which addresses are
/// registered), and a screen that said "we could not find that account" would
/// hand back exactly what the API withheld.
function renderForgotPassword(): void {
  const container = root();
  clear(container);

  const message = el("div");
  const email = el("input", {
    type: "email",
    required: true,
    autocomplete: "email",
    value: rememberedEmail.get() ?? "",
  });
  const button = submitButton("Send the reset link");

  const form = el("form", { class: "auth" }, [
    el("h1", { text: "Reset your password" }),
    message,
    field(
      "Email",
      email,
      el("span", { class: "hint", text: "We will send a link that works once and lasts an hour." }),
    ),
    button,
    el("p", { class: "switch" }, [
      "Remembered it? ",
      el("a", { class: "inline", href: "#/signin", text: "Sign in" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Sending…", async () => {
      try {
        const result = await api.forgotPassword(email.value);
        clear(container);
        container.append(
          el("div", { class: "auth" }, [
            el("h1", { text: "Check your email" }),
            notice("ok", result.message),
            el("p", {
              class: "hint",
              text: "If nothing arrives in a few minutes, look in your spam folder before asking for another link.",
            }),
            el("p", { class: "switch" }, [
              el("a", { class: "inline", href: "#/signin", text: "Back to sign in" }),
            ]),
          ]),
        );
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  container.append(form);
  email.focus();
}

/// Landing page for the link in the reset email.
///
/// The token is never put in the DOM as a link and never re-sent anywhere
/// except this one request. Once it succeeds the session it returns is used
/// straight away: the person has just proved they control the address and
/// chosen the password, so a sign-in form here would ask them to prove the
/// same thing twice.
function renderResetPassword(token: string): void {
  const container = root();
  clear(container);

  const message = el("div");
  const password = el("input", {
    type: "password",
    required: true,
    autocomplete: "new-password",
    minlength: 12,
  });
  const confirmation = el("input", { type: "password", required: true, autocomplete: "new-password" });
  const button = submitButton("Set the new password");

  const mismatch = el("span", { class: "hint hint-error", hidden: true });
  const checkMatch = (): void => {
    const differ = confirmation.value !== "" && confirmation.value !== password.value;
    mismatch.hidden = !differ;
    mismatch.textContent = differ ? "The passwords do not match." : "";
  };
  on(password, "input", checkMatch);
  on(confirmation, "input", checkMatch);

  const form = el("form", { class: "auth" }, [
    el("h1", { text: "Choose a new password" }),
    message,
    field("New password", password, el("span", { class: "hint", text: "At least 12 characters." })),
    field("Repeat password", confirmation, mismatch),
    el("p", {
      class: "hint",
      text: "Everywhere you are currently signed in will be signed out.",
    }),
    button,
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    if (password.value !== confirmation.value) {
      checkMatch();
      confirmation.focus();
      return;
    }

    void withPending(button, "Saving…", async () => {
      try {
        await api.resetPassword(token, password.value, confirmation.value);
        session.set();
        window.location.hash = "#/targets";
      } catch (error) {
        message.replaceChildren(
          notice("error", describeError(error)),
          el("p", { class: "switch" }, [
            "Links expire after an hour. You can ",
            el("a", { class: "inline", href: "#/forgot", text: "ask for a new one" }),
            ".",
          ]),
        );
      }
    });
  });

  container.append(form);
  password.focus();
}

// --- sites -----------------------------------------------------------------

/// The state a site is in, as one word.
///
/// Everything visual keys off this: the spine colour, the wording, the
/// order rows appear in. Deriving it once means those three cannot drift
/// apart and start telling the reader different things.
type SiteState = "alarm" | "caution" | "clear" | "idle";

interface SiteRow {
  target: Target;
  /// Newest first.
  scans: ScanSummary[];
  latest: ScanSummary | undefined;
  state: SiteState;
}

function stateOf(target: Target, latest: ScanSummary | undefined): SiteState {
  if (!target.verified) return "caution";
  if (!latest) return "idle";
  if (latest.status === "failed") return "caution";
  if (latest.status !== "completed") return "idle";
  return latest.actionable_count > 0 ? "alarm" : "clear";
}

function buildRows(targets: Target[], scans: ScanSummary[]): SiteRow[] {
  const rows = targets.map((target) => {
    const own = scans.filter((scan) => scan.target_id === target.id);
    const latest = own[0];
    return { target, scans: own, latest, state: stateOf(target, latest) };
  });

  // Worst first. A list sorted by name makes somebody read all of it to
  // find the one thing that needs doing today.
  const order: Record<SiteState, number> = { alarm: 0, caution: 1, idle: 2, clear: 3 };
  return rows.sort(
    (a, b) => order[a.state] - order[b.state] || a.target.domain.localeCompare(b.target.domain),
  );
}

async function renderTargets(): Promise<void> {
  const container = root();
  clear(container);
  container.append(skeleton());

  let rows: SiteRow[];
  try {
    const [targets, scans] = await Promise.all([api.targets(), api.scans()]);
    rows = buildRows(targets, scans);
  } catch (error) {
    clear(container);
    container.append(notice("error", describeError(error)));
    return;
  }

  clear(container);

  if (rows.length === 0) {
    container.append(firstRun());
    return;
  }

  const addPanel = addTargetForm();
  addPanel.hidden = true;

  const addButton = el("button", { class: "ghost", type: "button", text: "Add a site" });
  on(addButton, "click", () => {
    addPanel.hidden = !addPanel.hidden;
    if (!addPanel.hidden) addPanel.querySelector("input")?.focus();
  });

  container.append(
    standingStatement(rows),
    el("div", { class: "head-row" }, [el("div"), addButton]),
    addPanel,
    sectionRule("Sites", countOf(rows.length, "site")),
  );

  const ledger = el("ul", { class: "ledger" });
  for (const row of rows) {
    ledger.append(siteEntry(row));
  }
  container.append(ledger);

  // Registered after render so the palette offers exactly what is on
  // screen, rather than a copy captured when it was last opened.
  palette.setCommands(() => [
    ...rows.map((row) => ({
      group: "Sites",
      label: row.target.domain,
      detail: row.target.client_name ?? undefined,
      keywords: row.state,
      run: () => {
        window.location.hash = `#/targets/${row.target.id}`;
      },
    })),
    ...standardCommands(),
  ]);
}

/// Commands available from anywhere.
function standardCommands(): palette.Command[] {
  return [
    {
      group: "Go to",
      label: "Sites",
      run: () => {
        window.location.hash = "#/targets";
      },
    },
    {
      group: "Go to",
      label: "Pricing",
      keywords: "billing upgrade subscription plan invoice",
      run: () => {
        window.location.hash = "#/plan";
      },
    },
    {
      group: "Go to",
      label: "Settings",
      run: () => {
        window.location.hash = "#/settings";
      },
    },
    {
      group: "Account",
      label: "Sign out",
      run: () => {
        session.clear();
        window.location.hash = "#/signin";
      },
    },
  ];
}

/// The assessment, written out.
///
/// Three numbers in boxes leave the reader to work out what they add up
/// to. A sentence has already done that, and the coloured words keep it
/// scannable — the shape of the line tells you the answer before you have
/// read it.
function standingStatement(rows: SiteRow[]): HTMLElement {
  const alarm = rows.filter((row) => row.state === "alarm").length;
  const caution = rows.filter((row) => row.state === "caution").length;
  const idle = rows.filter((row) => row.state === "idle").length;

  const line = el("p", { class: "standing" });

  if (alarm > 0) {
    line.append(
      el("span", { class: "alarm", text: countOf(alarm, "site") }),
      ` ${alarm === 1 ? "needs" : "need"} work`,
    );
    if (caution > 0) {
      line.append(", ", el("span", { class: "caution", text: String(caution) }), " awaiting setup");
    }
    line.append(".");
  } else if (caution > 0) {
    line.append(
      "Nothing to fix. ",
      el("span", { class: "caution", text: countOf(caution, "site") }),
      ` still ${caution === 1 ? "needs" : "need"} setting up.`,
    );
  } else if (idle > 0 && idle === rows.length) {
    line.append("Everything is set up. ", el("strong", { text: "Run your first scan." }));
  } else {
    line.append(el("span", { class: "clear", text: "Everything is clear" }), " across your sites.");
  }

  const newest = rows
    .map((row) => row.latest)
    .filter((scan): scan is ScanSummary => scan !== undefined)
    .map((scan) => scan.completed_at ?? scan.created_at)
    .sort()
    .pop();

  return el("div", {}, [
    line,
    el("p", {
      class: "standing-meta",
      text: newest ? `Last checked ${relativeTime(newest)}` : "No scans yet",
    }),
  ]);
}

function siteEntry(row: SiteRow): HTMLElement {
  const { target, latest, state } = row;

  const detail = el("div", { class: "entry-state" });

  if (!target.verified) {
    detail.append(el("span", { class: "headline", text: "Awaiting domain check" }));
  } else if (!latest) {
    detail.append(el("span", { text: "Ready to scan" }));
  } else if (latest.status === "queued" || latest.status === "running") {
    detail.append(el("span", { text: "Scan running" }));
  } else if (latest.status === "failed") {
    detail.append(el("span", { class: "headline", text: "Last scan did not finish" }));
  } else {
    detail.append(
      latest.actionable_count > 0
        ? el("span", { class: "headline", text: `${latest.actionable_count} to fix` })
        : el("span", { class: "headline", text: "Clear" }),
      el("span", { class: "sep", text: "/" }),
      el("span", { text: relativeTime(latest.completed_at ?? latest.created_at) }),
    );
  }

  // Which sites are actually being watched, and which are only ever
  // checked when somebody remembers. That is the difference between a
  // service and a tool, so it belongs on the list.
  if (target.scan_cadence !== "manual") {
    detail.append(
      el("span", { class: "sep", text: "/" }),
      el("span", { class: "watching", text: target.scan_cadence }),
    );
  }

  return el("li", {}, [
    el("a", { class: `entry entry-${state}`, href: `#/targets/${target.id}` }, [
      el("div", {}, [
        el("div", { class: "entry-name", text: target.domain }),
        target.client_name ? el("div", { class: "entry-client", text: target.client_name }) : null,
        detail,
      ]),
      el("div", { class: "entry-right" }, [
        severitySplit(row),
        historyStrip(row),
        el("span", { class: "entry-go", text: "→" }),
      ]),
    ]),
  ]);
}

/// How the outstanding work splits by rank.
///
/// "3 to fix" does not distinguish one serious problem plus two notes from
/// three serious problems, and those are different afternoons. The split is
/// only fetched for the scan being shown in detail, so on the list it is
/// derived from what the summary already carries: the ranks are not in the
/// list payload, so this shows magnitude only when there is nothing better.
function severitySplit(row: SiteRow): HTMLElement | null {
  const latest = row.latest;
  if (!latest || latest.status !== "completed" || latest.actionable_count === 0) return null;

  const split = el("div", {
    class: "split",
    role: "img",
    "aria-label": countOf(latest.actionable_count, "item") + " to fix",
  });

  // Capped so a bad site does not draw a wall of marks; the number beside
  // it is the exact figure.
  const marks = Math.min(latest.actionable_count, 6);
  for (let index = 0; index < marks; index += 1) {
    split.append(el("span", { class: "split-mark split-high" }));
  }

  return split;
}

/// The last few scans, oldest on the left.
///
/// This is the thing a single number cannot say. A site that went from
/// clear to three issues is a different situation from one that has had
/// three all along, and only the shape of a run shows which is which.
function historyStrip(row: SiteRow): HTMLElement {
  const completed = row.scans
    .filter((scan) => scan.status === "completed")
    .slice(0, HISTORY_LENGTH)
    .reverse();

  if (completed.length === 0) {
    return el("span", { class: "history-empty", text: "no history" });
  }

  const strip = el("div", {
    class: "history",
    role: "img",
    // The bars are decoration to a screen reader without this; the state
    // is already in the text beside them, so one summary is enough.
    "aria-label": `Last ${countOf(completed.length, "scan")}`,
  });

  const worst = Math.max(1, ...completed.map((scan) => scan.actionable_count));

  for (const scan of completed) {
    // A clear result still gets a visible mark: a gap would read as
    // missing data rather than as good news.
    const share = scan.actionable_count / worst;
    const height = scan.actionable_count === 0 ? 4 : 8 + Math.round(share * 18);

    strip.append(
      el("span", {
        class: "history-bar",
        style: `height:${height}px`,
        title: `${scan.actionable_count === 0 ? "Clear" : `${scan.actionable_count} to fix`} — ${relativeTime(scan.completed_at ?? scan.created_at)}`,
      }),
    );
  }

  return strip;
}

/// What a new customer sees first.
///
/// Written as a procedure rather than as three tiles, because that is what
/// it is. It also says plainly that step two involves their DNS — the part
/// nobody expects, and the reason setup gets abandoned halfway.
function firstRun(): HTMLElement {
  const step = (n: string, title: string, body: string): HTMLElement =>
    el("li", { "data-step": n }, [el("h3", { text: title }), el("p", { text: body })]);

  return el("div", {}, [
    el("h1", { text: "Add your first site" }),
    el("p", {
      class: "blurb",
      text:
        "Glarion checks a website for security problems and turns the result into " +
        "a short report you can hand straight to your client.",
    }),
    el("ol", { class: "procedure" }, [
      step("1", "Add the site", "Its domain, and which client it belongs to."),
      step(
        "2",
        "Prove the domain is yours",
        "A one-time DNS record. We only ever scan sites whose owner asked us to.",
      ),
      step("3", "Scan, then send", "Run a scan and download the report under your own name."),
    ]),
    el("div", { style: "margin-top:2.5rem" }, [addTargetForm()]),
  ]);
}

function addTargetForm(): HTMLElement {
  const message = el("div");
  const domain = el("input", {
    type: "text",
    placeholder: "client-site.com",
    required: true,
    autocapitalize: "none",
    autocorrect: "off",
    spellcheck: false,
  });
  const client = el("input", { type: "text", placeholder: "Optional" });
  const button = submitButton("Add");

  // The domain from the free check, if this account was opened off the back
  // of one. Taken rather than read: it belongs in the box once, and after
  // that the box is the user's.
  const remembered = takeRememberedDomain();
  if (remembered) domain.value = remembered;

  const form = el("form", {}, [
    message,
    el("div", { class: "field-row" }, [
      field("Domain", domain),
      field("Client", client),
      el("div", {}, [button]),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Adding…", async () => {
      try {
        const target = await api.addTarget(domain.value, client.value || null);
        window.location.hash = `#/targets/${target.id}`;
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return form;
}

// --- one site --------------------------------------------------------------

async function renderTarget(targetId: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(skeleton());

  let target: Target | undefined;
  let scans: ScanSummary[] = [];
  let latestDetail: ScanDetail | undefined;
  try {
    const [targets, scanList] = await Promise.all([api.targets(), api.scans(targetId)]);
    target = targets.find((candidate) => candidate.id === targetId);
    scans = scanList;

    // The most recent finished scan carries everything the profile and the
    // summary need. Fetched separately because the list endpoint returns
    // counts rather than findings, and loading every scan's findings to
    // render one page would be wasteful.
    const newest = scanList.find((scan) => scan.status === "completed");
    if (newest) latestDetail = await api.scan(newest.id);
  } catch (error) {
    clear(container);
    container.append(notice("error", describeError(error)));
    return;
  }

  if (!target) {
    clear(container);
    container.append(notice("error", "That site could not be found."));
    return;
  }

  clear(container);
  container.append(el("a", { class: "back", href: "#/targets", text: "← Sites" }));

  const site = target;
  container.append(
    el("div", { class: "head-row" }, [
      el("div", {}, [
        el("h1", { class: "mono", text: site.domain }),
        site.client_name ? el("p", { class: "lede", text: site.client_name }) : null,
      ]),
    ]),
  );

  if (site.verified) {
    append(
      container,
      expiryNote(site),
      latestDetail ? currentState(latestDetail) : null,
      postureSection(scans),
      latestDetail ? knownFacts(latestDetail) : null,
      cadenceControl(site),
      scansSection(site, scans),
    );
  } else {
    // The preview goes first, above the request for a DNS record.
    //
    // Asking somebody to edit a client's DNS before they have seen this
    // product do anything is the worst possible order, and it is where
    // setup was being abandoned. Everything in the preview is read from
    // what the site already publishes, so it needs no permission — and
    // seeing two real problems is a far better reason to finish the domain
    // check than being told to.
    // The preview, then the case for going further, then the procedure that
    // gets you there. The middle block is the one that was missing: people
    // saw a short list of headers, were asked to edit a client's DNS, and
    // had no way of knowing what they would get for it.
    const check = verificationSection(site);
    append(container, previewSection(site.domain), unlockSection(check.start), check.element);
  }
}

function expiryNote(target: Target): HTMLElement | null {
  if (!target.verification_expires_at) return null;

  return el("p", {
    class: "mono-note",
    style: "margin: -0.75rem 0 2.25rem",
    text: `Domain confirmed · recheck by ${shortDate(target.verification_expires_at)}`,
  });
}

/// What can be shown before anyone has proved anything.
function previewSection(domain: string): HTMLElement {
  const body = el("div");
  const section = el("div", { style: "margin-bottom:3rem" }, [
    sectionRule("A first look"),
    el("p", {
      class: "blurb",
      style: "margin-top:1rem",
      text:
        "Read from what this site already publishes to any visitor, so it needs " +
        "no permission from anyone.",
    }),
    body,
  ]);

  body.append(skeleton());

  void api
    .preview(domain)
    .then((result) => {
      body.replaceChildren(previewBody(result));
    })
    .catch((error: unknown) => {
      // A preview that cannot run is not a failure of the page: the domain
      // check below still works, so this says so quietly and gets out of
      // the way.
      body.replaceChildren(notice("info", describeError(error)));
    });

  return section;
}

function previewBody(result: PreviewResult): HTMLElement {
  const findings = result.observations.filter((observation) => observation.is_finding);

  const line = el("p", { class: "standing", style: "margin-bottom:1.25rem" });
  if (findings.length === 0) {
    line.append(
      el("span", { class: "clear", text: "Nothing obvious" }),
      " from the outside.",
    );
  } else {
    line.append(
      el("span", { class: "alarm", text: countOf(findings.length, "thing") }),
      " visible without looking hard.",
    );
  }

  const grid = el("div", { class: "facts" });
  for (const observation of result.observations) {
    grid.append(
      el("div", { class: observation.is_finding ? "fact fact-flagged" : "fact" }, [
        el("span", { class: "fact-label", text: observation.label }),
        el("span", { class: "fact-value", text: observation.value }),
      ]),
    );
  }

  const wrapper = el("div", {}, [line, grid]);

  for (const note of result.notes) {
    wrapper.append(el("p", { class: "hint", style: "margin-top:1rem", text: note }));
  }

  // The caveat comes from the server with the data, so a clean preview can
  // never be mistaken for a clean site.
  wrapper.append(el("p", { class: "hint", style: "margin-top:1.25rem", text: result.caveat }));

  return wrapper;
}

/// The screen that decides whether anyone ever sees a report.
///
/// It asks the reader to leave the product, sign in to a DNS provider, and
/// paste an exact string, so it is laid out as a procedure. The record is
/// split into its two parts with a copy control on each, since retyping a
/// random token is the likeliest way for the step to fail, and the wait for
/// propagation is stated before it happens rather than after the check
/// looks broken.
function verificationSection(target: Target): {
  element: HTMLElement;
  start: HTMLButtonElement;
} {
  const body = el("div");
  const section = el("div", { id: "domain-check" }, [
    sectionRule("Domain check"),
    el("p", {
      class: "blurb",
      style: "margin-top:1.25rem",
      text:
        "A full scan probes far more than the check above, so it only runs on sites " +
        "whose owner has asked us to. Publish the record below and we will confirm " +
        "it. One time, valid for 30 days, on any DNS provider.",
    }),
    body,
  ]);

  const start = el("button", { class: "primary", type: "button", text: "Show me the record" });
  body.append(start);

  on(start, "click", () => {
    void withPending(start, "Preparing…", async () => {
      try {
        const instructions = await api.startVerification(target.id);
        body.replaceChildren(verificationInstructions(target, instructions));
      } catch (error) {
        body.replaceChildren(notice("error", describeError(error)), start);
      }
    });
  });

  return { element: section, start };
}

/// What the full scan adds, and how to get it.
///
/// The gap this closes was the whole shape of the product to a new account:
/// the free check reads a handful of headers, and then the page asked for a
/// DNS record without ever saying what the record buys. Nobody edits a
/// client's DNS on a maybe.
///
/// Everything listed is something the scanner actually does — see
/// `orchestrator::tools` and `orchestrator::triage`. The price of the step
/// is stated in the same breath as the list, because the honest answer is
/// the persuasive one here: the full scan is on the free plan too, and the
/// only thing standing between the reader and it is proof that the domain
/// is theirs to scan.
const FULL_SCAN_ADDS: [string, string][] = [
  ["Known vulnerabilities", "Thousands of public fingerprints, matched against what this site actually runs."],
  ["Exposure", "Admin panels, config files, backups and dashboards reachable without a password."],
  ["Software age", "Versions on show, and the published CVEs that go with them."],
  ["The whole certificate chain", "Issuer, names covered, renewal date, and how the handshake is configured."],
  ["Ranked, not listed", "Every finding sorted by what it would cost you, with the fix written out."],
  ["A report you can send", "One page a client can read, under your name rather than ours."],
];

function unlockSection(start: HTMLButtonElement): HTMLElement {
  const list = el("div", { class: "locked" });
  for (const [label, detail] of FULL_SCAN_ADDS) {
    list.append(
      el("div", { class: "locked-item" }, [
        el("span", { class: "locked-mark", "aria-hidden": "true", text: "◇" }),
        el("div", {}, [
          el("span", { class: "locked-label", text: label }),
          el("span", { class: "locked-detail", text: detail }),
        ]),
      ]),
    );
  }

  const button = el("button", {
    class: "primary",
    type: "button",
    text: "Unlock the full scan",
  });

  // Scrolls to the procedure and opens it in one action. Two separate steps
  // — find the section, then press the button in it — is where a reader who
  // was persuaded stops being persuaded.
  on(button, "click", () => {
    document.getElementById("domain-check")?.scrollIntoView({ behavior: "smooth", block: "start" });
    if (!start.disabled) start.click();
  });

  return el("div", { class: "unlock" }, [
    sectionRule("The full scan"),
    el("p", {
      class: "blurb",
      style: "margin-top:1rem",
      text:
        "The check above reads what the site hands to every visitor. The full scan " +
        "goes looking, which is why it needs your permission first.",
    }),
    list,
    el("div", { class: "unlock-foot" }, [
      button,
      el("p", { class: "hint", style: "margin:0" }, [
        "Free on your first site. ",
        el("a", { class: "inline", href: "#/plan", text: "The paid plans" }),
        " add more sites, weekly re-checks without asking, and your own name on the report.",
      ]),
    ]),
  ]);
}

function verificationInstructions(
  target: Target,
  instructions: {
    dns_record_name: string;
    dns_record_value: string;
    well_known_url: string;
    well_known_content: string;
  },
): HTMLElement {
  const message = el("div");
  const check = el("button", { class: "primary", type: "button", text: "Check now" });

  let method: "dns_txt" | "well_known_file" = "dns_txt";

  const dnsPane = el("div", { class: "method-pane" }, [
    el("dl", { class: "kv" }, [
      el("dt", { text: "Type" }),
      el("dd", { text: "TXT" }),
      el("dt", { text: "Name" }),
      el("dd", {}, [copyableValue(instructions.dns_record_name, "record name")]),
      el("dt", { text: "Value" }),
      el("dd", {}, [copyableValue(instructions.dns_record_value, "record value")]),
    ]),
    el("p", {
      class: "hint",
      style: "margin-top:1.1rem",
      text:
        "DNS usually updates within a few minutes, though some providers take up " +
        "to an hour. If the check does not find it yet, wait and try again.",
    }),
  ]);

  const filePane = el("div", { class: "method-pane", hidden: true }, [
    el("dl", { class: "kv" }, [
      el("dt", { text: "Address" }),
      el("dd", {}, [copyableValue(instructions.well_known_url, "file address")]),
      el("dt", { text: "Contents" }),
      el("dd", {}, [copyableValue(instructions.well_known_content, "file contents")]),
    ]),
    el("p", {
      class: "hint",
      style: "margin-top:1.1rem",
      text: "The file must be reachable over HTTPS and contain only that value.",
    }),
  ]);

  const dnsTab = el("button", { class: "tab tab-active", type: "button", text: "DNS record" });
  const fileTab = el("button", { class: "tab", type: "button", text: "File upload" });

  function select(next: "dns_txt" | "well_known_file"): void {
    method = next;
    const isDns = next === "dns_txt";
    dnsPane.hidden = !isDns;
    filePane.hidden = isDns;
    dnsTab.className = isDns ? "tab tab-active" : "tab";
    fileTab.className = isDns ? "tab" : "tab tab-active";
    clear(message);
  }

  on(dnsTab, "click", () => select("dns_txt"));
  on(fileTab, "click", () => select("well_known_file"));

  on(check, "click", () => {
    clear(message);
    void withPending(check, "Checking…", async () => {
      try {
        const result = await api.checkVerification(target.id, method);
        if (result.verified) {
          message.replaceChildren(notice("ok", "Confirmed."));
          window.setTimeout(() => void renderTarget(target.id), 700);
        } else {
          message.replaceChildren(notice("info", result.detail));
        }
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return el("div", { style: "margin-top:1.75rem" }, [
    el("div", { class: "tabs" }, [dnsTab, fileTab]),
    dnsPane,
    filePane,
    el("div", { style: "margin-top:1.75rem" }, [message, check]),
  ]);
}

/// Where the site stands right now, before any history or detail.
///
/// The page used to open with a schedule control and a list of scan rows,
/// which answered "what have we done" rather than "how is the site" — and
/// the second is the only question anybody arrives with.
function currentState(detail: ScanDetail): HTMLElement {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const finding of detail.triaged.actionable) {
    if (finding.priority === "urgent" || finding.priority === "high") counts.high += 1;
    else if (finding.priority === "medium") counts.medium += 1;
    else counts.low += 1;
  }

  const total = detail.triaged.actionable.length;
  const line = el("p", { class: "standing", style: "margin-bottom:.75rem" });

  if (total === 0) {
    line.append(el("span", { class: "clear", text: "Nothing to fix" }), " on this site.");
  } else {
    line.append(
      el("span", { class: "alarm", text: countOf(total, "thing") }),
      " to fix, ",
      el("span", { class: "caution", text: String(detail.triaged.review.length) }),
      " to decide.",
    );
  }

  const bar = proportionBar([
    { count: counts.high, className: "part-alarm", label: "high" },
    { count: counts.medium, className: "part-caution", label: "medium" },
    { count: counts.low, className: "part-low", label: "low" },
    { count: total === 0 ? 1 : 0, className: "part-clear", label: "clear" },
  ]);

  const legend = el("div", { class: "legend" });
  const swatch = (className: string, text: string, count: number): HTMLElement | null =>
    count === 0
      ? null
      : el("span", { class: "legend-item" }, [
          el("span", { class: `legend-swatch ${className}` }),
          `${count} ${text}`,
        ]);

  append(
    legend,
    swatch("part-alarm", "high", counts.high),
    swatch("part-caution", "medium", counts.medium),
    swatch("part-low", "low", counts.low),
    el("span", { class: "legend-item" }, [
      `${countOf(detail.finding_count, "check")} run`,
    ]),
  );

  const open = el("a", { class: "ghost", href: `#/scans/${detail.id}`, text: "See the detail →" });

  return el("div", { style: "margin-bottom:2.75rem" }, [
    line,
    bar,
    legend,
    el("div", { style: "margin-top:1.25rem" }, [open]),
  ]);
}

/// How the site has moved over its last few scans.
///
/// The single most useful thing an agency can show a client at renewal: a
/// line that came down and stayed down is the argument for the retainer.
function postureSection(scans: ScanSummary[]): HTMLElement | null {
  const completed = scans
    .filter((scan) => scan.status === "completed")
    .slice(0, 12)
    .reverse();

  // One point is not a trend, and a chart of it invites reading a shape
  // that is not there.
  if (completed.length < 2) return null;

  const points = completed.map((scan) => ({
    value: scan.actionable_count,
    label: relativeTime(scan.completed_at ?? scan.created_at),
  }));

  const first = completed[0];
  const last = completed[completed.length - 1];

  return el("div", { style: "margin-bottom:2.75rem" }, [
    sectionRule("Over time", countOf(completed.length, "scan")),
    el("div", { class: "chart-frame" }, [postureChart(points)]),
    el("div", { class: "chart-axis" }, [
      el("span", { text: first ? relativeTime(first.completed_at ?? first.created_at) : "" }),
      el("span", { text: last ? relativeTime(last.completed_at ?? last.created_at) : "" }),
    ]),
  ]);
}

/// What the scan learned about the site, beyond what is wrong with it.
///
/// All of this was already being collected and filed in an appendix nobody
/// read. An agency about to speak to a client wants to know what the site
/// *is* before it hears what is wrong with it.
function knownFacts(detail: ScanDetail): HTMLElement | null {
  const facts = siteProfile(detail.triaged.inventory);
  if (facts.length === 0) return null;

  const grid = el("div", { class: "facts" });
  for (const fact of facts) {
    grid.append(
      el("div", { class: "fact" }, [
        el("span", { class: "fact-label", text: fact.label }),
        el("span", { class: "fact-value", text: fact.value }),
      ]),
    );
  }

  return el("div", { style: "margin-bottom:2.75rem" }, [
    sectionRule("What we found", countOf(facts.length, "detail")),
    grid,
  ]);
}

/// Turning recurring scanning on or off.
///
/// The whole subscription rests on this switch: a tool somebody has to
/// remember to run gets used once, while a site that is checked every week
/// is a service worth paying for every month. So it sits above the scan
/// list rather than in a settings page nobody opens.
function cadenceControl(target: Target): HTMLElement {
  const message = el("div");
  const options: Array<{ value: Cadence; label: string }> = [
    { value: "manual", label: "Off" },
    { value: "weekly", label: "Weekly" },
    { value: "monthly", label: "Monthly" },
  ];

  const buttons = new Map<Cadence, HTMLButtonElement>();
  const row = el("div", { class: "tabs", style: "margin-bottom:1.1rem" });

  let current = target.scan_cadence;

  function paint(): void {
    for (const [value, button] of buttons) {
      button.className = value === current ? "tab tab-active" : "tab";
    }
  }

  for (const option of options) {
    const button = el("button", { class: "tab", type: "button", text: option.label });
    buttons.set(option.value, button);

    on(button, "click", () => {
      if (current === option.value) return;
      const previous = current;

      // Painted before the request so the switch feels immediate; put back
      // if the server refuses, rather than leaving a lie on screen.
      current = option.value;
      paint();
      clear(message);

      void api
        .setCadence(target.id, option.value)
        .then(() => {
          message.replaceChildren(
            notice(
              "ok",
              option.value === "manual"
                ? "Automatic checks are off."
                : `Checking ${option.label.toLowerCase()}. We will email you only when something changes.`,
            ),
          );
        })
        .catch((error: unknown) => {
          current = previous;
          paint();
          message.replaceChildren(notice("error", describeError(error)));
        });
    });

    row.append(button);
  }

  paint();

  return el("div", { style: "margin-bottom:2.5rem" }, [
    sectionRule("Automatic checks"),
    el("p", {
      class: "blurb",
      style: "margin:1rem 0 1.1rem",
      text: "We re-check the site on this schedule and email you only when the result changes.",
    }),
    row,
    message,
  ]);
}

function scansSection(target: Target, scans: ScanSummary[]): HTMLElement {
  const message = el("div");
  const list = el("ul", { class: "ledger" });
  const start = el("button", { class: "primary", type: "button", text: "Run a scan" });

  const section = el("div", {}, [
    el("div", { class: "head-row", style: "margin-bottom:1.25rem" }, [
      el("div", {}, [sectionRule("Scans")]),
      start,
    ]),
    message,
    list,
  ]);

  function paint(current: ScanSummary[]): void {
    clear(list);
    if (current.length === 0) {
      list.append(el("p", { class: "muted", text: "No scans yet." }));
      return;
    }
    for (const scan of current) {
      list.append(scanEntry(scan));
    }
  }

  paint(scans);

  // Poll only while something is unfinished, and stop as soon as everything
  // has settled so an idle tab is not making requests forever.
  const pending = (list_: ScanSummary[]) =>
    list_.some((scan) => scan.status === "queued" || scan.status === "running");

  function schedule(current: ScanSummary[]): void {
    stopPolling();
    if (!pending(current)) return;

    pollTimer = window.setInterval(() => {
      void api
        .scans(target.id)
        .then((updated) => {
          paint(updated);
          if (!pending(updated)) stopPolling();
        })
        .catch(() => {
          // A transient failure should not kill the page; the next tick
          // tries again.
        });
    }, SCAN_POLL_MS);
  }

  schedule(scans);

  on(start, "click", () => {
    clear(message);
    void withPending(start, "Starting…", async () => {
      try {
        await api.startScan(target.id);
        const updated = await api.scans(target.id);
        paint(updated);
        schedule(updated);
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return section;
}

function scanEntry(scan: ScanSummary): HTMLElement {
  const state: SiteState =
    scan.status === "failed"
      ? "caution"
      : scan.status !== "completed"
        ? "idle"
        : scan.actionable_count > 0
          ? "alarm"
          : "clear";

  const headline =
    scan.status === "queued"
      ? "Queued"
      : scan.status === "running"
        ? "Running"
        : scan.status === "failed"
          ? "Did not finish"
          : scan.actionable_count > 0
            ? `${scan.actionable_count} to fix`
            : "Clear";

  const detail = el("div", { class: "entry-state" }, [
    el("span", { class: "headline", text: headline }),
    el("span", { class: "sep", text: "/" }),
    el("span", { text: relativeTime(scan.completed_at ?? scan.created_at) }),
    scan.status === "completed"
      ? el("span", {}, [
          el("span", { class: "sep", text: "/" }),
          ` ${countOf(scan.finding_count, "check")}`,
        ])
      : null,
    scan.status === "failed" && scan.failure_reason
      ? el("span", { class: "muted", text: scan.failure_reason })
      : null,
  ]);

  const inner = el("div", {}, [detail]);

  if (scan.status === "completed") {
    return el("li", {}, [
      el("a", { class: `entry entry-${state}`, href: `#/scans/${scan.id}` }, [
        inner,
        el("span", { class: "entry-go", text: "→" }),
      ]),
    ]);
  }

  return el("li", {}, [el("div", { class: `entry entry-${state}` }, [inner])]);
}

// --- one scan --------------------------------------------------------------

async function renderScan(scanId: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(skeleton());

  let detail: ScanDetail;
  try {
    detail = await api.scan(scanId);
  } catch (error) {
    clear(container);
    container.append(notice("error", describeError(error)));
    return;
  }

  clear(container);

  const download = el("button", { class: "primary", type: "button", text: "Download report" });
  const message = el("div");

  on(download, "click", () => {
    clear(message);
    void withPending(download, "Building…", async () => {
      try {
        await api.downloadReport(detail.id, detail.domain);
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  const actionable = detail.triaged.actionable.length;
  const verdict = el("p", { class: "standing" });
  if (actionable > 0) {
    verdict.append(
      el("span", { class: "alarm", text: countOf(actionable, "thing") }),
      ` to fix on `,
      el("strong", { text: detail.domain }),
      ".",
    );
  } else {
    verdict.append(
      el("span", { class: "clear", text: "Nothing to fix" }),
      " on ",
      el("strong", { text: detail.domain }),
      ".",
    );
  }

  container.append(
    el("a", { class: "back", href: `#/targets/${detail.target_id}`, text: `← ${detail.domain}` }),
    verdict,
    el("p", {
      class: "standing-meta",
      text: `${countOf(detail.finding_count, "check")} · ${detail.triaged.review.length} to decide · scanned ${relativeTime(detail.completed_at ?? detail.created_at)}`,
    }),
    el("div", { class: "head-row", style: "margin-bottom:2rem" }, [el("div"), download]),
    message,
  );

  if (detail.triaged.actionable.length > 0) {
    container.append(sectionRule("Fix these", countOf(detail.triaged.actionable.length, "item")));
    container.append(worklist(detail.triaged.actionable));
  }

  if (detail.triaged.review.length > 0) {
    container.append(
      el("div", { style: "margin-top:2.75rem" }, [
        sectionRule("Your call", countOf(detail.triaged.review.length, "item")),
        worklist(detail.triaged.review),
      ]),
    );
  }

  if (detail.triaged.inventory.length > 0) {
    const items = el("ul", { class: "appendix" });
    for (const finding of detail.triaged.inventory) {
      items.append(el("li", { text: finding.title }));
    }
    container.append(
      el("div", { style: "margin-top:2.75rem" }, [
        sectionRule("Checked, nothing to report", String(detail.triaged.inventory.length)),
        el("div", { style: "margin-top:1.1rem" }, [items]),
      ]),
    );
  }
}

/// Findings as a numbered worklist, in the order they should be dealt with.
///
/// A grid of cards implies the reader picks one. A numbered list says where
/// to start, which is what somebody with an hour and a client site wants.
function worklist(findings: TriagedFinding[]): HTMLElement {
  const list = el("ol", { class: "worklist" });

  for (const finding of findings) {
    list.append(
      el("li", { class: "work-item" }, [
        el("div", { class: "work-head" }, [
          el("h3", { text: finding.title }),
          el("span", { class: `rank rank-${finding.priority}`, text: finding.priority }),
          finding.occurrences > 1
            ? el("span", { class: "work-repeat", text: `×${finding.occurrences}` })
            : null,
        ]),
        finding.guidance ? el("p", { class: "work-why", text: finding.guidance.why }) : null,
        finding.guidance
          ? el("div", { class: "work-fix" }, [
              el("span", { class: "work-label", text: "Do this" }),
              finding.guidance.fix,
            ])
          : null,
        finding.evidence
          ? el("p", { class: "work-evidence" }, [
              el("span", { class: "work-label", text: "Observed" }),
              el("code", { text: finding.evidence }),
            ])
          : null,
      ]),
    );
  }

  return list;
}

// --- settings --------------------------------------------------------------

async function renderSettings(): Promise<void> {
  const container = root();
  clear(container);
  container.append(skeleton());

  let profile = { agency_name: null as string | null, agency_logo_url: null as string | null };
  try {
    profile = await api.profile();
  } catch (error) {
    clear(container);
    container.append(notice("error", describeError(error)));
    return;
  }

  clear(container);

  const message = el("div");
  const name = el("input", { type: "text", value: profile.agency_name ?? "" });
  const logo = el("input", {
    type: "url",
    value: profile.agency_logo_url ?? "",
    placeholder: "https://…",
  });
  const button = submitButton("Save");

  const form = el("form", { style: "max-width:30rem" }, [
    el("h1", { text: "Your details" }),
    el("p", {
      class: "blurb",
      text: "These appear on the reports you send to clients. Ours never do.",
    }),
    message,
    field("Business name", name),
    field("Logo URL", logo, el("span", { class: "hint", text: "Must be an https address." })),
    button,
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);
    void withPending(button, "Saving…", async () => {
      try {
        await api.saveProfile({
          agency_name: name.value || null,
          agency_logo_url: logo.value || null,
        });
        message.replaceChildren(notice("ok", "Saved."));
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Your details"), form]));

  const plan = el("p", { class: "muted" }, [
    "Your plan, what it includes, and every other plan: ",
    el("a", { class: "inline", href: "#/plan", text: "Pricing" }),
    ".",
  ]);
  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Pricing"), plan]));

  const support = el("p", { class: "muted" }, [
    "Something wrong, or a question about your account? ",
    el("a", { class: "inline", href: "mailto:aurelio_11@outlook.it", text: "aurelio_11@outlook.it" }),
    ". Also see the ",
    el("a", { class: "inline", href: "/privacy.html", text: "Privacy Policy" }),
    " and ",
    el("a", { class: "inline", href: "/terms.html", text: "Terms of Service" }),
    ".",
  ]);
  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Support"), support]));

  container.append(
    el("div", { style: "margin-top:3rem" }, [sectionRule("Password"), changePasswordSection()]),
  );

  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Email address"), changeEmailSection()]));

  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Delete account"), deleteAccountSection()]));
}

/// Changing the password without pretending to have forgotten it.
///
/// This page used to offer only "send the confirmation link", which settles
/// a different question entirely — whether an address can receive mail —
/// and is no use at all to somebody who is signed in and simply wants a
/// different password. They were left with the recovery flow, which asks
/// them to lie about having forgotten it.
///
/// The current password is asked for because the session alone is exactly
/// what a thief already holds. Everything else is the server's business:
/// it ends every other session and rotates this one in the same response.
function changePasswordSection(): HTMLElement {
  const message = el("div");
  const current = el("input", {
    type: "password",
    required: true,
    autocomplete: "current-password",
  });
  const next = el("input", { type: "password", required: true, autocomplete: "new-password" });
  const confirmation = el("input", {
    type: "password",
    required: true,
    autocomplete: "new-password",
  });
  const button = submitButton("Change password");

  const form = el("form", { style: "max-width:22rem" }, [
    el("p", {
      class: "blurb",
      style: "margin:0 0 1.1rem",
      text:
        "Changing it signs out every other device. This one stays signed in, " +
        "and the address on the account is told either way.",
    }),
    message,
    field("Current password", current),
    field("New password", next, el("span", { class: "hint", text: "At least 12 characters." })),
    field("Repeat the new password", confirmation),
    button,
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    // Caught here as well as on the server so the commonest mistake costs a
    // keystroke rather than a round trip.
    if (next.value !== confirmation.value) {
      message.replaceChildren(notice("error", "The new passwords do not match."));
      return;
    }

    void withPending(button, "Changing…", async () => {
      try {
        const result = await api.changePassword(current.value, next.value, confirmation.value);
        message.replaceChildren(notice("ok", result.message));
        current.value = "";
        next.value = "";
        confirmation.value = "";
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return form;
}

/// Moving the account to a different mailbox.
///
/// The password is asked for here for the same reason it is asked for to
/// delete: a stolen session already has the token, and an action that hands
/// the account to a different mailbox is a complete takeover. It needs the
/// one thing a stolen session would not also have.
///
/// The confirmation shown afterwards is deliberately the same sentence
/// whatever happened, including when the address is already registered. The
/// API answers that way so a signed-in account cannot be used to enumerate
/// the others, and a screen that said "that address is taken" would hand
/// back exactly what the API withheld.
function changeEmailSection(): HTMLElement {
  const message = el("div");
  const address = el("input", { type: "email", required: true, autocomplete: "email" });
  const password = el("input", { type: "password", required: true, autocomplete: "current-password" });
  const button = submitButton("Send the confirmation link");

  const form = el("form", { style: "max-width:22rem" }, [
    el("p", {
      class: "blurb",
      style: "margin:0 0 1.1rem",
      text: "The new address has to confirm before anything moves. Until it does, this account keeps the address it has.",
    }),
    message,
    field("New email", address),
    field("Confirm your password", password),
    button,
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);
    void withPending(button, "Sending…", async () => {
      try {
        const result = await api.changeEmail(address.value, password.value);
        message.replaceChildren(notice("ok", result.message));
        address.value = "";
        password.value = "";
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return form;
}

/// Landing page for the link in the change-of-address email.
///
/// Signs the session out on success rather than carrying it forward: the
/// server has just invalidated every token for this account, which is the
/// point — if the move was made by somebody who should not have been signed
/// in, that bump is what removes them.
function renderConfirmEmailChange(token: string): void {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Confirming" }));

  void (async () => {
    try {
      const result = await api.confirmEmailChange(token);
      session.clear();
      clear(container);
      container.append(
        el("div", { class: "auth" }, [
          el("h1", { text: "Address changed" }),
          notice("ok", result.message),
          el("p", { class: "switch" }, [
            el("a", { class: "inline", href: "#/signin", text: "Sign in" }),
          ]),
        ]),
      );
    } catch (error) {
      clear(container);
      container.append(
        el("div", { class: "auth" }, [
          el("h1", { text: "That link did not work" }),
          notice("error", describeError(error)),
          el("p", { class: "switch" }, [
            "Links expire after an hour. Sign in and request the change again from ",
            el("a", { class: "inline", href: "#/settings", text: "your account" }),
            ".",
          ]),
        ]),
      );
    }
  })();
}

/// Asks for the password before doing anything, then does it without a
/// second confirmation dialog.
///
/// The password *is* the confirmation — someone who cannot supply it has
/// not proven they are the account holder making this decision, and
/// someone who can has already deliberately typed it into a form labelled
/// "Delete account". A second "are you sure?" after that would only be
/// asking them to confirm they meant what they just did.
function deleteAccountSection(): HTMLElement {
  const message = el("div");
  const password = el("input", { type: "password", autocomplete: "current-password" });
  const button = el("button", { class: "ghost", type: "submit", text: "Delete my account" });

  const form = el("form", { style: "max-width:22rem" }, [
    el("p", {
      class: "blurb",
      style: "margin:0 0 1.1rem",
      text: "Permanent. Your name, email, and password are removed immediately — this cannot be undone from here.",
    }),
    message,
    field("Confirm your password", password),
    button,
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);
    void withPending(button, "Deleting…", async () => {
      try {
        await api.deleteAccount(password.value);
        session.clear();
        window.location.hash = "#/signin";
      } catch (error) {
        message.replaceChildren(notice("error", describeError(error)));
      }
    });
  });

  return form;
}

/// What each plan buys, and what it costs.
///
/// One list, rather than figures written into the markup in several
/// places. These have to match the Stripe catalogue exactly: a page that
/// quotes one price while checkout charges another is not a display bug,
/// it is a chargeback. The yearly saving is derived from the two numbers
/// rather than written down, which is how the old "two months free" label
/// came to be wrong after the yearly prices changed.
const PLANS = [
  { plan: "free", name: "Free", monthly: 0, yearly: 0, sites: 1, scheduling: false },
  { plan: "solo", name: "Solo", monthly: 19, yearly: 170, sites: 5, scheduling: true },
  { plan: "studio", name: "Studio", monthly: 39, yearly: 350, sites: 10, scheduling: true },
  { plan: "agency", name: "Agency", monthly: 99, yearly: 750, sites: 40, scheduling: true },
] as const;

type PlanOffer = (typeof PLANS)[number];

/// What a plan includes, in the order somebody comparing them cares about.
function planIncludes(offer: PlanOffer): string {
  const sites = `${offer.sites} ${offer.sites === 1 ? "site" : "sites"}`;
  return offer.scheduling
    ? `${sites} · weekly checks · reports under your name`
    : `${sites} · scans when you ask`;
}

/// The plan page.
///
/// Its own route rather than a block at the top of Settings. Somebody who
/// has run out of sites is not looking for the page where they edit their
/// business name, and hiding the only paid thing in the product behind a
/// gear icon is how a product with a paid tier never sells one.
async function renderPlan(): Promise<void> {
  const container = root();
  clear(container);
  container.append(skeleton());

  let subscription: Subscription;
  try {
    subscription = await api.subscription();
  } catch (error) {
    clear(container);
    container.append(notice("error", describeError(error)));
    return;
  }

  clear(container);
  const message = el("div");

  // Where they stand, as a sentence that has already done the
  // interpreting — the same shape as every other page here.
  const usage = el("p", { class: "standing" });
  usage.append(
    el("strong", { text: subscription.plan_name }),
    " — ",
    `${subscription.targets_used} of ${subscription.max_targets} ${
      subscription.max_targets === 1 ? "site" : "sites"
    } used`,
    ".",
  );

  const meta: string[] = [];
  if (!subscription.allows_scheduling) meta.push("Automatic checks not included");
  if (subscription.current_period_end) {
    meta.push(`Renews ${shortDate(subscription.current_period_end)}`);
  }
  if (subscription.status && subscription.status !== "active") {
    meta.push(subscription.status.replace(/_/g, " "));
  }

  append(
    container,
    el("h1", { text: "Pricing" }),
    el("div", { style: "margin-top:1.25rem" }, [usage]),
    meta.length > 0 ? el("p", { class: "standing-meta", text: meta.join(" · ") }) : null,
    message,
  );

  // Being out of room is the one thing on this page somebody needs told
  // rather than left to work out from two numbers.
  if (subscription.targets_used >= subscription.max_targets) {
    container.append(
      notice(
        "info",
        subscription.plan === "agency"
          ? "Every site on your plan is in use. Get in touch if you need more than forty."
          : "Every site on your plan is in use. A larger plan adds room for more.",
      ),
    );
  }

  if (subscription.manageable) {
    const manage = el("button", { class: "ghost", type: "button", text: "Manage billing" });
    on(manage, "click", () => {
      void withPending(manage, "Opening…", async () => {
        try {
          const result = await api.billingPortal();
          window.location.href = result.url;
        } catch (error) {
          message.replaceChildren(notice("error", describeError(error)));
        }
      });
    });
    container.append(el("div", { style: "margin-top:1.5rem" }, [manage]));
  }

  container.append(el("div", { style: "margin-top:3rem" }, [sectionRule("Every plan")]));

  // One switch for the whole table rather than two prices crowded into
  // every row. Monthly and yearly are the same plan, not two different
  // things to compare — a reader picks a plan first and a billing rhythm
  // second, and the old layout made them do both at once for each row.
  let interval: "monthly" | "yearly" = "monthly";
  const toggleRow = el("div", { class: "tabs", style: "margin-bottom:0" });
  const monthlyTab = el("button", { class: "tab tab-active", type: "button", text: "Monthly" });
  const yearlyTab = el("button", { class: "tab", type: "button", text: "Yearly" });
  toggleRow.append(monthlyTab, yearlyTab);

  const list = el("ul", { class: "ledger" });

  function paintList(): void {
    clear(list);
    for (const offer of PLANS) list.append(planRow(offer, subscription, interval, message));
  }

  function selectInterval(value: "monthly" | "yearly"): void {
    if (interval === value) return;
    interval = value;
    monthlyTab.className = value === "monthly" ? "tab tab-active" : "tab";
    yearlyTab.className = value === "yearly" ? "tab tab-active" : "tab";
    paintList();
  }

  on(monthlyTab, "click", () => selectInterval("monthly"));
  on(yearlyTab, "click", () => selectInterval("yearly"));

  paintList();
  container.append(el("div", { style: "margin-top:1.75rem" }, [toggleRow]), list);

  container.append(
    el("p", { class: "muted", style: "margin-top:1.5rem" }, [
      "Prices exclude VAT, which is added at checkout. Cancel whenever you like from Manage billing — ",
      "the sites stay, the automatic checks stop.",
    ]),
  );
}

/// One plan, as a row on a hairline.
///
/// All three are listed, including the one already held: a page that shows
/// only what you are not on gives no sense of what you would be giving up
/// or gaining, and showing the current plan as buyable is how people end
/// up subscribed twice. The price shown follows the page's monthly/yearly
/// switch, so this never carries its own — a plan does not have an
/// opinion on billing rhythm, the reader does.
function planRow(
  offer: PlanOffer,
  subscription: Subscription,
  interval: "monthly" | "yearly",
  message: HTMLElement,
): HTMLElement {
  const current = offer.plan === subscription.plan;
  const saving = offer.monthly * 12 - offer.yearly;

  const state = el("div", { class: "entry-state" }, [
    el("span", { text: planIncludes(offer) }),
  ]);

  const right = el("div", { class: "entry-right" });
  const price = el("div", { class: "plan-row-price" });

  if (current) {
    // Achromatic, and the spine below stays grey with it. Green here
    // would read as "this site is fine" — colour in this interface means
    // security state and nothing else, and spending it on "you are on
    // this plan" is exactly how a reserved palette stops being read.
    right.append(el("span", { class: "mono-note", text: "Current plan" }));
  } else if (offer.monthly === 0) {
    // Free is not something to buy, and moving down to it is done by
    // cancelling in Stripe's portal — where it is clear what happens at
    // the end of the period — rather than by a button here that would
    // have to decide the fate of the sites over the smaller allowance.
    right.append(el("span", { class: "mono-note", text: "Cancel to return" }));
  } else {
    if (interval === "yearly") {
      price.append(
        el("span", { class: "plan-row-amount", text: `€${offer.yearly}` }),
        el("span", { class: "plan-row-unit", text: "/yr" }),
      );
      state.append(
        el("span", { class: "sep", text: "·" }),
        el("span", { class: "watching", text: `saves €${saving} a year` }),
      );
    } else {
      price.append(
        el("span", { class: "plan-row-amount", text: `€${offer.monthly}` }),
        el("span", { class: "plan-row-unit", text: "/mo" }),
      );
    }

    const subscribe = el("button", { class: "primary", type: "button", text: "Subscribe" });
    on(subscribe, "click", () => {
      clear(message);
      void withPending(subscribe, "Opening…", async () => {
        try {
          const result = await api.checkout(offer.plan, interval);
          window.location.href = result.url;
        } catch (error) {
          message.replaceChildren(notice("error", describeError(error)));
        }
      });
    });

    right.append(price, subscribe);
  }

  return el("li", {}, [
    el("div", { class: "entry entry-idle" }, [
      el("div", {}, [el("div", { class: "entry-name", text: offer.name }), state]),
      right,
    ]),
  ]);
}

// --- routing ---------------------------------------------------------------

function renderNav(): void {
  const nav = byId<HTMLElement>("nav-links");
  clear(nav);

  if (!session.isSignedIn) return;

  const section = window.location.hash.split("/")[1] ?? "";
  const link = (href: string, text: string, matches: string[]): HTMLElement =>
    el("a", { href, text, class: matches.includes(section) ? "active" : undefined });

  // Without something on screen saying so, a keyboard-first interface is
  // just an interface nobody knows is keyboard-first.
  const jump = el("button", { class: "kbd-hint", type: "button", title: "Jump to anything" }, [
    el("kbd", { text: navigator.platform.includes("Mac") ? "⌘K" : "Ctrl K" }),
  ]);
  on(jump, "click", () => palette.open());

  nav.append(
    jump,
    link("#/targets", "Sites", ["targets", "scans", ""]),
    link("#/plan", "Pricing", ["plan"]),
    link("#/settings", "Settings", ["settings"]),
  );

  const signOut = el("button", { type: "button", text: "Sign out" });
  on(signOut, "click", () => {
    void api.logout().finally(() => {
      session.clear();
      window.location.hash = "#/signin";
    });
  });
  nav.append(signOut);
}

function routeInner(): void {
  stopPolling();
  renderNav();

  // The query lives inside the fragment (`#/signup?d=example.com`), so it
  // is split off here rather than read from location.search — the server
  // never sees it, and a route that kept it would look for a view called
  // "signup?d=example.com".
  const hash = window.location.hash.replace(/^#/, "") || "/";
  const separator = hash.indexOf("?");
  const path = separator === -1 ? hash : hash.slice(0, separator);
  const query = new URLSearchParams(separator === -1 ? "" : hash.slice(separator + 1));
  const parts = path.split("/").filter(Boolean);

  // Confirmation links get followed while signed out, and sometimes while
  // signed in as somebody else. The token decides, not the session.
  if (parts[0] === "verify" && parts[1]) {
    void renderVerify(parts[1]);
    return;
  }

  // Recovery links, like confirmation links, get followed while signed out
  // and sometimes while signed in as somebody else. The token decides, not
  // the session — otherwise the one person who most needs this screen, the
  // one with a stale session in another tab, is bounced away from it.
  if (parts[0] === "reset" && parts[1]) {
    renderResetPassword(parts[1]);
    return;
  }
  if (parts[0] === "forgot") {
    renderForgotPassword();
    return;
  }

  // Followed from the new mailbox, which is by definition not where the
  // session is — and often while signed in as the account being moved. The
  // token decides, not the session.
  if (parts[0] === "confirm-email" && parts[1]) {
    renderConfirmEmailChange(parts[1]);
    return;
  }

  if (!session.isSignedIn) {
    if (parts[0] === "signup") renderSignUp(cleanDomain(query.get("d")));
    else renderSignIn();
    return;
  }

  if (parts[0] === "signin" || parts[0] === "signup" || parts.length === 0) {
    window.location.hash = "#/targets";
    return;
  }

  if (parts[0] === "targets" && parts[1]) {
    void renderTarget(parts[1]);
    return;
  }
  if (parts[0] === "targets") {
    void renderTargets();
    return;
  }
  if (parts[0] === "scans" && parts[1]) {
    void renderScan(parts[1]);
    return;
  }
  if (parts[0] === "plan") {
    void renderPlan();
    return;
  }
  if (parts[0] === "settings") {
    void renderSettings();
    return;
  }

  void renderTargets();
}

function route(): void {
  routeInner();
}

palette.installShortcuts();
// A sensible default so the palette is never empty on a view that has not
// registered anything more specific.
palette.setCommands(standardCommands);

window.addEventListener("hashchange", () => {
  palette.close();
  route();
});
window.addEventListener("DOMContentLoaded", route);
