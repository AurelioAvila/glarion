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
import type { Cadence, ScanDetail, ScanSummary, Target, TriagedFinding } from "./api.js";
import { append, byId, clear, copyableValue, el, on } from "./dom.js";
import { countOf, relativeTime, shortDate } from "./format.js";
import * as palette from "./palette.js";

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
  const button = submitButton("Sign in");

  const form = el("form", { class: "auth" }, [
    el("h1", { text: "Sign in" }),
    message,
    field("Email", email),
    field("Password", password),
    el("label", { class: "checkbox" }, [remember, "Remember my email on this device"]),
    button,
    el("p", { class: "switch" }, [
      "No account yet? ",
      el("a", { class: "inline", href: "#/signup", text: "Create one" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Signing in…", async () => {
      try {
        const result = await api.login(email.value, password.value);
        rememberedEmail.set(remember.checked ? email.value.trim() : null);
        session.set(result.token);
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
    notice("info", "Confirm your email address before signing in. Check your inbox."),
    resend,
  );
  return wrapper;
}

// --- sign up ---------------------------------------------------------------

function renderSignUp(): void {
  const container = root();
  clear(container);

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
  const button = submitButton("Create account");

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
    message,
    el("div", { class: "field-pair" }, [
      field("First name", firstName),
      field("Last name", lastName),
    ]),
    field(
      "Date of birth",
      dateOfBirth,
      el("span", { class: "hint", text: "You must be 18 or over to open an account." }),
    ),
    field("Email", email),
    field("Password", password, el("span", { class: "hint", text: "At least 12 characters." })),
    field("Repeat password", confirmation, mismatch),
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
        renderCheckYourEmail(result.email);
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
function renderCheckYourEmail(email: string): void {
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
      el("p", {
        class: "blurb",
        text: `We sent a link to ${email}. Open it to finish setting up your account.`,
      }),
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
    const result = await api.verifyEmail(token);
    // Signed in straight away: they have just proved they control the
    // address, so asking for the password again adds nothing.
    session.set(result.token);
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
  try {
    const [targets, scanList] = await Promise.all([api.targets(), api.scans(targetId)]);
    target = targets.find((candidate) => candidate.id === targetId);
    scans = scanList;
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
    append(container, expiryNote(site), cadenceControl(site), scansSection(site, scans));
  } else {
    // Deliberately the only thing on the page. Until ownership is proved
    // nothing else can happen, and offering a scan button that always
    // fails would just waste the reader's time.
    container.append(verificationSection(site));
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

/// The screen that decides whether anyone ever sees a report.
///
/// It asks the reader to leave the product, sign in to a DNS provider, and
/// paste an exact string, so it is laid out as a procedure. The record is
/// split into its two parts with a copy control on each, since retyping a
/// random token is the likeliest way for the step to fail, and the wait for
/// propagation is stated before it happens rather than after the check
/// looks broken.
function verificationSection(target: Target): HTMLElement {
  const body = el("div");
  const section = el("div", {}, [
    sectionRule("Domain check"),
    el("p", {
      class: "blurb",
      style: "margin-top:1.25rem",
      text:
        "We only scan sites whose owner has asked us to. Publish the record below " +
        "and we will confirm it. One time, valid for 30 days.",
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

  return section;
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

  let profile = { agency_name: null as string | null, agency_logo_url: null as string | null };
  try {
    profile = await api.profile();
  } catch (error) {
    container.append(notice("error", describeError(error)));
    return;
  }

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

  container.append(form);
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
    link("#/settings", "Settings", ["settings"]),
  );

  const signOut = el("button", { type: "button", text: "Sign out" });
  on(signOut, "click", () => {
    session.clear();
    window.location.hash = "#/signin";
  });
  nav.append(signOut);
}

function routeInner(): void {
  stopPolling();
  renderNav();

  const hash = window.location.hash.replace(/^#/, "") || "/";
  const parts = hash.split("/").filter(Boolean);

  // Confirmation links get followed while signed out, and sometimes while
  // signed in as somebody else. The token decides, not the session.
  if (parts[0] === "verify" && parts[1]) {
    void renderVerify(parts[1]);
    return;
  }

  if (!session.isSignedIn) {
    if (parts[0] === "signup") renderSignUp();
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
