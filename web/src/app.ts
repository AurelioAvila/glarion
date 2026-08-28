// The dashboard.
//
// Plain TypeScript with hash routing and no framework, matching the rest of
// the portfolio. Views render into a single root element; each render
// rebuilds its subtree rather than patching it, which is fast enough for a
// handful of screens and removes a whole class of stale-DOM bugs.

import { api, ApiError, rememberedEmail, session } from "./api.js";
import type { ScanDetail, ScanSummary, Target, TriagedFinding } from "./api.js";
import { append, byId, clear, copyableValue, detailRow, el, on } from "./dom.js";
import { countOf, relativeTime, shortDate } from "./format.js";

const root = () => byId<HTMLElement>("view");

/// How often to re-check a scan that is still running.
///
/// A full scan takes on the order of twenty minutes, so polling every few
/// seconds would be thousands of pointless requests. Ten seconds keeps the
/// page feeling live without that.
const SCAN_POLL_MS = 10_000;

let pollTimer: number | undefined;

function stopPolling(): void {
  if (pollTimer !== undefined) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

// --- shared pieces ---------------------------------------------------------

function banner(kind: "error" | "ok" | "info", message: string): HTMLElement {
  return el("p", { class: `banner banner-${kind}`, role: "status", text: message });
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

// --- sign in ---------------------------------------------------------------

function renderSignIn(): void {
  const container = root();
  clear(container);

  const message = el("div");
  const saved = rememberedEmail.get();

  const email = el("input", {
    type: "email",
    name: "email",
    required: true,
    autocomplete: "email",
    value: saved ?? "",
  });
  const password = el("input", {
    type: "password",
    name: "password",
    required: true,
    autocomplete: "current-password",
  });
  const remember = el("input", { type: "checkbox", checked: saved !== null });
  const button = submitButton("Sign in");

  const form = el("form", { class: "card auth-card" }, [
    el("h1", { text: "Sign in" }),
    message,
    el("label", {}, ["Email", email]),
    el("label", {}, ["Password", password]),
    el("label", { class: "checkbox" }, [remember, "Remember my email on this device"]),
    button,
    el("p", { class: "switch" }, [
      "No account yet? ",
      el("a", { href: "#/signup", text: "Create one" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Signing in\u2026", async () => {
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
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  container.append(form);
  // Focus whichever field still needs filling in.
  (saved ? password : email).focus();
}

/// Shown when the password was right but the address was never confirmed.
function unconfirmedNotice(email: string): HTMLElement {
  const wrapper = el("div");
  const resend = el("button", { class: "linklike", type: "button", text: "Send it again" });

  on(resend, "click", () => {
    void withPending(resend, "Sending\u2026", async () => {
      try {
        const result = await api.resendVerification(email);
        wrapper.replaceChildren(banner("ok", result.message));
      } catch (error) {
        wrapper.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  wrapper.append(
    banner("info", "Confirm your email address before signing in. Check your inbox."),
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
  const confirmation = el("input", {
    type: "password",
    required: true,
    autocomplete: "new-password",
  });
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

  const form = el("form", { class: "card auth-card" }, [
    el("h1", { text: "Create your account" }),
    message,
    el("div", { class: "field-pair" }, [
      el("label", {}, ["First name", firstName]),
      el("label", {}, ["Last name", lastName]),
    ]),
    el("label", {}, [
      "Date of birth",
      dateOfBirth,
      el("span", { class: "hint", text: "You must be 18 or over to open an account." }),
    ]),
    el("label", {}, ["Email", email]),
    el("label", {}, [
      "Password",
      password,
      el("span", { class: "hint", text: "At least 12 characters." }),
    ]),
    el("label", {}, ["Repeat password", confirmation, mismatch]),
    button,
    el("p", { class: "switch" }, [
      "Already have an account? ",
      el("a", { href: "#/signin", text: "Sign in" }),
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

    void withPending(button, "Creating\u2026", async () => {
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
        message.replaceChildren(banner("error", describeError(error)));
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
    void withPending(resend, "Sending\u2026", async () => {
      try {
        const result = await api.resendVerification(email);
        message.replaceChildren(banner("ok", result.message));
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  container.append(
    el("div", { class: "card auth-card" }, [
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
      // "a new link is on its way" and has nowhere to go. Without this
      // they are stranded on a screen that cannot change.
      el("p", { class: "switch" }, [
        "Already confirmed? ",
        el("a", { href: "#/signin", text: "Sign in" }),
      ]),
    ]),
  );
}

/// Landing page for the link in the confirmation email.
async function renderVerify(token: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Confirming\u2026" }));

  try {
    const result = await api.verifyEmail(token);
    // Signed in straight away: they have just proved they control the
    // address, so asking for the password again adds nothing.
    session.set(result.token);
    window.location.hash = "#/targets";
  } catch (error) {
    clear(container);
    container.append(
      el("div", { class: "card auth-card" }, [
        el("h1", { text: "That link did not work" }),
        banner("error", describeError(error)),
        el("p", { class: "switch" }, [
          "You can ",
          el("a", { href: "#/signin", text: "sign in" }),
          " to request a new one.",
        ]),
      ]),
    );
  }
}

// --- sites -----------------------------------------------------------------

/// A site with the state a reader needs at a glance.
///
/// The API returns targets and scans separately, so the two are joined
/// here. That keeps the list endpoint simple and costs one extra request
/// on a page that is already fetching.
interface SiteRow {
  target: Target;
  latestScan: ScanSummary | undefined;
}

function joinScans(targets: Target[], scans: ScanSummary[]): SiteRow[] {
  return targets.map((target) => ({
    target,
    // Scans arrive newest first, so the first match is the latest.
    latestScan: scans.find((scan) => scan.target_id === target.id),
  }));
}

async function renderTargets(): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Loading\u2026" }));

  let rows: SiteRow[];
  try {
    const [targets, scans] = await Promise.all([api.targets(), api.scans()]);
    rows = joinScans(targets, scans);
  } catch (error) {
    clear(container);
    container.append(banner("error", describeError(error)));
    return;
  }

  clear(container);

  if (rows.length === 0) {
    container.append(onboarding());
    return;
  }

  const addPanel = addTargetForm();
  addPanel.hidden = true;

  const addButton = el("button", { class: "primary", type: "button", text: "Add site" });
  on(addButton, "click", () => {
    addPanel.hidden = !addPanel.hidden;
    if (!addPanel.hidden) addPanel.querySelector("input")?.focus();
  });

  container.append(
    el("div", { class: "page-head" }, [
      el("div", {}, [
        el("h1", { text: "Sites" }),
        el("p", {
          class: "lede",
          text: "The sites you look after, and what each one needs.",
        }),
      ]),
      addButton,
    ]),
    addPanel,
    summaryTiles(rows),
  );

  const list = el("ul", { class: "site-list" });
  for (const row of rows) {
    list.append(siteCard(row));
  }
  container.append(list);
}

/// The three numbers worth reading before anything else.
///
/// An agency with twenty clients does not want to scan the list looking
/// for red; it wants to know immediately whether today needs attention.
function summaryTiles(rows: SiteRow[]): HTMLElement {
  const needingAttention = rows.filter(
    (row) => row.latestScan?.status === "completed" && row.latestScan.actionable_count > 0,
  ).length;
  const awaitingSetup = rows.filter((row) => !row.target.verified).length;

  const tile = (value: number, label: string, variant?: string): HTMLElement =>
    el("div", { class: variant ? `tile ${variant}` : "tile" }, [
      el("div", { class: "tile-value", text: String(value) }),
      el("div", { class: "tile-label", text: label }),
    ]);

  return el("div", { class: "tiles" }, [
    tile(rows.length, rows.length === 1 ? "Site" : "Sites"),
    tile(needingAttention, "Need attention", "tile-attention"),
    tile(awaitingSetup, "Awaiting setup", "tile-setup"),
  ]);
}

function siteCard(row: SiteRow): HTMLElement {
  const { target, latestScan } = row;

  const status = target.verified
    ? el("span", { class: "chip chip-ok", text: "Verified" })
    : el("span", { class: "chip chip-pending", text: "Not verified" });

  // The footer answers "what should I do about this site" without a click.
  const footer = el("div", { class: "site-card-foot" });

  if (!target.verified) {
    footer.append(el("span", { text: "Prove you control the domain to start scanning" }));
  } else if (!latestScan) {
    footer.append(el("span", { text: "Ready to scan" }));
  } else if (latestScan.status === "running" || latestScan.status === "queued") {
    footer.append(el("span", { text: "Scan in progress\u2026" }));
  } else if (latestScan.status === "failed") {
    footer.append(el("span", { text: "Last scan did not finish" }));
  } else {
    const needsAction = latestScan.actionable_count;
    footer.append(
      needsAction > 0
        ? el("span", {
            class: "site-finding-count",
            text: `${needsAction} to fix`,
          })
        : el("span", { class: "site-clean", text: "Nothing to fix" }),
      el("span", { class: "dot", text: "\u00b7" }),
      el("span", { text: `scanned ${relativeTime(latestScan.completed_at ?? latestScan.created_at)}` }),
    );
  }

  return el("li", {}, [
    el("a", { class: "site-card", href: `#/targets/${target.id}` }, [
      el("div", { class: "site-card-top" }, [
        el("div", {}, [
          el("div", { class: "site-domain", text: target.domain }),
          target.client_name
            ? el("div", { class: "site-client", text: target.client_name })
            : null,
        ]),
        status,
      ]),
      footer,
    ]),
  ]);
}

/// What a new customer sees first.
///
/// The old version of this screen was one line of grey text. That is a poor
/// use of the only moment when someone is guaranteed to be reading: this is
/// where the product explains what it does, and — more usefully — warns
/// that step two involves their DNS, which is the part that surprises
/// people and the reason they abandon setup halfway.
function onboarding(): HTMLElement {
  const step = (n: string, title: string, body: string): HTMLElement =>
    el("div", { class: "step-card" }, [
      el("span", { class: "step-number", text: n }),
      el("h3", { text: title }),
      el("p", { text: body }),
    ]);

  return el("section", { class: "card onboard" }, [
    el("h2", { text: "Add your first site" }),
    el("p", {
      class: "blurb",
      text:
        "Glarion checks a website for security problems and turns the result " +
        "into a short report you can hand straight to your client.",
    }),
    el("div", { class: "steps" }, [
      step("1", "Add the site", "The domain, and which client it belongs to."),
      step(
        "2",
        "Prove it is yours",
        "A one-time DNS record, so we only ever scan sites whose owner asked us to.",
      ),
      step("3", "Scan and send", "Run a scan, then download the report under your own name."),
    ]),
    addTargetForm(),
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
  const client = el("input", { type: "text", placeholder: "Client name (optional)" });
  const button = submitButton("Add site");

  const form = el("form", { class: "card inline-form" }, [
    message,
    el("div", { class: "field-row" }, [domain, client, button]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Adding\u2026", async () => {
      try {
        const target = await api.addTarget(domain.value, client.value || null);
        window.location.hash = `#/targets/${target.id}`;
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  return form;
}

// --- one site: verification and scans --------------------------------------

async function renderTarget(targetId: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Loading…" }));

  let target: Target | undefined;
  let scans: ScanSummary[] = [];
  try {
    const [targets, scanList] = await Promise.all([api.targets(), api.scans(targetId)]);
    target = targets.find((candidate) => candidate.id === targetId);
    scans = scanList;
  } catch (error) {
    clear(container);
    container.append(banner("error", describeError(error)));
    return;
  }

  if (!target) {
    clear(container);
    container.append(banner("error", "That site could not be found."));
    return;
  }

  clear(container);
  append(
    container,
    el("p", { class: "breadcrumb" }, [
      el("a", { href: "#/targets", text: "\u2190 All sites" }),
    ]),
    el("div", { class: "page-head" }, [
      el("div", {}, [
        el("h1", { text: target.domain }),
        target.client_name ? el("p", { class: "subtitle", text: target.client_name }) : null,
      ]),
      target.verified
        ? el("span", { class: "chip chip-ok", text: "Verified" })
        : el("span", { class: "chip chip-pending", text: "Not verified" }),
    ]),
  );

  if (target.verified) {
    append(container, verifiedPanel(target), scansPanel(target, scans));
  } else {
    // Deliberately the only thing on the page. Until ownership is proved
    // nothing else can happen, and offering a scan button that always
    // fails would just be a way to waste the user's time.
    container.append(verificationPanel(target));
  }
}

/// A one-line reminder that ownership proof expires.
///
/// Returns nothing when there is no expiry to report, rather than an empty
/// panel: a card containing a single blank row is worse than no card.
function verifiedPanel(target: Target): HTMLElement | null {
  if (!target.verification_expires_at) return null;

  return el("p", { class: "muted", style: "margin: -0.5rem 0 1.15rem" }, [
    `Ownership confirmed. Needs re-checking by ${shortDate(target.verification_expires_at)}.`,
  ]);
}

/// The screen that decides whether anyone ever sees a report.
///
/// It asks the user to leave the product, sign in to a DNS provider, and
/// paste an exact string. Everything here exists to reduce the chance that
/// they get it wrong or give up: the record is split into its two parts,
/// both copyable; the wait for propagation is stated before it happens
/// rather than after it looks broken; and there is a second method for
/// people who cannot reach their DNS.
function verificationPanel(target: Target): HTMLElement {
  const body = el("div");
  const panel = el("section", { class: "card" }, [
    el("h2", { text: "Prove you control this domain" }),
    el("p", {
      class: "blurb",
      text:
        "We only scan sites whose owner has asked us to. Publish the record below " +
        "and we will confirm it — this is a one-time step, valid for 30 days.",
    }),
    body,
  ]);

  const startButton = el("button", { class: "primary", type: "button", text: "Show me the record" });
  body.append(startButton);

  on(startButton, "click", () => {
    void withPending(startButton, "Preparing…", async () => {
      try {
        const instructions = await api.startVerification(target.id);
        body.replaceChildren(verificationInstructions(target, instructions));
      } catch (error) {
        body.replaceChildren(banner("error", describeError(error)), startButton);
      }
    });
  });

  return panel;
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
  const checkButton = el("button", {
    class: "primary",
    type: "button",
    text: "I've added it — check now",
  });

  let method: "dns_txt" | "well_known_file" = "dns_txt";

  const dnsPane = el("div", { class: "method-pane" }, [
    el("p", { class: "step", text: "Add this TXT record at your DNS provider:" }),
    detailRow("Name", copyableValue(instructions.dns_record_name, "record name")),
    detailRow("Value", copyableValue(instructions.dns_record_value, "record value")),
    el("p", {
      class: "hint",
      text:
        "DNS changes usually appear within a few minutes, but some providers " +
        "take up to an hour. If the check does not find it yet, wait and try again.",
    }),
  ]);

  const fileP = el("p", { class: "step", text: "Upload a file to this exact address:" });
  const filePane = el("div", { class: "method-pane", hidden: true }, [
    fileP,
    detailRow("Address", copyableValue(instructions.well_known_url, "file address")),
    detailRow("Contents", copyableValue(instructions.well_known_content, "file contents")),
    el("p", {
      class: "hint",
      text: "The file must be reachable over HTTPS and contain only that value.",
    }),
  ]);

  const dnsTab = el("button", { class: "tab tab-active", type: "button", text: "DNS record" });
  const fileTab = el("button", { class: "tab", type: "button", text: "File upload" });

  function selectMethod(next: "dns_txt" | "well_known_file"): void {
    method = next;
    const isDns = next === "dns_txt";
    dnsPane.hidden = !isDns;
    filePane.hidden = isDns;
    dnsTab.className = isDns ? "tab tab-active" : "tab";
    fileTab.className = isDns ? "tab" : "tab tab-active";
    clear(message);
  }

  on(dnsTab, "click", () => selectMethod("dns_txt"));
  on(fileTab, "click", () => selectMethod("well_known_file"));

  on(checkButton, "click", () => {
    clear(message);
    void withPending(checkButton, "Checking…", async () => {
      try {
        const result = await api.checkVerification(target.id, method);
        if (result.verified) {
          message.replaceChildren(banner("ok", "Verified. Loading…"));
          window.setTimeout(() => void renderTarget(target.id), 700);
        } else {
          message.replaceChildren(banner("info", result.detail));
        }
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  return el("div", {}, [
    el("div", { class: "tabs" }, [dnsTab, fileTab]),
    dnsPane,
    filePane,
    message,
    checkButton,
  ]);
}

function scansPanel(target: Target, scans: ScanSummary[]): HTMLElement {
  const message = el("div");
  const list = el("div", { class: "scan-list" });
  const startButton = el("button", { class: "primary", type: "button", text: "Run a scan" });

  const panel = el("section", { class: "card" }, [
    el("div", { class: "panel-head" }, [el("h2", { text: "Scans" }), startButton]),
    message,
    list,
  ]);

  function paint(current: ScanSummary[]): void {
    clear(list);
    if (current.length === 0) {
      list.append(el("p", { class: "empty", text: "No scans yet." }));
      return;
    }
    for (const scan of current) {
      list.append(scanRow(scan));
    }
  }

  paint(scans);

  // Poll only while something is unfinished, and stop as soon as everything
  // has settled so an idle tab is not making requests forever.
  const hasPending = (list_: ScanSummary[]) =>
    list_.some((scan) => scan.status === "queued" || scan.status === "running");

  function schedulePolling(current: ScanSummary[]): void {
    stopPolling();
    if (!hasPending(current)) return;

    pollTimer = window.setInterval(() => {
      void api
        .scans(target.id)
        .then((updated) => {
          paint(updated);
          if (!hasPending(updated)) stopPolling();
        })
        .catch(() => {
          // A transient failure should not kill the page; the next tick
          // tries again.
        });
    }, SCAN_POLL_MS);
  }

  schedulePolling(scans);

  on(startButton, "click", () => {
    clear(message);
    void withPending(startButton, "Starting…", async () => {
      try {
        await api.startScan(target.id);
        const updated = await api.scans(target.id);
        paint(updated);
        schedulePolling(updated);
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  return panel;
}

function scanRow(scan: ScanSummary): HTMLElement {
  const status = el("span", {
    class: `chip chip-${scan.status}`,
    text:
      scan.status === "queued"
        ? "Queued"
        : scan.status === "running"
          ? "Running"
          : scan.status === "completed"
            ? "Done"
            : "Failed",
  });

  const summary =
    scan.status === "completed"
      ? scan.actionable_count > 0
        ? `${scan.actionable_count} to fix of ${countOf(scan.finding_count, "check")}`
        : `Nothing to fix, ${countOf(scan.finding_count, "check")}`
      : scan.status === "failed" && scan.failure_reason
        ? scan.failure_reason
        : "";

  const row = el("div", { class: "scan-row" }, [
    status,
    el("span", { class: "muted", text: relativeTime(scan.completed_at ?? scan.created_at) }),
    summary ? el("span", { class: "muted", text: summary }) : null,
  ]);

  if (scan.status === "completed") {
    row.append(
      el("a", { class: "grow", href: `#/scans/${scan.id}`, text: "View findings \u2192" }),
    );
  }

  return row;
}

// --- one scan --------------------------------------------------------------

async function renderScan(scanId: string): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Loading…" }));

  let detail: ScanDetail;
  try {
    detail = await api.scan(scanId);
  } catch (error) {
    clear(container);
    container.append(banner("error", describeError(error)));
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
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  container.append(
    el("p", { class: "breadcrumb" }, [
      el("a", { href: `#/targets/${detail.target_id}`, text: `← ${detail.domain}` }),
    ]),
    el("div", { class: "panel-head" }, [el("h1", { text: "Findings" }), download]),
    message,
    el("p", {
      class: "subtitle",
      text: `${detail.triaged.actionable.length} need attention · ${detail.triaged.review.length} worth a decision · ${detail.triaged.inventory.length} checked`,
    }),
  );

  append(
    container,
    findingSection("Needs attention", detail.triaged.actionable, "Nothing here requires a fix."),
    findingSection("Worth a decision", detail.triaged.review, null),
  );

  if (detail.triaged.inventory.length > 0) {
    const items = el("ul", { class: "inventory" });
    for (const finding of detail.triaged.inventory) {
      items.append(el("li", { text: finding.title }));
    }
    container.append(
      el("section", { class: "card" }, [
        el("h2", { text: "Also checked" }),
        el("p", { class: "blurb", text: "Verified and found unremarkable." }),
        items,
      ]),
    );
  }
}

function findingSection(
  heading: string,
  findings: TriagedFinding[],
  emptyText: string | null,
): HTMLElement | null {
  if (findings.length === 0 && emptyText === null) return null;

  const section = el("section", { class: "card" }, [el("h2", { text: heading })]);

  if (findings.length === 0) {
    section.append(el("p", { class: "empty", text: emptyText ?? "" }));
    return section;
  }

  for (const finding of findings) {
    section.append(findingCard(finding));
  }
  return section;
}

function findingCard(finding: TriagedFinding): HTMLElement {
  return el("article", { class: "finding" }, [
    el("div", { class: "finding-head" }, [
      el("span", { class: `pill pill-${finding.priority}`, text: finding.priority }),
      el("h3", { text: finding.title }),
    ]),
    finding.occurrences > 1
      ? el("p", { class: "muted", text: `Observed ${finding.occurrences} times.` })
      : null,
    finding.guidance ? el("p", { text: finding.guidance.why }) : null,
    finding.guidance
      ? el("p", { class: "fix" }, [
          el("span", { class: "fix-label", text: "What to do" }),
          finding.guidance.fix,
        ])
      : null,
    finding.evidence
      ? el("p", { class: "evidence" }, [
          el("span", { class: "fix-label", text: "Observed" }),
          el("code", { text: finding.evidence }),
        ])
      : null,
  ]);
}

// --- settings --------------------------------------------------------------

async function renderSettings(): Promise<void> {
  const container = root();
  clear(container);

  let profile = { agency_name: null as string | null, agency_logo_url: null as string | null };
  try {
    profile = await api.profile();
  } catch (error) {
    container.append(banner("error", describeError(error)));
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

  const form = el("form", { class: "card" }, [
    el("h1", { text: "Your details" }),
    el("p", {
      class: "blurb",
      text: "These appear on the reports you send to clients. Ours never do.",
    }),
    message,
    el("label", {}, ["Your business name", name]),
    el("label", {}, [
      "Logo URL",
      logo,
      el("span", { class: "hint", text: "Must be an https address." }),
    ]),
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
        message.replaceChildren(banner("ok", "Saved."));
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
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

  // Marking the current section costs one class and stops the header
  // looking like three interchangeable words.
  const section = window.location.hash.split("/")[1] ?? "";
  const link = (href: string, text: string, matches: string[]): HTMLElement =>
    el("a", {
      href,
      text,
      class: matches.includes(section) ? "active" : undefined,
    });

  nav.append(
    link("#/targets", "Sites", ["targets", "scans", ""]),
    link("#/settings", "Settings", ["settings"]),
  );

  const signOut = el("button", { class: "linklike", type: "button", text: "Sign out" });
  on(signOut, "click", () => {
    session.clear();
    window.location.hash = "#/signin";
  });
  nav.append(signOut);
}

function route(): void {
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

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", route);
