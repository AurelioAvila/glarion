// The dashboard.
//
// Plain TypeScript with hash routing and no framework, matching the rest of
// the portfolio. Views render into a single root element; each render
// rebuilds its subtree rather than patching it, which is fast enough for a
// handful of screens and removes a whole class of stale-DOM bugs.

import { api, ApiError, session } from "./api.js";
import type { ScanDetail, ScanSummary, Target, TriagedFinding } from "./api.js";
import { append, byId, clear, copyableValue, detailRow, el, on } from "./dom.js";

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
function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isAuthFailure) {
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

// --- sign in / sign up -----------------------------------------------------

function renderAuth(mode: "signin" | "signup"): void {
  const isSignUp = mode === "signup";
  const container = root();
  clear(container);

  const message = el("div");
  const email = el("input", { type: "email", name: "email", required: true, autocomplete: "email" });
  const password = el("input", {
    type: "password",
    name: "password",
    required: true,
    autocomplete: isSignUp ? "new-password" : "current-password",
    minlength: isSignUp ? 12 : 1,
  });

  const button = submitButton(isSignUp ? "Create account" : "Sign in");
  const form = el("form", { class: "card auth-card" }, [
    el("h1", { text: isSignUp ? "Create your account" : "Sign in" }),
    message,
    el("label", {}, ["Email", email]),
    el("label", {}, [
      "Password",
      password,
      isSignUp ? el("span", { class: "hint", text: "At least 12 characters." }) : null,
    ]),
    button,
    el("p", { class: "switch" }, [
      isSignUp ? "Already have an account? " : "No account yet? ",
      el("a", { href: isSignUp ? "#/signin" : "#/signup", text: isSignUp ? "Sign in" : "Create one" }),
    ]),
  ]);

  on(form, "submit", (event) => {
    event.preventDefault();
    clear(message);

    void withPending(button, "Working…", async () => {
      try {
        const result = isSignUp
          ? await api.signup(email.value, password.value)
          : await api.login(email.value, password.value);
        session.set(result.token);
        window.location.hash = "#/targets";
      } catch (error) {
        message.replaceChildren(banner("error", describeError(error)));
      }
    });
  });

  container.append(form);
}

// --- targets ---------------------------------------------------------------

async function renderTargets(): Promise<void> {
  const container = root();
  clear(container);
  container.append(el("p", { class: "loading", text: "Loading…" }));

  let targets: Target[];
  try {
    targets = await api.targets();
  } catch (error) {
    clear(container);
    container.append(banner("error", describeError(error)));
    return;
  }

  clear(container);
  container.append(el("h1", { text: "Sites" }));
  container.append(addTargetForm());

  if (targets.length === 0) {
    container.append(
      el("p", { class: "empty", text: "No sites yet. Add one above to get started." }),
    );
    return;
  }

  const list = el("ul", { class: "target-list" });
  for (const target of targets) {
    list.append(targetRow(target));
  }
  container.append(list);
}

function targetRow(target: Target): HTMLElement {
  const status = target.verified
    ? el("span", { class: "chip chip-ok", text: "Verified" })
    : el("span", { class: "chip chip-pending", text: "Not verified" });

  return el("li", { class: "target-row" }, [
    el("div", {}, [
      el("a", { class: "target-domain", href: `#/targets/${target.id}`, text: target.domain }),
      target.client_name ? el("p", { class: "target-client", text: target.client_name }) : null,
    ]),
    status,
  ]);
}

function addTargetForm(): HTMLElement {
  const message = el("div");
  const domain = el("input", {
    type: "text",
    placeholder: "client-site.com",
    required: true,
    autocapitalize: "none",
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

    void withPending(button, "Adding…", async () => {
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
    el("p", { class: "breadcrumb" }, [el("a", { href: "#/targets", text: "← All sites" })]),
    el("h1", { text: target.domain }),
    target.client_name ? el("p", { class: "subtitle", text: target.client_name }) : null,
  );

  if (target.verified) {
    container.append(verifiedPanel(target));
    container.append(scansPanel(target, scans));
  } else {
    // Deliberately the only thing on the page. Until ownership is proved
    // nothing else can happen, and offering a scan button that always
    // fails would just be a way to waste the user's time.
    container.append(verificationPanel(target));
  }
}

function verifiedPanel(target: Target): HTMLElement {
  const expires = target.verification_expires_at
    ? new Date(target.verification_expires_at).toLocaleDateString()
    : null;

  return el("section", { class: "card" }, [
    el("div", { class: "panel-head" }, [
      el("span", { class: "chip chip-ok", text: "Verified" }),
      expires ? el("span", { class: "muted", text: `Re-check needed after ${expires}` }) : null,
    ]),
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
  const started = new Date(scan.created_at).toLocaleString();

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

  const right =
    scan.status === "completed"
      ? el("a", { class: "link", href: `#/scans/${scan.id}`, text: "View findings" })
      : scan.status === "failed" && scan.failure_reason
        ? el("span", { class: "muted", text: scan.failure_reason })
        : null;

  return el("div", { class: "scan-row" }, [
    status,
    el("span", { class: "muted", text: started }),
    right,
  ]);
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

  nav.append(
    el("a", { href: "#/targets", text: "Sites" }),
    el("a", { href: "#/settings", text: "Settings" }),
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

  if (!session.isSignedIn) {
    renderAuth(parts[0] === "signup" ? "signup" : "signin");
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
