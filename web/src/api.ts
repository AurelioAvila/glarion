// Typed client for the Glarion API.
//
// Every response shape here mirrors a Rust type in crates/api. They are
// written out rather than inferred so a backend change that alters a field
// shows up as a type error in the views instead of as `undefined` on screen.

export interface SignupDetails {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  email: string;
  password: string;
  passwordConfirmation: string;
}

export interface Profile {
  agency_name: string | null;
  agency_logo_url: string | null;
  /// The address this account signs in with. Sent on GET only — the server
  /// ignores it on a save, because moving an account to another address is
  /// the confirmed change-of-address flow, not a profile field.
  email?: string | null;
}

export interface PreviewObservation {
  label: string;
  value: string;
  is_finding: boolean;
}

export interface PreviewResult {
  domain: string;
  observations: PreviewObservation[];
  notes: string[];
  /// What the check deliberately did not do. Sent with every result so the
  /// boundary travels with the data rather than living in one page.
  caveat: string;
}

export interface Subscription {
  plan: string;
  plan_name: string;
  max_targets: number;
  targets_used: number;
  allows_scheduling: boolean;
  allows_full_scan: boolean;
  status: string | null;
  current_period_end: string | null;
  manageable: boolean;
}

export type Cadence = "manual" | "weekly" | "monthly";

export interface Target {
  id: string;
  domain: string;
  client_name: string | null;
  verified: boolean;
  verification_expires_at: string | null;
  scan_cadence: Cadence;
}

export interface VerificationInstructions {
  verification_id: string;
  token: string;
  dns_record_name: string;
  dns_record_value: string;
  well_known_url: string;
  well_known_content: string;
}

export interface VerificationResult {
  verified: boolean;
  expires_at: string | null;
  detail: string;
}

export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface ScanSummary {
  id: string;
  target_id: string;
  domain: string;
  tool: string;
  status: ScanStatus;
  failure_reason: string | null;
  created_at: string;
  completed_at: string | null;
  /// Everything the scanner reported, including inventory.
  finding_count: number;
  /// What survived triage. This is the number to show a reader; the raw
  /// count tells an agency their client has thirty-two problems when the
  /// answer is three.
  actionable_count: number;
}

export type Disposition = "act" | "review" | "inventory";
export type Priority = "urgent" | "high" | "medium" | "low" | "none";

export interface Guidance {
  why: string;
  fix: string;
}

export interface TriagedFinding {
  title: string;
  disposition: Disposition;
  priority: Priority;
  scanner_severity: string;
  guidance: Guidance | null;
  evidence: string | null;
  template_id: string;
  /// Which matcher fired. For a detection template this is the answer
  /// itself — the firewall's name, the technology — while the evidence is
  /// only where we looked.
  matcher: string;
  occurrences: number;
}

export interface TriagedScan {
  actionable: TriagedFinding[];
  review: TriagedFinding[];
  inventory: TriagedFinding[];
}

export interface ScanDetail extends ScanSummary {
  triaged: TriagedScan;
}

/// An error carrying what the API actually said, so a view can show the
/// server's message rather than a generic failure.
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  /// True when the session is gone and the only useful response is to send
  /// the user back to sign-in.
  get isAuthFailure(): boolean {
    return this.status === 401;
  }
}

const TOKEN_KEY = "glarion.token";
const SESSION_MARKER_KEY = "glarion.session";
const REMEMBERED_EMAIL_KEY = "glarion.email";

/// The address to prefill on the sign-in form.
///
/// Opt-in, and only ever the address — never the password. On a shared
/// computer this does reveal who has been signing in, which is why it is a
/// choice rather than the default.
export const rememberedEmail = {
  get(): string | null {
    try {
      return localStorage.getItem(REMEMBERED_EMAIL_KEY);
    } catch {
      return null;
    }
  },

  set(email: string | null): void {
    try {
      if (email) localStorage.setItem(REMEMBERED_EMAIL_KEY, email);
      else localStorage.removeItem(REMEMBERED_EMAIL_KEY);
    } catch {
      // Storage unavailable; the box simply will not be remembered.
    }
  },
};

// New sessions live exclusively in an HttpOnly cookie. `token()` only reads
// the former localStorage key so sessions created before this migration keep
// working until they expire; `set()` removes that legacy credential.
export const session = {
  token(): string | null {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      // Storage can be unavailable in private modes. Treat that as signed
      // out rather than crashing the app on load.
      return null;
    }
  },

  set(_token?: string): void {
    try {
      // Authentication now lives in an HttpOnly cookie. Keep only a
      // non-sensitive UI marker and remove any legacy readable token.
      localStorage.removeItem(TOKEN_KEY);
      localStorage.setItem(SESSION_MARKER_KEY, "1");
    } catch {
      // Ignored: the user stays signed in for this page view only.
    }
  },

  clear(): void {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(SESSION_MARKER_KEY);
    } catch {
      // Nothing useful to do.
    }
  },

  get isSignedIn(): boolean {
    try {
      return this.token() !== null || localStorage.getItem(SESSION_MARKER_KEY) === "1";
    } catch {
      return false;
    }
  },
};

/// Where the API lives.
///
/// Same origin in production, which is the default and needs no
/// configuration. The meta tag overrides that when it is set.
///
/// The localhost fallback exists so development does not require editing a
/// tracked file — the reliable way for someone's machine-specific URL to
/// get committed by accident.
function apiBase(): string {
  const configured = document
    .querySelector<HTMLMetaElement>('meta[name="glarion-api"]')
    ?.content?.trim();

  if (configured) return configured.replace(/\/$/, "");

  const { hostname, port } = window.location;
  const isLocal = hostname === "localhost" || hostname === "127.0.0.1";
  if (isLocal && port !== "8080") return "http://localhost:8080";

  return "";
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  const token = session.token();
  if (token) headers["authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) headers["x-glarion-csrf"] = "1";

  let response: Response;
  try {
    response = await fetch(`${apiBase()}${path}`, {
      method,
      headers,
      credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    // fetch only rejects on network-level failure, which is worth
    // distinguishing from a server error the user could act on.
    throw new ApiError(0, "network", "Could not reach the server.");
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    if (response.status === 401) session.clear();
    const detail = payload as { error?: string; message?: string } | null;
    throw new ApiError(
      response.status,
      detail?.error ?? "error",
      detail?.message ?? `Request failed (${response.status}).`,
    );
  }

  return payload as T;
}

export const api = {
  signup(details: SignupDetails) {
    return request<{ email: string; message: string; delivered: boolean }>("POST", "/api/auth/signup", {
      first_name: details.firstName,
      last_name: details.lastName,
      date_of_birth: details.dateOfBirth,
      email: details.email,
      password: details.password,
      password_confirmation: details.passwordConfirmation,
    });
  },

  verifyEmail(token: string) {
    return request<{ user_id: string }>("POST", "/api/auth/verify", { token });
  },

  resendVerification(email: string) {
    return request<{ message: string }>("POST", "/api/auth/resend-verification", { email });
  },

  changeEmail(newEmail: string, password: string) {
    return request<{ message: string }>("POST", "/api/account/email", {
      new_email: newEmail,
      password,
    });
  },

  /// Changing the password from inside the account.
  ///
  /// The reply carries no token: the server rotates the session cookie in
  /// the same response, which is what keeps this device signed in while
  /// every other one is signed out.
  changePassword(currentPassword: string, newPassword: string, confirmation: string) {
    return request<{ message: string }>("POST", "/api/account/password", {
      current_password: currentPassword,
      new_password: newPassword,
      new_password_confirmation: confirmation,
    });
  },

  confirmEmailChange(token: string) {
    return request<{ message: string }>("POST", "/api/auth/confirm-email-change", { token });
  },

  forgotPassword(email: string) {
    return request<{ message: string }>("POST", "/api/auth/forgot-password", { email });
  },

  // No token in the reply: the session arrives as an HttpOnly cookie, the same
  // as sign-in and confirmation. A reset that handed one back in the body
  // would be the single path where a session lands where script can read it.
  resetPassword(token: string, password: string, passwordConfirmation: string) {
    return request<{ user_id: string }>("POST", "/api/auth/reset-password", {
      token,
      password,
      password_confirmation: passwordConfirmation,
    });
  },

  login(email: string, password: string) {
    return request<{ user_id: string }>("POST", "/api/auth/login", {
      email,
      password,
    });
  },

  logout() {
    return request<void>("POST", "/api/auth/logout");
  },

  profile() {
    return request<Profile>("GET", "/api/profile");
  },

  saveProfile(profile: Profile) {
    return request<Profile>("PUT", "/api/profile", profile);
  },

  targets() {
    return request<Target[]>("GET", "/api/targets");
  },

  addTarget(domain: string, clientName: string | null) {
    return request<Target>("POST", "/api/targets", {
      domain,
      client_name: clientName,
    });
  },

  /// The check that needs no ownership proof.
  ///
  /// Reads only what a site publishes to any visitor, so it works on a
  /// domain nobody has verified — which is the whole point: it shows
  /// something real before asking anyone to edit DNS.
  preview(domain: string) {
    return request<PreviewResult>("POST", "/api/preview", { domain });
  },

  subscription() {
    return request<Subscription>("GET", "/api/billing");
  },

  checkout(plan: string, interval: "monthly" | "yearly") {
    return request<{ url: string }>("POST", "/api/billing/checkout", { plan, interval });
  },

  billingPortal() {
    return request<{ url: string }>("POST", "/api/billing/portal", {});
  },

  deleteAccount(password: string) {
    return request<{ message: string }>("DELETE", "/api/account", { password });
  },

  setCadence(targetId: string, cadence: Cadence) {
    return request<Target>("PUT", `/api/targets/${encodeURIComponent(targetId)}/cadence`, {
      cadence,
    });
  },

  startVerification(targetId: string) {
    return request<VerificationInstructions>(
      "POST",
      `/api/targets/${encodeURIComponent(targetId)}/verification`,
    );
  },

  checkVerification(targetId: string, method: "dns_txt" | "well_known_file") {
    return request<VerificationResult>(
      "POST",
      `/api/targets/${encodeURIComponent(targetId)}/verification/check`,
      { method },
    );
  },

  scans(targetId?: string) {
    const query = targetId ? `?target_id=${encodeURIComponent(targetId)}` : "";
    return request<ScanSummary[]>("GET", `/api/scans${query}`);
  },

  scan(scanId: string) {
    return request<ScanDetail>("GET", `/api/scans/${encodeURIComponent(scanId)}`);
  },

  /// Queues one scan.
  ///
  /// The tool is chosen by the caller rather than fixed here. "tls" was
  /// allowlisted by the server and unreachable from the dashboard, so the
  /// certificate checks a paying customer had been sold could only ever
  /// run through the preview.
  startScan(targetId: string, tool: "nuclei" | "tls") {
    return request<ScanSummary>("POST", "/api/scans", {
      target_id: targetId,
      tool,
      accept_terms: true,
    });
  },

  /// Downloads the report.
  ///
  /// Fetched rather than linked because the endpoint needs an Authorization
  /// header, which a plain anchor cannot send. The blob URL is revoked
  /// immediately after the click so it does not linger as a way to read the
  /// document without authenticating again.
  async downloadReport(scanId: string, domain: string): Promise<void> {
    const token = session.token();
    const response = await fetch(
      `${apiBase()}/api/scans/${encodeURIComponent(scanId)}/report`,
      {
        credentials: "include",
        headers: token ? { authorization: `Bearer ${token}` } : {},
      },
    );

    if (!response.ok) {
      throw new ApiError(response.status, "report", "Could not build the report.");
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `security-review-${domain}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  },
};
