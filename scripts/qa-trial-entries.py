"""The free trial in Glarion's workspace navigation and at its locked points, rendered in Brave.

Usage: python scripts/qa-trial-entries.py <base-url> [screenshot-dir]
Build web/ (`npx tsc` in web) and serve it (for example `python -m http.server 8794 --directory web`).
The API is mocked for every plan state: free (trial offered), trial used, trial running, Solo monthly,
Studio yearly and Agency. Checks that the navigation offers the trial only while the account may start
it, counts a running trial down, shows nothing to a paying account, and that the site list's locked
"full scans need a plan" line leads with the same trial. Desktop and phone widths.
"""
import json, sys
from datetime import datetime, timedelta, timezone
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding="utf-8")
base = sys.argv[1]
out = sys.argv[2] if len(sys.argv) > 2 else None
BRAVE = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
ends = (datetime.now(timezone.utc) + timedelta(hours=68)).isoformat()

def sub(plan, name, state, manageable, can, extra=None):
    s = {"plan": plan, "plan_name": name, "max_targets": 1 if plan == "free" else 10, "targets_used": 1,
         "allows_scheduling": plan != "free", "allows_full_scan": plan != "free", "status": None if plan == "free" else "active",
         "current_period_end": None, "manageable": manageable, "trial_enabled": True, "trial_days": 3, "state": state,
         "blocked_reason": "none", "trial_ends_at": None, "cancel_at_period_end": False, "can_start_trial": can}
    s.update(extra or {})
    return s

STATES = {  # name: (subscription, expected navigation entry)
    "free": (sub("free", "Free", "none", False, True), "offer"),
    "trial-used": (sub("free", "Free", "none", False, False), None),
    "trial-active": (sub("solo", "Solo", "trialing", True, False, {"trial_ends_at": ends, "billing_interval": "month"}), "running"),
    "solo-monthly": (sub("solo", "Solo", "active", True, False, {"billing_interval": "month"}), None),
    "studio-yearly": (sub("studio", "Studio", "active", True, False, {"billing_interval": "year"}), None),
    "agency": (sub("agency", "Agency", "active", True, True), None),
}
TARGETS = [{"id": "t1", "domain": "example.com", "client_name": None, "verified": True, "verification_expires_at": None, "scan_cadence": "manual"}]
PRICES = {"server_time": datetime.now(timezone.utc).isoformat(), "trial_enabled": True, "trial_days": 3, "prices": []}

def handler(subscription):
    def handle(route, _req=None):
        path = route.request.url.split("/api/", 1)[1].split("?")[0]
        if path == "billing":
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(subscription))
        if path == "targets":
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(TARGETS))
        if path == "scans" and route.request.method == "POST":
            body = {"error": {"code": "plan_limit", "message": "Full scans are included in every paid plan."}}
            return route.fulfill(status=402, content_type="application/json", body=json.dumps(body))
        if path == "scans":
            return route.fulfill(status=200, content_type="application/json", body="[]")
        if path == "billing/prices":
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(PRICES))
        if path == "profile":
            return route.fulfill(status=200, content_type="application/json", body=json.dumps({"email": "qa@example.com"}))
        return route.fulfill(status=404, content_type="application/json", body='{"error":{"code":"not_found","message":"not mocked"}}')
    return handle

failures = []
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=BRAVE, headless=True)
    for name, (subscription, want) in STATES.items():
        for size, vp in (("desktop", {"width": 1366, "height": 860}), ("mobile", {"width": 390, "height": 844})):
            ctx = browser.new_context(viewport=vp)
            ctx.add_init_script("localStorage.setItem('glarion.session', '1'); localStorage.setItem('glarion.email', 'qa@example.com');")
            page = ctx.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)[:160]))
            page.route("**/api/**", handler(subscription))
            page.goto(f"{base}/index.html#/targets")
            page.wait_for_timeout(1500)
            nav = page.locator("#nav-trial")
            shown = nav.count() > 0 and nav.is_visible()
            kind = None
            if shown:
                kind = "running" if "running" in (nav.get_attribute("class") or "") else "offer"
            text = nav.inner_text() if shown else ""
            # The site list's locked line (free accounts only).
            locked = page.locator(".standing a[href='#/plan']")
            locked_text = locked.first.inner_text() if locked.count() else ""
            ok = kind == want and not errors
            if want == "offer":
                ok = ok and text == "Start your 3-day free trial" and locked_text == text
            if want == "running":
                ok = ok and text.startswith("Trial — 2 days")
            print(f"{'ok  ' if ok else 'FAIL'} {name:13} {size:7} nav={kind} {text!r} locked={locked_text!r} errors={errors[:2]}")
            if not ok:
                failures.append(f"{name} {size}")
            if out and name in ("free", "trial-active"):
                page.screenshot(path=f"{out}/glarion-{name}-{size}.png")
            ctx.close()
    browser.close()
print("FAILURES:", ", ".join(failures) or "none")
sys.exit(1 if failures else 0)
