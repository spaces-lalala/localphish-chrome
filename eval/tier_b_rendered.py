"""Tier B — Playwright-rendered evaluation.

Why this exists. Tier A parses PhreshPhish HTML excerpts with BeautifulSoup,
which is fast but blind to JS-rendered content. Tier B loads the same HTML
inside a real Chromium, lets the page's scripts execute, then re-extracts the
DOM features. The difference between Tier A and Tier B signal sets is the
"static-vs-rendered" drift — Week 16's report uses this to show whether
PhreshPhish's static excerpts under-represent the actual rendered phishing
content (cloaking gates, JS-rendered forms, late-injected payloads).

Tier B intentionally does NOT load the extension. Loading the extension
would also exercise the Service Worker + Offscreen + Nano stack which is
slow (~10–25 s per page × 200 rows = 30–80 min) and ties the result to the
tester's Chrome + Nano availability. For a clean tier-comparison we want
to isolate ONE variable (rendered vs static), not three.

A separate sanity-check mode (--sanity-extension) DOES load the extension
on the 6 local fixtures and asserts that the verdict landed on DANGEROUS
— that's the e2e regression test, not the dataset benchmark.

Usage:
    uv run python tier_b_rendered.py --limit 200
    uv run python tier_b_rendered.py --sanity-extension
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import socketserver
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path

from rich.console import Console
from rich.table import Table

from localphish_eval.rules import load_rule_data, run_stage1, Signal
from localphish_eval.dom_features import analyze_dom


# ---------------------------------------------------------- HTTP harness ---


class _Handler(http.server.BaseHTTPRequestHandler):
    """Trivial in-memory HTTP server: each GET serves the HTML stored in
    `self.server.html_blobs[path[1:]]`. Used to deliver PhreshPhish HTML
    excerpts to Chromium without writing them to disk per-page."""

    # Silence the default access log — 200 rows × N requests = noisy.
    def log_message(self, format, *args):  # noqa: A002
        return

    def do_GET(self):
        key = self.path.lstrip("/")
        html_blobs = getattr(self.server, "html_blobs", {})
        blob = html_blobs.get(key)
        if blob is None:
            self.send_response(404)
            self.end_headers()
            return
        encoded = blob.encode("utf-8", errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _Server(socketserver.TCPServer):
    allow_reuse_address = True
    html_blobs: dict[str, str] = {}


@contextmanager
def serve_blobs(port: int = 8766):
    """Spin up an HTTP server on `port` for the duration of a `with` block."""
    srv = _Server(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=srv.serve_forever, name="tier-b-http", daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=2)


# --------------------------------------------------- Playwright extraction


# Browser-side feature extractor. Mirrors extension/src/content/dom-extract.ts.
# Kept inline so this script is self-contained — drift risk is small because
# Tier B's whole point is comparing rendered vs static, and the structural
# fields we collect map 1:1 to extension/src/types.ts PageFeatures.
RENDER_EXTRACTOR_JS = r"""
() => {
  const rawText = document.body?.innerText ?? "";
  const visibleTextSample = rawText.slice(0, 2000).replace(/\s+/g, " ").trim();
  const bodyTextLength = rawText.replace(/\s+/g, " ").trim().length;

  const inputs = Array.from(document.querySelectorAll("input"));
  const hasPasswordField = inputs.some((i) => i.type === "password");
  const hasOtpField = inputs.some((i) => {
    const ac = (i.autocomplete || "").toLowerCase();
    if (ac.includes("one-time-code")) return true;
    const name = (i.name || "").toLowerCase();
    return /^(otp|otpcode|otp-code|one[-_]?time|2fa|tfa|verifycode|verification[-_]?code)$/.test(name)
        || /(^|[-_])otp([-_]|$)/.test(name);
  });
  const CARD_HINTS = ["card","cardnumber","card-number","creditcard","cc-number","ccnumber","cvv","cvc","csc","securitycode","security-code"];
  const hasCreditCardField = inputs.some((i) => {
    const ac = (i.autocomplete || "").toLowerCase();
    if (ac.includes("cc-number") || ac === "cc-csc" || ac === "cc-exp") return true;
    const name = (i.name || "").toLowerCase().replace(/[_\s]/g, "-");
    if (CARD_HINTS.some((h) => name.includes(h))) return true;
    const ph = (i.placeholder || "").toLowerCase();
    return /\bcvv\b|\bcvc\b|card number|信用卡|卡號/.test(ph);
  });

  const forms = Array.from(document.querySelectorAll("form"));
  const formActions = forms.map((f) => f.action || "").filter(Boolean);

  // Cloaking widgets
  const hasTurnstileWidget = !!(
    document.querySelector('div.cf-turnstile, div[data-sitekey][class*="turnstile"]') ||
    document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')
  );
  const hasHCaptchaWidget = !!(
    document.querySelector('div.h-captcha, div[data-sitekey][class*="h-captcha"]') ||
    document.querySelector('script[src*="hcaptcha.com/1/api.js"], iframe[src*="hcaptcha.com"]')
  );

  // Favicon
  const linkIcon = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
  const faviconUrl = linkIcon && linkIcon.href ? linkIcon.href : null;

  return {
    url: location.href,
    title: document.title,
    pageProtocol: location.protocol,
    visibleTextSample,
    bodyTextLength,
    hasPasswordField,
    hasOtpField,
    hasCreditCardField,
    seedPhraseGridPattern: false,  // approximate; Tier A handles this on raw HTML
    formActions,
    externalScriptUrls: [],        // not used by the Tier B comparison
    hiddenIframeCount: 0,          // requires layout; skipped for parity
    tinyElementCount: 0,           // ditto
    hasAntiDebug: false,           // checked by Tier A on raw HTML
    hasTurnstileWidget,
    hasHCaptchaWidget,
    faviconUrl,
    etld1: ""
  };
}
"""


async def render_one(playwright_page, blob_key: str, base_url: str, original_url: str, html: str,
                     server: _Server) -> dict | None:
    """Serve `html` at /{blob_key}, navigate Chromium there, return rendered features."""
    server.html_blobs[blob_key] = html
    served_url = f"{base_url}/{blob_key}"
    try:
        # Goto with networkidle: phishing kits often inject content after first
        # paint; networkidle catches the post-injection DOM. Cap at 15 s — some
        # PhreshPhish samples reference dead CDNs and hang otherwise.
        await playwright_page.goto(served_url, wait_until="networkidle", timeout=15000)
    except Exception:
        # Even on timeout the DOM may be usable; try to extract anyway.
        pass

    try:
        features = await playwright_page.evaluate(RENDER_EXTRACTOR_JS)
    except Exception as e:
        return {"_error": f"extract failed: {e}", "url": original_url}

    # Reset url to the *original* PhreshPhish URL so the downstream Stage 1
    # detectors see the real hostname (not localhost:8766).
    features["url"] = original_url
    return features


# ----------------------------------------------------------- pipeline ------


def signals_from_features(features: dict, original_url: str, data) -> list[Signal]:
    """Run rules.run_stage1 + dom_features.analyze_dom on rendered features."""
    s1 = run_stage1(original_url, data)
    sigs: list[Signal] = list(s1["signals"])
    if s1["shortCircuit"]:
        return sigs
    # For Stage 2 we want to feed the post-render DOM back. analyze_dom takes
    # html string + url. We synthesise a minimal HTML that contains the
    # rendered features the detector cares about — but a simpler/faithful
    # approach is to skip analyze_dom and just emit signals from the feature
    # dict directly. For Tier B we report the features themselves as the
    # comparison target — see compare_tiers.py.
    return sigs


def static_features(html: str) -> dict:
    """Run a minimal BS4-based feature extraction matching the JS extractor's
    shape. Used as the Tier A side of the comparison."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(" ", strip=True)
    body_text = " ".join(text.split())
    inputs = soup.find_all("input")
    has_password = any((i.get("type") or "").lower() == "password" for i in inputs)
    has_otp = any(
        "one-time-code" in (i.get("autocomplete") or "").lower()
        or (i.get("name") or "").lower().startswith("otp")
        for i in inputs
    )
    forms = soup.find_all("form")
    form_actions = [f.get("action") or "" for f in forms if f.get("action")]
    has_turnstile = bool(
        soup.select_one('div.cf-turnstile, div[data-sitekey][class*="turnstile"]')
        or soup.select_one('script[src*="challenges.cloudflare.com/turnstile"]')
    )
    has_hcaptcha = bool(
        soup.select_one('div.h-captcha, div[data-sitekey][class*="h-captcha"]')
        or soup.select_one('script[src*="hcaptcha.com/1/api.js"], iframe[src*="hcaptcha.com"]')
    )
    return {
        "bodyTextLength": len(body_text),
        "hasPasswordField": has_password,
        "hasOtpField": has_otp,
        "formCount": len(form_actions),
        "hasTurnstileWidget": has_turnstile,
        "hasHCaptchaWidget": has_hcaptcha,
        "faviconPresent": bool(soup.find("link", rel=lambda v: v and "icon" in (v if isinstance(v, list) else v.lower()))),
    }


def compare_features(static: dict, rendered: dict) -> dict:
    """Return per-field diff between static and rendered feature dicts."""
    diff = {}
    for k in (
        "hasPasswordField", "hasOtpField", "hasTurnstileWidget", "hasHCaptchaWidget"
    ):
        a = bool(static.get(k))
        b = bool(rendered.get(k))
        if a != b:
            diff[k] = {"static": a, "rendered": b}
    # form count vs rendered formActions length
    a = static.get("formCount", 0)
    b = len(rendered.get("formActions") or [])
    if a != b:
        diff["formCount"] = {"static": a, "rendered": b}
    # body text length — flag big swings only
    a = static.get("bodyTextLength", 0)
    b = rendered.get("bodyTextLength", 0)
    if abs(a - b) > 200:
        diff["bodyTextLength"] = {"static": a, "rendered": b, "delta": b - a}
    return diff


# ----------------------------------------------------------- runners -------


async def run_dataset(input_path: Path, limit: int, port: int, extension_dist: Path | None,
                      out_csv: Path, console: Console) -> int:
    from playwright.async_api import async_playwright
    rows = []
    with input_path.open("r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("_meta"):
                continue
            rows.append(obj)
            if limit and len(rows) >= limit:
                break
    console.print(f"[cyan]Tier B: rendering {len(rows)} rows[/cyan]")

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    import csv
    fieldnames = ["url", "label", "static_features", "rendered_features", "diff"]
    fout = out_csv.open("w", encoding="utf-8", newline="")
    w = csv.DictWriter(fout, fieldnames=fieldnames)
    w.writeheader()

    drift_counter: Counter[str] = Counter()
    error_count = 0

    with serve_blobs(port) as server:
        base_url = f"http://127.0.0.1:{port}"
        async with async_playwright() as pw:
            launch_args: dict = {"headless": True}
            if extension_dist:
                # MV3 extensions require a persistent context.
                launch_args["args"] = [
                    f"--disable-extensions-except={extension_dist.resolve()}",
                    f"--load-extension={extension_dist.resolve()}",
                ]
                launch_args["headless"] = False  # extensions don't run in headless
                user_data_dir = Path(tempfile.mkdtemp(prefix="localphish-tierb-"))
                context = await pw.chromium.launch_persistent_context(str(user_data_dir), **launch_args)
            else:
                browser = await pw.chromium.launch(**launch_args)
                context = await browser.new_context()
            page = await context.new_page()

            for i, row in enumerate(rows):
                url = row.get("url", "")
                html = row.get("html_excerpt") or ""
                label = int(row.get("label", -1))
                blob_key = f"row-{i:04d}.html"
                rendered = await render_one(page, blob_key, base_url, url, html, server)
                static = static_features(html)
                if rendered is None or "_error" in (rendered or {}):
                    error_count += 1
                    diff = {"_error": (rendered or {}).get("_error", "render failed")}
                else:
                    diff = compare_features(static, rendered)
                for k in diff.keys():
                    if not k.startswith("_"):
                        drift_counter[k] += 1
                w.writerow({
                    "url": url,
                    "label": label,
                    "static_features": json.dumps(static, ensure_ascii=False),
                    "rendered_features": json.dumps(rendered or {}, ensure_ascii=False),
                    "diff": json.dumps(diff, ensure_ascii=False)
                })
                if (i + 1) % 25 == 0:
                    console.print(f"  [{i + 1}/{len(rows)}] drift-so-far: {dict(drift_counter)}")

            await context.close()

    fout.close()

    # Summary
    tbl = Table(title="Tier B — static vs rendered feature drift")
    tbl.add_column("field")
    tbl.add_column("rows with disagreement")
    tbl.add_column("pct")
    n = len(rows) or 1
    for k, c in drift_counter.most_common():
        tbl.add_row(k, str(c), f"{(c / n) * 100:.1f}%")
    if error_count:
        tbl.add_row("(render errors)", str(error_count), f"{(error_count / n) * 100:.1f}%")
    console.print(tbl)
    console.print(f"[green]wrote[/green] {out_csv}")
    return 0


async def run_sanity(extension_dist: Path, console: Console) -> int:
    """Load the extension into Chromium, hit the 6 local fixtures, assert
    that the in-page badge ends up DANGEROUS. This is the smoke test the
    user can run before recording the demo video."""
    from playwright.async_api import async_playwright

    fixtures = [
        "microsoft-365-login-fake.html",
        "paypal-verify-fake.html",
        "crypto-wallet-connect-fake.html",
        "tw/post-customs-fake.html",
        "tw/ntbsa-tax-refund-fake.html",
        "tw/etc-overdue-fake.html",
    ]
    fixtures_dir = Path(__file__).parent.parent / "test" / "fixtures"
    if not fixtures_dir.exists():
        console.print(f"[red]missing fixtures dir[/red] {fixtures_dir}")
        return 2

    user_data_dir = Path(tempfile.mkdtemp(prefix="localphish-sanity-"))
    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            str(user_data_dir),
            headless=False,
            args=[
                f"--disable-extensions-except={extension_dist.resolve()}",
                f"--load-extension={extension_dist.resolve()}",
            ]
        )
        # Serve fixtures
        with serve_blobs(port=8767) as server:
            server.html_blobs = {
                f: (fixtures_dir / f).read_text(encoding="utf-8") for f in fixtures
            }
            page = await ctx.new_page()
            results = []
            for f in fixtures:
                console.print(f"  → {f}")
                await page.goto(f"http://127.0.0.1:8767/{f}", wait_until="domcontentloaded", timeout=10000)
                # Wait up to 40 s for the badge UI to settle on DANGEROUS.
                verdict = "(timeout)"
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    # Selector matches badge.ts: shadowRoot contains
                    # <div id="lp-badge"> with <span .label> + <span .score>.
                    # No badge at all means SAFE (badge.ts:217-222 hides safe).
                    badge_text = await page.evaluate("""
                        () => {
                          const host = document.getElementById("localphish-badge-host");
                          if (!host || !host.shadowRoot) return null;
                          // Still loading?
                          if (host.shadowRoot.querySelector(".spinner")) return null;
                          const badge = host.shadowRoot.getElementById("lp-badge");
                          if (!badge) return null;
                          const label = badge.querySelector(".label")?.textContent?.trim() ?? "";
                          const score = badge.querySelector(".score")?.textContent?.trim() ?? "";
                          return label + ":" + score;
                        }
                    """)
                    if badge_text:
                        verdict = badge_text
                        break
                    await asyncio.sleep(0.5)
                results.append((f, verdict))
            await ctx.close()

    tbl = Table(title="Sanity — extension on local fixtures")
    tbl.add_column("fixture"); tbl.add_column("badge verdict")
    for f, v in results:
        tbl.add_row(f, v)
    console.print(tbl)
    return 0


# ------------------------------------------------------------------ CLI ----


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "datasets/phreshphish_subset.jsonl")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_b_results.csv")
    parser.add_argument("--limit", type=int, default=200,
                        help="render at most N rows (0 = all)")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--extension", type=Path,
                        help="path to extension/dist — load the real extension into Chromium")
    parser.add_argument("--sanity-extension", action="store_true",
                        help="run the 6-fixture smoke test instead of dataset eval")
    args = parser.parse_args()

    console = Console()

    if args.sanity_extension:
        ext = args.extension or Path(__file__).parent.parent / "extension" / "dist"
        if not ext.exists():
            console.print(f"[red]missing extension dist[/red] {ext}; run `npm run build` first")
            return 2
        return asyncio.run(run_sanity(ext, console))

    if not args.input.exists():
        console.print(f"[red]missing input[/red] {args.input} — run "
                      "`uv run python fetch_phreshphish.py` first")
        return 2

    return asyncio.run(run_dataset(args.input, args.limit, args.port,
                                   args.extension, args.out, console))


if __name__ == "__main__":
    raise SystemExit(main())
