// Content script — DOM feature extractor.
// Runs in ISOLATED world. Pure read-only scan; never mutates the page.
// All raw URLs are passed through to the SW as strings; eTLD+1 resolution
// happens there to avoid duplicating the tldts dataset in the content bundle.

import type { PageFeatures } from "@/types";

// ---- Form-field detection -------------------------------------------------

const CREDIT_CARD_NAME_HINTS = [
  "card", "cardnumber", "card-number", "creditcard", "cc-number", "ccnumber",
  "cvv", "cvc", "csc", "securitycode", "security-code"
];

function inputMatchesCreditCard(input: HTMLInputElement): boolean {
  const ac = (input.autocomplete || "").toLowerCase();
  if (ac.includes("cc-number") || ac === "cc-csc" || ac === "cc-exp") return true;
  const name = (input.name || "").toLowerCase().replace(/[_\s]/g, "-");
  if (CREDIT_CARD_NAME_HINTS.some((h) => name.includes(h))) return true;
  const placeholder = (input.placeholder || "").toLowerCase();
  if (/\bcvv\b|\bcvc\b|card number|信用卡|卡號/.test(placeholder)) return true;
  return false;
}

function inputMatchesOtp(input: HTMLInputElement): boolean {
  const ac = (input.autocomplete || "").toLowerCase();
  if (ac.includes("one-time-code")) return true;
  const name = (input.name || "").toLowerCase();
  if (/^(otp|otpcode|otp-code|one[-_]?time|2fa|tfa|verifycode|verification[-_]?code)$/.test(name)) return true;
  if (/(^|[-_])otp([-_]|$)/.test(name)) return true;
  return false;
}

// Taiwan national ID (身分證字號) is 1 uppercase letter + 9 digits ("A123456789").
// 統一編號 (company ID) is 8 digits. Legit sites that need these collect them
// over verified channels (gov.tw / banks). Phishing kits ask for them inline
// to support post-takeover identity theft / SIM-swap. We flag presence so
// Stage 2 can combine with cross-eTLD+1 form actions for high-precision FP.
const TW_NATIONAL_ID_NAME_HINTS = [
  "idno", "idnum", "id-number", "nationalid", "national-id",
  "twid", "tw-id", "personid", "person-id",
  "身分證", "身份證", "統一編號", "統編"
];
const TW_NATIONAL_ID_PATTERN = /\b[A-Z][12]\d{8}\b/; // strict Taiwan ID format

function inputMatchesTwNationalId(input: HTMLInputElement): boolean {
  const name = (input.name || "").toLowerCase().replace(/[_\s]/g, "-");
  if (TW_NATIONAL_ID_NAME_HINTS.some((h) => name.includes(h.toLowerCase()))) return true;
  const placeholder = input.placeholder || "";
  if (placeholder.includes("身分證") || placeholder.includes("身份證") ||
      placeholder.includes("統一編號") || placeholder.includes("統編")) return true;
  if (TW_NATIONAL_ID_PATTERN.test(placeholder)) return true;
  const pattern = input.pattern || "";
  if (pattern.includes("[A-Z]") && pattern.includes("[0-9]")) {
    // crude: matches "[A-Z][0-9]{9}" style HTML5 patterns
    return true;
  }
  return false;
}

// ---- Seed-phrase grid pattern ---------------------------------------------

/** Heuristic: a form contains a password field AND ≥8 short text inputs that
 *  share a name prefix (w1, w2, ... / word1, word2, ...). This is the canonical
 *  crypto-wallet drainer form. Real wallets NEVER ask for the seed phrase in
 *  a login flow. */
function formMatchesSeedPhraseGrid(form: HTMLFormElement): boolean {
  const pwd = form.querySelector('input[type="password"]');
  if (!pwd) return false;
  const texts = Array.from(form.querySelectorAll('input[type="text"], input:not([type])'));
  if (texts.length < 8) return false;

  // Group by name prefix: strip trailing digits and check whether at least 8
  // share the same root (e.g. w1, w2, ..., w12 all have root "w").
  const roots = new Map<string, number>();
  for (const el of texts as HTMLInputElement[]) {
    const root = (el.name || el.placeholder || "").replace(/\d+$/, "").trim().toLowerCase();
    if (root === "") continue;
    roots.set(root, (roots.get(root) ?? 0) + 1);
  }
  for (const c of roots.values()) {
    if (c >= 8) return true;
  }
  return false;
}

// ---- Iframe + tiny-element visibility -------------------------------------

function isHidden(el: Element): boolean {
  const cs = getComputedStyle(el as HTMLElement);
  if (cs.display === "none" || cs.visibility === "hidden") return true;
  const rect = (el as HTMLElement).getBoundingClientRect();
  if (rect.width <= 2 && rect.height <= 2) return true;
  return false;
}

function isInteractive(el: Element): boolean {
  if (el.matches("a[href], button, form")) return true;
  // contains form or link descendants? Then it's still interactive even if
  // wrapper appears tiny.
  return el.querySelector("a[href], button, form, input") !== null;
}

// ---- Anti-debug heuristics -----------------------------------------------

const ANTI_DEBUG_SCRIPT_PATTERNS = [
  /\bkeyCode\s*===?\s*123\b/,         // F12
  /\be\.key(?:Code)?\s*===?\s*['"]?F12['"]?/,
  /\bctrlKey[^;]*shiftKey[^;]*(73|74)\b/,  // Ctrl+Shift+I/J — DevTools shortcuts
  /\bdebugger\s*;[\s\S]{0,80}\bsetInterval/,  // common DevTools-defeating pattern
  /window\.outerHeight\s*-\s*window\.innerHeight\s*>\s*\d{2,3}/, // DevTools detection
  /\bdisableContextMenu\b/i,
  /\bnoDevTools?\b/i
];

const BLOCKING_ATTR_NAMES = ["oncontextmenu", "onkeydown", "onkeyup", "onkeypress"];

function detectAntiDebug(): boolean {
  // Inline attributes on common roots — phishing kits often slap these on <body>.
  const roots: (HTMLElement | null)[] = [document.body, document.documentElement];
  for (const root of roots) {
    if (!root) continue;
    for (const attr of BLOCKING_ATTR_NAMES) {
      const v = root.getAttribute(attr);
      if (!v) continue;
      // "return false" is the giveaway. Pure innocuous handlers (e.g. analytics)
      // don't typically return false.
      if (/return\s+false/i.test(v) || /preventDefault\s*\(/.test(v)) {
        return true;
      }
    }
  }

  // Inline scripts containing DevTools-defeating patterns.
  // Bounded scan: at most 30 inline scripts, at most 4 KB each.
  const inlineScripts = Array.from(document.querySelectorAll<HTMLScriptElement>("script:not([src])")).slice(0, 30);
  for (const s of inlineScripts) {
    const text = (s.textContent ?? "").slice(0, 4096);
    if (!text) continue;
    for (const pat of ANTI_DEBUG_SCRIPT_PATTERNS) {
      if (pat.test(text)) return true;
    }
  }

  return false;
}

function isTinyOffscreenInteractive(el: HTMLElement): boolean {
  const cs = getComputedStyle(el);
  // 0 opacity but rendered — classic clickjacking layer.
  if (parseFloat(cs.opacity || "1") === 0) return isInteractive(el);

  const rect = el.getBoundingClientRect();
  if (rect.width <= 1 && rect.height <= 1 && isInteractive(el)) return true;

  // Off-screen position (negative or > 10k far away).
  if ((rect.left < -1000 || rect.top < -1000) && isInteractive(el)) return true;

  return false;
}

// ---- Cloaking widgets -----------------------------------------------------
// Cheap structural check for verify-wall gates. We look at *static DOM*
// markers the kit author needs to emit so the JS challenge has something to
// hook onto; the actual challenge usually injects more DOM after passing.

function detectTurnstileWidget(): boolean {
  // Cloudflare Turnstile is summoned by either:
  //   - <div class="cf-turnstile" data-sitekey="...">
  //   - explicit <script src="https://challenges.cloudflare.com/turnstile/v0/api.js">
  if (document.querySelector('div.cf-turnstile, div[data-sitekey][class*="turnstile"]')) {
    return true;
  }
  if (document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')) {
    return true;
  }
  return false;
}

function detectHCaptchaWidget(): boolean {
  if (document.querySelector('div.h-captcha, div[data-sitekey][class*="h-captcha"]')) {
    return true;
  }
  if (document.querySelector('script[src*="hcaptcha.com/1/api.js"], iframe[src*="hcaptcha.com"]')) {
    return true;
  }
  return false;
}

// ---- Favicon URL ----------------------------------------------------------

function findFaviconUrl(): string | null {
  // Prefer explicitly declared icon links. We accept any rel that includes
  // "icon" — shortcut icon, apple-touch-icon, mask-icon, fluid-icon, etc.
  // First match wins because pages typically list the canonical first.
  const link = document.querySelector<HTMLLinkElement>(
    'link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]'
  );
  if (link && link.href) return link.href;
  // No explicit declaration -> browser falls back to /favicon.ico on origin,
  // which is same-origin and therefore uninteresting for the brand-mismatch
  // detector. Return null instead of synthesising the same-origin path.
  return null;
}

// ---- Top-level extractor --------------------------------------------------

// Hard upper bound on how long extractFeatures() is allowed to spend
// before degrading to URL-only. Defends against pathological pages
// (millions of nodes) and against attacker DoM-bombs designed to stall
// the cascade — the browser would jank, the user blames the extension.
// 250 ms is generous: extraction normally finishes in 5-20 ms.
const EXTRACT_BUDGET_MS = 250;

// Hard cap on how many DOM nodes we walk in any one selector pass. Pages
// with > 200k nodes are extremely rare but exist (Google Sheets large
// spreadsheet, some dev tools UIs); the same cap keeps the worst-case
// per-element work bounded.
const SELECTOR_NODE_CAP = 5000;

export function extractFeatures(): PageFeatures {
  const t0 = performance.now();
  const budgetExceeded = () => performance.now() - t0 > EXTRACT_BUDGET_MS;

  const url = location.href;
  const title = document.title;
  const pageProtocol = location.protocol;

  // Visible text — first ~2 KB after whitespace collapse. The body.innerText
  // call triggers layout, so we keep it once.
  const rawText = document.body?.innerText ?? "";
  const visibleTextSample = rawText
    .slice(0, 2000)
    .replace(/\s+/g, " ")
    .trim();
  const bodyTextLength = rawText.replace(/\s+/g, " ").trim().length;

  // -- Forms ---------------------------------------------------------------
  const forms = Array.from(document.querySelectorAll<HTMLFormElement>("form"));
  const formActions = new Set<string>();
  let hasPasswordField = false;
  let hasOtpField = false;
  let hasCreditCardField = false;
  let seedPhraseGridPattern = false;
  let hasTwNationalIdField = false;

  // Survey all inputs at once, then attribute per-form.
  for (const f of forms.slice(0, SELECTOR_NODE_CAP)) {
    if (budgetExceeded()) break;
    if (f.action) formActions.add(f.action);
    if (formMatchesSeedPhraseGrid(f)) seedPhraseGridPattern = true;
  }
  const allInputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
  for (const inp of allInputs.slice(0, SELECTOR_NODE_CAP)) {
    if (budgetExceeded()) break;
    if (inp.type === "password") hasPasswordField = true;
    if (inputMatchesOtp(inp)) hasOtpField = true;
    if (inputMatchesCreditCard(inp)) hasCreditCardField = true;
    if (inputMatchesTwNationalId(inp)) hasTwNationalIdField = true;
  }

  // -- Iframes -------------------------------------------------------------
  let hiddenIframeCount = 0;
  const allIframes = Array.from(document.querySelectorAll<HTMLIFrameElement>("iframe"));
  for (const f of allIframes.slice(0, SELECTOR_NODE_CAP)) {
    if (budgetExceeded()) break;
    if (isHidden(f)) hiddenIframeCount++;
  }

  // -- Tiny / off-screen interactive elements ------------------------------
  // Bounding: walk a, button, [onclick]; cheaper than scanning every node.
  let tinyElementCount = 0;
  const interactive = Array.from(
    document.querySelectorAll<HTMLElement>("a[href], button, form, [onclick]")
  );
  // Cap the scan to avoid pathological pages (e.g. 50k-link directories).
  // 500 is the historical cap; we also honour the global time budget so a
  // crafted page can't combine "lots of cheap interactives" with "expensive
  // computed-style queries on each" to blow past the budget.
  for (const el of interactive.slice(0, 500)) {
    if (budgetExceeded()) break;
    if (isTinyOffscreenInteractive(el)) tinyElementCount++;
  }

  // -- External scripts ----------------------------------------------------
  const externalScriptUrls: string[] = [];
  const scripts = Array.from(document.querySelectorAll<HTMLScriptElement>("script[src]"));
  for (const s of scripts.slice(0, SELECTOR_NODE_CAP)) {
    if (budgetExceeded()) break;
    const src = s.src;
    if (!src) continue;
    // Skip same-origin scripts entirely — irrelevant for cross-host provenance.
    try {
      const u = new URL(src, location.href);
      if (u.hostname && u.hostname !== location.hostname) {
        externalScriptUrls.push(u.href);
      }
    } catch {
      // ignore parse errors
    }
  }

  // -- Anti-debug / right-click block patterns -----------------------------
  // We can only see what's in the parsed HTML from the ISOLATED world; the
  // page's MAIN-world JS overrides are invisible to us. So we look for the
  // inline attribute + script-text patterns common in cheap phishing kits.
  const hasAntiDebug = detectAntiDebug();

  // -- Cloaking-widget markers + favicon URL -------------------------------
  const hasTurnstileWidget = detectTurnstileWidget();
  const hasHCaptchaWidget = detectHCaptchaWidget();
  const faviconUrl = findFaviconUrl();

  return {
    url,
    title,
    pageProtocol,
    visibleTextSample,
    bodyTextLength,
    hasPasswordField,
    hasOtpField,
    hasCreditCardField,
    seedPhraseGridPattern,
    formActions: Array.from(formActions),
    externalScriptUrls,
    hiddenIframeCount,
    tinyElementCount,
    hasAntiDebug,
    hasTurnstileWidget,
    hasHCaptchaWidget,
    faviconUrl,
    hasTwNationalIdField,
    etld1: ""
  };
}
