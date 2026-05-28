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

// ---- Top-level extractor --------------------------------------------------

export function extractFeatures(): PageFeatures {
  const url = location.href;
  const title = document.title;
  const pageProtocol = location.protocol;

  // Visible text — first ~2 KB after whitespace collapse. The body.innerText
  // call triggers layout, so we keep it once.
  const visibleTextSample = (document.body?.innerText ?? "")
    .slice(0, 2000)
    .replace(/\s+/g, " ")
    .trim();

  // -- Forms ---------------------------------------------------------------
  const forms = Array.from(document.querySelectorAll<HTMLFormElement>("form"));
  const formActions = new Set<string>();
  let hasPasswordField = false;
  let hasOtpField = false;
  let hasCreditCardField = false;
  let seedPhraseGridPattern = false;

  // Survey all inputs at once, then attribute per-form.
  for (const f of forms) {
    if (f.action) formActions.add(f.action);
    if (formMatchesSeedPhraseGrid(f)) seedPhraseGridPattern = true;
  }
  for (const inp of Array.from(document.querySelectorAll<HTMLInputElement>("input"))) {
    if (inp.type === "password") hasPasswordField = true;
    if (inputMatchesOtp(inp)) hasOtpField = true;
    if (inputMatchesCreditCard(inp)) hasCreditCardField = true;
  }

  // -- Iframes -------------------------------------------------------------
  let hiddenIframeCount = 0;
  for (const f of Array.from(document.querySelectorAll<HTMLIFrameElement>("iframe"))) {
    if (isHidden(f)) hiddenIframeCount++;
  }

  // -- Tiny / off-screen interactive elements ------------------------------
  // Bounding: walk a, button, [onclick]; cheaper than scanning every node.
  let tinyElementCount = 0;
  const interactive = Array.from(
    document.querySelectorAll<HTMLElement>("a[href], button, form, [onclick]")
  );
  // Cap the scan to avoid pathological pages (e.g. 50k-link directories).
  for (const el of interactive.slice(0, 500)) {
    if (isTinyOffscreenInteractive(el)) tinyElementCount++;
  }

  // -- External scripts ----------------------------------------------------
  const externalScriptUrls: string[] = [];
  for (const s of Array.from(document.querySelectorAll<HTMLScriptElement>("script[src]"))) {
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

  return {
    url,
    title,
    pageProtocol,
    visibleTextSample,
    hasPasswordField,
    hasOtpField,
    hasCreditCardField,
    seedPhraseGridPattern,
    formActions: Array.from(formActions),
    externalScriptUrls,
    hiddenIframeCount,
    tinyElementCount,
    hasAntiDebug,
    etld1: ""
  };
}
