// Stage 2 — Cloaking / verify-wall detector.
//
// Threat model. Modern phishing kits (since ~2024 Cloudflare Turnstile became
// free, and the various hCaptcha + custom JS challenge variants) gate the
// real phishing content behind a "Verify you are human" wall. The bot view
// — what scrapers, including PhreshPhish's archival crawler, capture — is
// almost empty: a CAPTCHA widget, maybe a logo, no form. Only after the
// challenge passes does the kit fetch the real credential-harvest payload
// from another endpoint and inject it.
//
// Static HTML samples thus systematically *under-represent* phishing
// signals — Tier A rules-only recall=0% @ threshold 50 partly reflects this.
//
// Detection heuristic: a page that shows a CAPTCHA widget AND has near-zero
// body content AND no real form is most likely a cloaking gate, not the
// payload itself. We don't say "this is phishing" definitively — there are
// legit Cloudflare-protected pages — but we do flag the structural pattern
// so the cascade's LLM stage (which sees this signal) can apply heavier
// scepticism, and so analysts looking at Tier A misses can identify
// cloaked samples.

import type { PageFeatures, Signal } from "@/types";
import { weight as W } from "./weights";

/** Used in the v2 Nano prompt's signals[] to tell the LLM about the gate. */
const VERIFY_WALL_TEXT_THRESHOLD = 300;  // chars of body text below which we consider it "thin"

export function cloakingSignals(features: PageFeatures): Signal[] {
  const out: Signal[] = [];

  const verifyPresent = features.hasTurnstileWidget || features.hasHCaptchaWidget;
  if (!verifyPresent) return out;

  const widget = features.hasTurnstileWidget
    ? "Cloudflare Turnstile"
    : "hCaptcha";

  // Use bodyTextLength (full body) where available; fall back to the 2 KB
  // sample length so we still fire on samples extracted before this field
  // was populated.
  const bodyLen = features.bodyTextLength ?? features.visibleTextSample.length;

  if (bodyLen >= VERIFY_WALL_TEXT_THRESHOLD) {
    // A challenge widget *can* legitimately appear on a page with substantial
    // content (Cloudflare-protected article pages, comment forms). Don't
    // flag those — the cloaking pattern is specifically "widget + empty body".
    return out;
  }

  // Zero forms is the smoking gun. A real login page has at least one form
  // (or, if React-rendered, would still show password inputs in the static
  // snapshot). An empty body + challenge widget + zero forms = nothing here
  // to verify against. Either it's a cloaking gate or a 403 challenge —
  // either way, no real content for downstream stages to reason about.
  // (Earlier versions also gated on `!hasPasswordField`, but the form-count
  // check alone already captures the no-real-content invariant: a stray
  // password input outside a form is rare and shouldn't downgrade us from
  // STRONG to WEAK.)
  const formCount = features.formActions.length;
  if (formCount === 0) {
    out.push({
      id: "dom.cloaking_verify_wall_strong",
      stage: "stage2",
      weight: W("dom.cloaking_verify_wall_strong"),
      detail: `${widget} widget present + body text ${bodyLen} chars + no form — likely cloaking gate hiding the actual payload`
    });
  } else {
    out.push({
      id: "dom.cloaking_verify_wall",
      stage: "stage2",
      weight: W("dom.cloaking_verify_wall"),
      detail: `${widget} widget present with thin body (${bodyLen} chars) — possible verify-wall gate`
    });
  }

  return out;
}
