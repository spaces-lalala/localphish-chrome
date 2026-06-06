// Stage 2 — DOM-feature scoring.
// Runs in the SW on a PageFeatures payload from the content script. Pure
// function over the snapshot; no DOM access here.

import { getDomain } from "tldts";

import type { PageFeatures, Signal, StageId, Verdict } from "@/types";
import { crossStraitLanguageSignals } from "./cross-strait-language";
import { cloakingSignals } from "./cloaking";
import { faviconMismatchSignals } from "./favicon-mismatch";
import { unicodeTrickeryTextSignals } from "./unicode-trickery";
import { getBrandIndex } from "./stage1";

import idpAllowlistRaw from "@/data/known-idp-allowlist.json";
import { weight as W, cap as CAP } from "./weights";

// Pre-compiled known-IDP set used to suppress cross-eTLD+1 form-action signals
// when the action actually points at a legitimate OAuth / SSO target.
const IDP_ALLOWLIST: ReadonlySet<string> = new Set(
  (idpAllowlistRaw as { etld1s: string[] }).etld1s.map((s) => s.toLowerCase())
);

export interface Stage2Result {
  rawScore: number;
  signals: Signal[];
  stagesRan: StageId[];
  latencyMs: number;
}

/**
 * @param pageEtld1 eTLD+1 of the page itself, as already computed by Stage 1.
 *                  Passed in so we don't reparse the URL.
 */
export function runStage2(features: PageFeatures, pageEtld1: string | null): Stage2Result {
  const t0 = performance.now();
  const signals: Signal[] = [];

  // ---- Insecure password collection (no TLS) ------------------------------
  if (features.hasPasswordField && features.pageProtocol === "http:") {
    signals.push({
      id: "dom.password_no_tls",
      stage: "stage2",
      weight: W("dom.password_no_tls"),
      detail: "page collects a password over plain http:// — TLS missing"
    });
  }

  // ---- Resolve form-action eTLD+1s ----------------------------------------
  const formActionEtld1s: (string | null)[] = features.formActions.map((a) => {
    try {
      const abs = new URL(a, features.url).hostname;
      return getDomain(abs) ?? null;
    } catch {
      return null;
    }
  });
  // A cross-eTLD+1 form action that lands on a known IDP (accounts.google.com,
  // login.microsoftonline.com, appleid.apple.com, …) is the OAuth / SSO happy
  // path, not credential harvest. Filter those out before deciding whether
  // the page is actually posting credentials off-site.
  const suspiciousCrossActions = formActionEtld1s.filter(
    (d) => d != null && d !== pageEtld1 && !IDP_ALLOWLIST.has(d)
  );
  const allCrossActionsAreIdp =
    pageEtld1 != null &&
    formActionEtld1s.some((d) => d != null && d !== pageEtld1) &&
    suspiciousCrossActions.length === 0;

  const hasCrossEtld1FormAction =
    pageEtld1 != null && suspiciousCrossActions.length > 0;

  const offendingActionEtld1 = hasCrossEtld1FormAction
    ? suspiciousCrossActions[0]
    : null;

  if (allCrossActionsAreIdp) {
    signals.push({
      id: "dom.oauth_idp_allowlisted",
      stage: "stage2",
      weight: 0,
      detail: "cross-eTLD+1 form actions all target known OAuth/SSO IDPs — not flagging"
    });
  }

  // ---- Sensitive fields posted cross-eTLD+1 ------------------------------
  if (hasCrossEtld1FormAction) {
    if (features.hasPasswordField) {
      signals.push({
        id: "dom.password_cross_etld1_post",
        stage: "stage2",
        weight: W("dom.password_cross_etld1_post"),
        detail: `password field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
    if (features.hasOtpField) {
      signals.push({
        id: "dom.otp_cross_etld1_post",
        stage: "stage2",
        weight: W("dom.otp_cross_etld1_post"),
        detail: `OTP field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
    if (features.hasCreditCardField) {
      signals.push({
        id: "dom.card_cross_etld1_post",
        stage: "stage2",
        weight: W("dom.card_cross_etld1_post"),
        detail: `credit-card field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
  }

  // ---- Bonus: card + password together — full credential harvest combo ----
  if (features.hasCreditCardField && features.hasPasswordField) {
    signals.push({
      id: "dom.card_and_password",
      stage: "stage2",
      weight: W("dom.card_and_password"),
      detail: "page collects password and credit card in the same flow"
    });
  }

  // ---- Taiwan PII combo (身分證字號 + 卡號 + OTP) on non-trusted page ------
  // Legit Taiwan sites that need to collect 身分證字號 (national ID) live on
  // .gov.tw / .edu.tw or in the Taiwan first-class allowlist — those are
  // already short-circuited by Stage 1. If we see this combo here, the page
  // is by construction not on the trusted list, so the combo is near-certain
  // identity-theft / SIM-swap setup.
  if (features.hasTwNationalIdField) {
    const triadComplete =
      features.hasTwNationalIdField &&
      features.hasCreditCardField &&
      features.hasOtpField;
    if (triadComplete) {
      signals.push({
        id: "dom.tw_pii_combo",
        stage: "stage2",
        weight: W("dom.tw_pii_combo"),
        detail: "page collects 身分證字號 + 卡號 + OTP on a host outside the Taiwan trusted list — identity-theft / SIM-swap pattern"
      });
    }
    // Even just national ID posted off-site is a strong signal.
    if (hasCrossEtld1FormAction) {
      signals.push({
        id: "dom.tw_national_id_cross_etld1_post",
        stage: "stage2",
        weight: W("dom.tw_national_id_cross_etld1_post"),
        detail: `身分證字號 field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
  }

  // ---- Seed-phrase grid (wallet drainer) ---------------------------------
  if (features.seedPhraseGridPattern) {
    signals.push({
      id: "dom.seed_phrase_grid",
      stage: "stage2",
      weight: W("dom.seed_phrase_grid"),
      detail: "form asks for a 12-/24-word seed phrase — wallet drainer pattern"
    });
  }

  // ---- Hidden iframes ----------------------------------------------------
  if (features.hiddenIframeCount > 0) {
    const w = Math.min(CAP("dom.hidden_iframes_cap"), W("dom.hidden_iframes") * features.hiddenIframeCount);
    signals.push({
      id: "dom.hidden_iframes",
      stage: "stage2",
      weight: w,
      detail: `${features.hiddenIframeCount} hidden iframe(s)`
    });
  }

  // ---- Tiny / off-screen interactive overlays ----------------------------
  if (features.tinyElementCount > 0) {
    const w = Math.min(CAP("dom.tiny_interactive_cap"), W("dom.tiny_interactive") * features.tinyElementCount);
    signals.push({
      id: "dom.tiny_interactive",
      stage: "stage2",
      weight: w,
      detail: `${features.tinyElementCount} tiny/off-screen interactive element(s)`
    });
  }

  // ---- Many cross-host external scripts ----------------------------------
  // Heuristic: ad/CDN-heavy legit sites also have lots; gate on >5 distinct
  // foreign eTLD+1s to avoid flagging news sites and SaaS dashboards.
  if (pageEtld1) {
    const foreignEtld1s = new Set<string>();
    for (const src of features.externalScriptUrls) {
      try {
        const host = new URL(src, features.url).hostname;
        const d = getDomain(host);
        if (d && d !== pageEtld1) foreignEtld1s.add(d);
      } catch {
        // skip
      }
    }
    if (foreignEtld1s.size > 5) {
      signals.push({
        id: "dom.many_foreign_scripts",
        stage: "stage2",
        weight: W("dom.many_foreign_scripts"),
        detail: `loads scripts from ${foreignEtld1s.size} distinct foreign eTLD+1s`
      });
    }
  }

  // ---- Anti-debug / right-click block patterns ---------------------------
  // Soft signal: many legitimate sites block right-click for image protection,
  // so we never flag it on its own. The cascade picks it up combined with
  // credential-harvest signals (e.g. password form + right-click blocked +
  // mainland Chinese terms = classic phishing kit fingerprint).
  if (features.hasAntiDebug) {
    signals.push({
      id: "dom.anti_debug",
      stage: "stage2",
      weight: W("dom.anti_debug"),
      detail: "page disables right-click / F12 / DevTools — common phishing-kit anti-inspection"
    });
  }

  // ---- Cross-strait (繁/簡 中文) terminology anomaly ----------------------
  // Pages that claim to be a Taiwan institution but sprinkle mainland Chinese
  // terms ("短信、激活、信息、賬號") are a fingerprint of phishing kits
  // localized for Taiwan but produced upstream. Gated on TW-institution claim
  // or .tw hostname to avoid false-positives on legitimate mainland sites.
  signals.push(...crossStraitLanguageSignals(features, pageEtld1));

  // ---- Cloaking / Turnstile / hCaptcha verify-wall -----------------------
  // 2024+ phishing kits gate the credential-harvest payload behind a
  // challenge widget; the static DOM seen by scrapers is then mostly empty.
  // Flag this structural pattern so Stage 3 LLM can apply heavier scepticism
  // and so Tier A misses caused by cloaking can be attributed.
  signals.push(...cloakingSignals(features));

  // ---- Favicon CDN hot-link mismatch -------------------------------------
  // Phishing kits routinely hot-link the real brand's favicon to keep the
  // tab icon convincing. If the favicon's eTLD+1 belongs to a known brand
  // (or its CDN) but the page eTLD+1 doesn't, that's strong impersonation.
  signals.push(...faviconMismatchSignals(features, pageEtld1, getBrandIndex()));

  // ---- Unicode trickery in title + visible text --------------------------
  // Zero-width / bidi-override / tag-character attacks embedded in copy.
  // Companion to the URL-level checks in Stage 1; text-level weights are
  // lower because Arabic/Hebrew + Latin content legitimately uses some
  // direction marks (we exclude LRM/RLM but keep override/isolate).
  signals.push(...unicodeTrickeryTextSignals(features.title, features.visibleTextSample));

  const rawScore = signals.reduce((s, sig) => s + sig.weight, 0);
  return {
    rawScore,
    signals,
    stagesRan: ["stage2"],
    latencyMs: performance.now() - t0
  };
}

// ---- Verdict helper (used by cascade) -------------------------------------

import { DANGER_FLOOR, SAFE_CEILING, SUSPICIOUS_FLOOR } from "./thresholds";

export function verdictFromScore(score: number): { verdict: Verdict; shortCircuit: boolean } {
  if (score >= DANGER_FLOOR) return { verdict: "dangerous", shortCircuit: true };
  if (score < SAFE_CEILING) return { verdict: "safe", shortCircuit: false };
  if (score >= SUSPICIOUS_FLOOR) return { verdict: "suspicious", shortCircuit: false };
  return { verdict: "caution", shortCircuit: false };
}
