// Stage 2 — DOM-feature scoring.
// Runs in the SW on a PageFeatures payload from the content script. Pure
// function over the snapshot; no DOM access here.

import { getDomain } from "tldts";

import type { PageFeatures, Signal, StageId, Verdict } from "@/types";
import { crossStraitLanguageSignals } from "./cross-strait-language";

const W_PASSWORD_INSECURE = 25;        // password field served over http://
const W_PASSWORD_CROSS_ETLD1 = 35;     // password posts to a different eTLD+1
const W_OTP_CROSS_ETLD1 = 25;          // OTP posts to a different eTLD+1
const W_CARD_CROSS_ETLD1 = 30;         // credit card posts to a different eTLD+1
const W_CARD_AND_PASSWORD = 12;        // bonus when both are collected together
const W_SEED_PHRASE_PATTERN = 45;      // 12-word seed-phrase grid — wallet drainer
const W_HIDDEN_IFRAME = 6;             // per iframe, capped
const W_HIDDEN_IFRAME_CAP = 20;
const W_TINY_ELEMENT = 4;              // per element, capped
const W_TINY_ELEMENT_CAP = 16;
const W_MANY_FOREIGN_SCRIPTS = 8;      // >5 distinct foreign eTLD+1s in scripts

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
      weight: W_PASSWORD_INSECURE,
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
  const hasCrossEtld1FormAction =
    pageEtld1 != null &&
    formActionEtld1s.some((d) => d != null && d !== pageEtld1);

  const offendingActionEtld1 = pageEtld1
    ? formActionEtld1s.find((d) => d != null && d !== pageEtld1) ?? null
    : null;

  // ---- Sensitive fields posted cross-eTLD+1 ------------------------------
  if (hasCrossEtld1FormAction) {
    if (features.hasPasswordField) {
      signals.push({
        id: "dom.password_cross_etld1_post",
        stage: "stage2",
        weight: W_PASSWORD_CROSS_ETLD1,
        detail: `password field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
    if (features.hasOtpField) {
      signals.push({
        id: "dom.otp_cross_etld1_post",
        stage: "stage2",
        weight: W_OTP_CROSS_ETLD1,
        detail: `OTP field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
    if (features.hasCreditCardField) {
      signals.push({
        id: "dom.card_cross_etld1_post",
        stage: "stage2",
        weight: W_CARD_CROSS_ETLD1,
        detail: `credit-card field on ${pageEtld1} but form posts to ${offendingActionEtld1}`
      });
    }
  }

  // ---- Bonus: card + password together — full credential harvest combo ----
  if (features.hasCreditCardField && features.hasPasswordField) {
    signals.push({
      id: "dom.card_and_password",
      stage: "stage2",
      weight: W_CARD_AND_PASSWORD,
      detail: "page collects password and credit card in the same flow"
    });
  }

  // ---- Seed-phrase grid (wallet drainer) ---------------------------------
  if (features.seedPhraseGridPattern) {
    signals.push({
      id: "dom.seed_phrase_grid",
      stage: "stage2",
      weight: W_SEED_PHRASE_PATTERN,
      detail: "form asks for a 12-/24-word seed phrase — wallet drainer pattern"
    });
  }

  // ---- Hidden iframes ----------------------------------------------------
  if (features.hiddenIframeCount > 0) {
    const w = Math.min(W_HIDDEN_IFRAME_CAP, W_HIDDEN_IFRAME * features.hiddenIframeCount);
    signals.push({
      id: "dom.hidden_iframes",
      stage: "stage2",
      weight: w,
      detail: `${features.hiddenIframeCount} hidden iframe(s)`
    });
  }

  // ---- Tiny / off-screen interactive overlays ----------------------------
  if (features.tinyElementCount > 0) {
    const w = Math.min(W_TINY_ELEMENT_CAP, W_TINY_ELEMENT * features.tinyElementCount);
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
        weight: W_MANY_FOREIGN_SCRIPTS,
        detail: `loads scripts from ${foreignEtld1s.size} distinct foreign eTLD+1s`
      });
    }
  }

  // ---- Cross-strait (繁/簡 中文) terminology anomaly ----------------------
  // Pages that claim to be a Taiwan institution but sprinkle mainland Chinese
  // terms ("短信、激活、信息、賬號") are a fingerprint of phishing kits
  // localized for Taiwan but produced upstream. Gated on TW-institution claim
  // or .tw hostname to avoid false-positives on legitimate mainland sites.
  signals.push(...crossStraitLanguageSignals(features, pageEtld1));

  const rawScore = signals.reduce((s, sig) => s + sig.weight, 0);
  return {
    rawScore,
    signals,
    stagesRan: ["stage2"],
    latencyMs: performance.now() - t0
  };
}

// ---- Verdict helper (used by cascade) -------------------------------------

export function verdictFromScore(score: number): { verdict: Verdict; shortCircuit: boolean } {
  if (score >= 85) return { verdict: "dangerous", shortCircuit: true };
  if (score < 15) return { verdict: "safe", shortCircuit: false };
  if (score >= 50) return { verdict: "suspicious", shortCircuit: false };
  return { verdict: "caution", shortCircuit: false };
}
