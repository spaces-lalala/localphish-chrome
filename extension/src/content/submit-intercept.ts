// Content script — password / sensitive-field submit-time interceptor.
//
// Addresses §10 條 14 (kill-chain timing): cascade runs at DOMContentLoaded,
// but on a slow Stage 3 LLM the user can finish typing + click submit before
// the verdict comes back. A 20 s offline-LLM cascade that warns AFTER the
// credential is exfiltrated has lost the kill chain.
//
// This module hooks every form containing a password / OTP / national-ID
// field and, on submit, consults the current cached verdict:
//   - SAFE / CAUTION         : let it through (don't be annoying)
//   - SUSPICIOUS             : show a confirm() dialog before submitting
//   - DANGEROUS              : block + show confirm() with strong wording
//
// Form action interception only — we cannot reach `fetch()` calls a SPA
// makes from a button click handler (different world), so for SPA login
// flows this is best-effort. But for the bread-and-butter `<form method=post>`
// pattern that 80%+ of phishing kits use, this is the missing kill-chain hook.

import type { ClassifyResult } from "@/types";

// Snapshot of the most recent verdict for this page; updated by index.ts
// every time classify() resolves. Module-level singleton so the submit
// handler can read it synchronously inside the (cancelable) submit event.
let latestVerdict: ClassifyResult | null = null;

export function setLatestVerdict(v: ClassifyResult | null): void {
  latestVerdict = v;
}

function formHasSensitiveField(form: HTMLFormElement): boolean {
  for (const inp of Array.from(form.querySelectorAll<HTMLInputElement>("input"))) {
    if (inp.type === "password") return true;
    const ac = (inp.autocomplete || "").toLowerCase();
    if (ac.includes("one-time-code") || ac.includes("cc-number")) return true;
    const name = (inp.name || "").toLowerCase();
    if (/^(otp|2fa|tfa|verifycode)/.test(name)) return true;
    const placeholder = inp.placeholder || "";
    if (placeholder.includes("身分證") || placeholder.includes("身份證") ||
        placeholder.includes("統一編號") || placeholder.includes("信用卡")) return true;
  }
  return false;
}

function isRulesAnchored(v: ClassifyResult): boolean {
  let pts = 0;
  for (const s of v.signals) {
    if (s.stage === "stage1" || s.stage === "stage2") pts += s.weight || 0;
  }
  return pts >= 75;
}

function shouldBlock(v: ClassifyResult): "block" | "confirm" | null {
  // Only block when verdict is rule-anchored dangerous. LLM-alone dangerous
  // (Qwen 0.5B on benign rendered DOM) is too noisy to block on; the user
  // would learn to instantly click-through every prompt and the intercept
  // becomes worse than useless. Tier F empirical: 52% benign FPR if we trust
  // LLM alone.
  if (v.verdict === "dangerous" && isRulesAnchored(v)) return "block";
  if (v.verdict === "dangerous") return "confirm";
  if (v.verdict === "suspicious") return "confirm";
  return null;
}

function attachToForm(form: HTMLFormElement): void {
  if ((form as HTMLFormElement & { __lpAttached?: boolean }).__lpAttached) return;
  (form as HTMLFormElement & { __lpAttached?: boolean }).__lpAttached = true;
  if (!formHasSensitiveField(form)) return;

  form.addEventListener(
    "submit",
    (ev) => {
      if (!latestVerdict) return; // cascade hasn't finished yet — let it through
      const action = shouldBlock(latestVerdict);
      if (!action) return;
      // confirm() runs synchronously in the page event loop, blocking the
      // submit. Use native confirm so we don't have to inject our own modal
      // and risk being z-index-warred by the host page.
      const score = latestVerdict.riskScore;
      const msg = action === "block"
        ? `⚠️ LocalPhish 偵測到強烈釣魚跡象 (分數 ${score})。\n\n` +
          `規則層發現此頁面結構符合釣魚模板。仍要送出嗎？\n\n` +
          `（按「取消」可保護你的帳密 / 個資不外流。）`
        : `LocalPhish 對此頁面感到可疑 (分數 ${score})。\n\n` +
          `仍要送出表單嗎？\n\n` +
          `（如果你本來就信任這個網站，可在 LocalPhish Options 加入個人 allowlist。）`;
      const proceed = window.confirm(msg);
      if (!proceed) {
        ev.preventDefault();
        ev.stopPropagation();
      }
    },
    true // capture phase: fire before the page's own listeners
  );
}

let observer: MutationObserver | null = null;

export function installSubmitInterceptor(): void {
  if (observer) return;
  // Cover existing forms.
  for (const f of Array.from(document.querySelectorAll<HTMLFormElement>("form"))) {
    attachToForm(f);
  }
  // Cover forms added later (SPA hydration).
  observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const n of Array.from(m.addedNodes)) {
        if (!(n instanceof Element)) continue;
        if (n.tagName === "FORM") {
          attachToForm(n as HTMLFormElement);
        } else {
          for (const f of Array.from(n.querySelectorAll<HTMLFormElement>("form"))) {
            attachToForm(f);
          }
        }
      }
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
}
