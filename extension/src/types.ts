// LocalPhish — shared types across SW / content / offscreen / UI.
// Keep this file free of side effects so every entry point can import safely.

export type Verdict = "safe" | "caution" | "suspicious" | "dangerous";

export type LLMBackend = "webllm" | "nano" | "rules-only";

export type StageId = "stage1" | "stage2" | "stage3" | "stage4a" | "stage4b";

export interface Signal {
  id: string;
  stage: StageId;
  weight: number;
  detail?: string;
}

// Snapshot of the page that the content script ships to the SW for scoring.
// Designed so the SW can run Stage 1 + Stage 2 without ever touching the DOM.
export interface PageFeatures {
  // Page-level
  url: string;
  title: string;
  /** "http:" or "https:" */
  pageProtocol: string;
  /** First ~2 KB of visible body text, whitespace-collapsed. */
  visibleTextSample: string;

  // Form fields (boolean presence)
  hasPasswordField: boolean;
  hasOtpField: boolean;
  hasCreditCardField: boolean;
  /** True when the form containing the password also holds ≥8 short text inputs
   *  (the seed-phrase grid pattern used by crypto-wallet drainers). */
  seedPhraseGridPattern: boolean;
  /** True if any input matches Taiwan national ID (身分證字號 / 統一編號)
   *  patterns. Used by the Taiwan PII combo detector in Stage 2. Optional
   *  for backwards compatibility with older PageFeatures producers. */
  hasTwNationalIdField?: boolean;

  // Form actions — raw URLs (string), SW resolves eTLD+1 with tldts.
  formActions: string[];

  // External script <src> URLs — raw URLs, SW resolves eTLD+1.
  externalScriptUrls: string[];

  // Visual obfuscation counts
  hiddenIframeCount: number;
  tinyElementCount: number;

  /** Inline anti-debug / right-click-block / F12-block patterns detected on
   *  the page. Soft signal — many legitimate sites also disable right-click
   *  for image protection — but combined with credential-harvest signals it
   *  helps separate "real phishing kit" from "legit-but-paranoid site". */
  hasAntiDebug: boolean;

  // ---- Cloaking / verify-wall hints (Stage 2) ----------------------------
  /** Cloudflare Turnstile widget present in the static DOM. */
  hasTurnstileWidget: boolean;
  /** hCaptcha widget present in the static DOM. */
  hasHCaptchaWidget: boolean;
  /** Total body.innerText length (unclamped). Cheap to compute alongside
   *  the 2 KB sample. Used by cloaking detector to spot "challenge widget
   *  + near-empty body" pattern. Optional for backwards compatibility with
   *  older PageFeatures producers. */
  bodyTextLength?: number;

  // ---- Favicon (Stage 2 hot-link mismatch) -------------------------------
  /** Resolved absolute URL of the page's favicon, or null if none declared. */
  faviconUrl?: string | null;

  // For backwards compatibility with popup-initiated URL-only classifies.
  etld1: string;
}

export interface ClassifyResult {
  verdict: Verdict;
  riskScore: number;
  signals: Signal[];
  reasons: string[];
  backend: LLMBackend;
  latencyMs: number;
  stagesRan: StageId[];
}

// ---- Stage 3 — LLM I/O ---------------------------------------------------

export interface Stage3Input {
  url: string;
  etld1: string;
  title: string;
  /** ≤ 1500 chars; further truncation done in the prompt builder. */
  textSample: string;
  /** Rule-layer signals shipped to the LLM as additional grounding. */
  ruleSignals: Array<{ id: string; weight: number; detail?: string }>;
}

export interface Stage3Output {
  riskScore: number;
  verdict: Verdict;
  /** Always an array. Prompt v1 returns one element; prompt v2 (台灣本土化) may
   *  return multiple (e.g. ["brand_impersonation", "fake_government"]). */
  category: string[];
  reasons: string[];
  needVisual: boolean;
}

// ---- Runtime RPC envelopes (SW <-> content / popup / options) -----------

export type RpcRequest =
  | { type: "ping" }
  | { type: "classifyPage"; tabId?: number; features: PageFeatures }
  | { type: "getTabVerdict"; tabId: number }
  | { type: "getBackendStatus" }
  | { type: "rebuildBrandDb" }
  | { type: "getUserAllowlist" }
  | { type: "addUserAllowlist"; etld1: string }
  | { type: "removeUserAllowlist"; etld1: string }
  | { type: "reportMisjudgment"; url: string; verdict: Verdict; expectedVerdict: Verdict; riskScore: number; reasons: string[] }
  | { type: "listMisjudgments" }
  | { type: "removeMisjudgment"; ts: number; url: string }
  | { type: "getProfile" }
  | { type: "setProfile"; profile: "auto" | "pro" | "lite" }
  | { type: "getWebllmProgress" }
  /** SW → content-script push: SPA route changed, re-extract DOM + classify. */
  | { type: "spaReClassify"; url: string };

export type RpcResponse =
  | { type: "pong"; backend: LLMBackend }
  | { type: "classifyResult"; result: ClassifyResult }
  | { type: "tabVerdict"; result: ClassifyResult | null }
  | { type: "backendStatus"; backend: LLMBackend; ready: boolean; reason?: string }
  | { type: "userAllowlist"; entries: string[] }
  | { type: "ok" }
  | { type: "misjudgmentList"; entries: Array<{ url: string; verdict: Verdict; expectedVerdict: Verdict; riskScore: number; reasons: string[]; ts: number }> }
  | { type: "profile"; profile: "auto" | "pro" | "lite" }
  | { type: "webllmProgress"; progress: number; text: string; backend: LLMBackend; ready: boolean }
  | { type: "error"; message: string };

// ---- Offscreen RPC envelopes (SW <-> offscreen document) ----------------
// Carry an explicit `target` tag so listeners that share the same
// chrome.runtime.onMessage channel can ignore messages not meant for them.

export type OffscreenRequest =
  | { target: "offscreen"; type: "probe" }
  | { target: "offscreen"; type: "stage3Classify"; input: Stage3Input }
  | { target: "offscreen"; type: "setProfile"; profile: "auto" | "pro" | "lite" }
  | { target: "offscreen"; type: "getProgress" };

export type OffscreenResponse =
  | { type: "offscreenProbe"; backend: LLMBackend; ready: boolean; reason?: string }
  | {
      type: "offscreenStage3Result";
      result: Stage3Output | null;
      backend: LLMBackend;
      latencyMs: number;
      error?: string;
    }
  | { type: "offscreenSetProfile"; backend: LLMBackend; ready: boolean; reason?: string }
  | { type: "offscreenProgress"; progress: number; text: string; backend: LLMBackend; ready: boolean };

// Empty-feature helper for popup synthesis / URL-only classify entry points.
export function emptyFeatures(url: string, title = ""): PageFeatures {
  return {
    url,
    title,
    pageProtocol: "",
    visibleTextSample: "",
    hasPasswordField: false,
    hasOtpField: false,
    hasCreditCardField: false,
    seedPhraseGridPattern: false,
    formActions: [],
    externalScriptUrls: [],
    hiddenIframeCount: 0,
    tinyElementCount: 0,
    hasAntiDebug: false,
    hasTurnstileWidget: false,
    hasHCaptchaWidget: false,
    bodyTextLength: 0,
    faviconUrl: null,
    hasTwNationalIdField: false,
    etld1: ""
  };
}
