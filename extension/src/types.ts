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

  // Form actions — raw URLs (string), SW resolves eTLD+1 with tldts.
  formActions: string[];

  // External script <src> URLs — raw URLs, SW resolves eTLD+1.
  externalScriptUrls: string[];

  // Visual obfuscation counts
  /** iframes that are display:none, visibility:hidden, or have w/h ≤ 2px. */
  hiddenIframeCount: number;
  /** Non-iframe elements rendered at ≤1×1 px, off-screen, or 0 opacity, that
   *  still carry interactive content (link, button, form). */
  tinyElementCount: number;

  // For backwards compatibility with popup-initiated URL-only classifies.
  // Empty string from synthetic features; content script fills it for telemetry.
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

// ---- RPC envelopes ---------------------------------------------------------

export type RpcRequest =
  | { type: "ping" }
  | { type: "classifyPage"; tabId?: number; features: PageFeatures }
  | { type: "getTabVerdict"; tabId: number }
  | { type: "getBackendStatus" }
  | { type: "rebuildBrandDb" };

export type RpcResponse =
  | { type: "pong"; backend: LLMBackend }
  | { type: "classifyResult"; result: ClassifyResult }
  | { type: "tabVerdict"; result: ClassifyResult | null }
  | { type: "backendStatus"; backend: LLMBackend; ready: boolean }
  | { type: "error"; message: string };

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
    etld1: ""
  };
}
