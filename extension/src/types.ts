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

export interface PageFeatures {
  url: string;
  etld1: string;
  title: string;
  visibleTextSample: string;
  hasPasswordField: boolean;
  hasOtpField: boolean;
  crossOriginFormAction: boolean;
  faviconHash?: string;
}

export interface ClassifyResult {
  verdict: Verdict;
  riskScore: number;
  signals: Signal[];
  reasons: string[];
  backend: LLMBackend;
  latencyMs: number;
}

// RPC message envelopes between SW, content script, popup, and offscreen.
export type RpcRequest =
  | { type: "ping" }
  | { type: "classifyPage"; tabId: number; features: PageFeatures }
  | { type: "getBackendStatus" }
  | { type: "rebuildBrandDb" };

export type RpcResponse =
  | { type: "pong"; backend: LLMBackend }
  | { type: "classifyResult"; result: ClassifyResult }
  | { type: "backendStatus"; backend: LLMBackend; ready: boolean }
  | { type: "error"; message: string };
