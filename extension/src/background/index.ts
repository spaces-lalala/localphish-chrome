// Service Worker entry — routes messages, owns the rule-layer cascade and
// the per-tab verdict cache. Per plan §3.5 the SW does NOT hold any model;
// Stage 3 is delegated to the Offscreen Document over a tagged RPC channel.

import type {
  ClassifyResult,
  LLMBackend,
  OffscreenRequest,
  OffscreenResponse,
  RpcRequest,
  RpcResponse,
  Stage3Input
} from "@/types";
import { runCascade } from "@/signals/cascade";

const OFFSCREEN_DOCUMENT_PATH = "src/offscreen/offscreen.html";

const tabVerdicts = new Map<number, ClassifyResult>();
let cachedBackendStatus: { backend: LLMBackend; ready: boolean; reason?: string } | null = null;

async function hasOffscreenDocument(): Promise<boolean> {
  if (typeof chrome.runtime.getContexts === "function") {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ["OFFSCREEN_DOCUMENT" as chrome.runtime.ContextType]
    });
    return contexts.length > 0;
  }
  return false;
}

async function ensureOffscreenDocument(): Promise<void> {
  if (await hasOffscreenDocument()) return;
  await chrome.offscreen.createDocument({
    url: OFFSCREEN_DOCUMENT_PATH,
    reasons: ["WORKERS" as chrome.offscreen.Reason],
    justification: "Host on-device LLM and vision models for phishing classification."
  });
}

async function sendToOffscreen<T extends OffscreenResponse>(msg: OffscreenRequest): Promise<T> {
  await ensureOffscreenDocument();
  return (await chrome.runtime.sendMessage(msg)) as T;
}

async function probeOffscreenBackend(): Promise<{ backend: LLMBackend; ready: boolean; reason?: string }> {
  if (cachedBackendStatus) return cachedBackendStatus;
  try {
    const r = await sendToOffscreen<Extract<OffscreenResponse, { type: "offscreenProbe" }>>({
      target: "offscreen",
      type: "probe"
    });
    cachedBackendStatus = { backend: r.backend, ready: r.ready, reason: r.reason };
  } catch (err) {
    cachedBackendStatus = {
      backend: "rules-only",
      ready: false,
      reason: `offscreen probe failed: ${(err as Error).message}`
    };
  }
  return cachedBackendStatus;
}

async function callStage3(
  input: Stage3Input
): Promise<{ result: Stage3Output | null; backend: LLMBackend; latencyMs: number; error?: string }> {
  // Don't bother spinning up offscreen if we already know LLM is unavailable.
  const status = await probeOffscreenBackend();
  if (!status.ready) {
    return { result: null, backend: status.backend, latencyMs: 0, error: status.reason };
  }
  try {
    const r = await sendToOffscreen<Extract<OffscreenResponse, { type: "offscreenStage3Result" }>>({
      target: "offscreen",
      type: "stage3Classify",
      input
    });
    return { result: r.result, backend: r.backend, latencyMs: r.latencyMs, error: r.error };
  } catch (err) {
    return {
      result: null,
      backend: "rules-only",
      latencyMs: 0,
      error: `Stage 3 RPC failed: ${(err as Error).message}`
    };
  }
}

// Local re-import to avoid circular type emission concerns.
type Stage3Output = import("@/types").Stage3Output;

chrome.runtime.onInstalled.addListener(() => {
  console.log("[LocalPhish] Service worker installed.");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabVerdicts.delete(tabId);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url !== undefined) {
    tabVerdicts.delete(tabId);
  }
});

// SPA route changes (React/Vue/Notion/Gmail/Twitter) don't fire popstate, so
// content scripts can't see them on their own. The webNavigation API does
// expose pushState/replaceState as onHistoryStateUpdated. When that fires we
// invalidate the cached verdict and ask the content script to re-extract
// features + re-classify against the new URL.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  // frameId 0 = main frame; ignore iframes (they shouldn't drive the page verdict).
  if (details.frameId !== 0) return;
  tabVerdicts.delete(details.tabId);
  void chrome.tabs
    .sendMessage(details.tabId, { type: "spaReClassify", url: details.url })
    .catch(() => {
      // Tab may be on a chrome:// page or unloaded; content script absent — ignore.
    });
});

chrome.runtime.onMessage.addListener((msg: unknown, sender, sendResponse) => {
  // Ignore messages routed to other contexts (esp. the Offscreen Document).
  if (typeof msg === "object" && msg !== null && (msg as { target?: string }).target === "offscreen") {
    return false;
  }
  const req = msg as RpcRequest;

  void (async () => {
    try {
      switch (req.type) {
        case "ping": {
          const s = await probeOffscreenBackend();
          (sendResponse as (r: RpcResponse) => void)({ type: "pong", backend: s.backend });
          return;
        }
        case "getBackendStatus": {
          const s = await probeOffscreenBackend();
          (sendResponse as (r: RpcResponse) => void)({
            type: "backendStatus",
            backend: s.backend,
            ready: s.ready,
            reason: s.reason
          });
          return;
        }
        case "classifyPage": {
          const result = await runCascade(req.features, { stage3: callStage3 });
          const tabId = sender.tab?.id ?? req.tabId ?? -1;
          if (tabId >= 0) {
            tabVerdicts.set(tabId, result);
          }
          (sendResponse as (r: RpcResponse) => void)({ type: "classifyResult", result });
          return;
        }
        case "getTabVerdict": {
          const cached = tabVerdicts.get(req.tabId) ?? null;
          (sendResponse as (r: RpcResponse) => void)({ type: "tabVerdict", result: cached });
          return;
        }
        case "rebuildBrandDb":
          (sendResponse as (r: RpcResponse) => void)({ type: "error", message: "rebuildBrandDb not yet implemented" });
          return;
        default:
          (sendResponse as (r: RpcResponse) => void)({ type: "error", message: "unknown rpc type" });
      }
    } catch (err) {
      (sendResponse as (r: RpcResponse) => void)({ type: "error", message: (err as Error).message });
    }
  })();

  return true;
});

export { ensureOffscreenDocument };
