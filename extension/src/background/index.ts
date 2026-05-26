// Service Worker entry — routes messages, owns Stage 1 rules and verdict cache.
// Per plan §3.5, the SW does NOT hold any model; that lives in the Offscreen Document.

import type { ClassifyResult, RpcRequest, RpcResponse } from "@/types";
import { runStage1 } from "@/signals/stage1";

const OFFSCREEN_DOCUMENT_PATH = "src/offscreen/offscreen.html";

async function hasOffscreenDocument(): Promise<boolean> {
  // chrome.offscreen.hasDocument() exists in Chrome 116+, but availability varies.
  // Fall back to enumerating contexts (Chrome 124+).
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

function classifyUrl(url: string): ClassifyResult {
  const r = runStage1(url);
  return {
    verdict: r.verdict,
    riskScore: r.rawScore,
    signals: r.signals,
    reasons: r.signals.map((s) => s.detail ?? s.id),
    backend: "rules-only",
    latencyMs: r.latencyMs
  };
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("[LocalPhish] Service worker installed.");
});

chrome.runtime.onMessage.addListener(
  (msg: RpcRequest, _sender, sendResponse: (r: RpcResponse) => void) => {
    void (async () => {
      try {
        switch (msg.type) {
          case "ping":
            // Note: do NOT create the offscreen document here. We only spin it
            // up when an LLM/vision backend is actually requested.
            sendResponse({ type: "pong", backend: "rules-only" });
            return;
          case "getBackendStatus":
            sendResponse({ type: "backendStatus", backend: "rules-only", ready: true });
            return;
          case "classifyPage": {
            const result = classifyUrl(msg.features.url);
            sendResponse({ type: "classifyResult", result });
            return;
          }
          case "rebuildBrandDb":
            sendResponse({ type: "error", message: "rebuildBrandDb not yet implemented" });
            return;
          default:
            sendResponse({ type: "error", message: "unknown rpc type" });
        }
      } catch (err) {
        sendResponse({ type: "error", message: (err as Error).message });
      }
    })();
    return true; // keep the message channel open for async sendResponse
  }
);

// Kept for forward-compat: when LLM backends arrive, the first classifyPage
// that needs them will call ensureOffscreenDocument().
export { ensureOffscreenDocument };
