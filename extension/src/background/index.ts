// Service Worker entry — routes messages, owns Stage 1 rules and verdict cache.
// Per plan §3.5, the SW does NOT hold any model; that lives in the Offscreen Document.

import type { RpcRequest, RpcResponse } from "@/types";

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

chrome.runtime.onInstalled.addListener(() => {
  console.log("[LocalPhish] Service worker installed.");
});

chrome.runtime.onMessage.addListener(
  (msg: RpcRequest, _sender, sendResponse: (r: RpcResponse) => void) => {
    void (async () => {
      try {
        switch (msg.type) {
          case "ping":
            await ensureOffscreenDocument();
            sendResponse({ type: "pong", backend: "rules-only" });
            return;
          case "getBackendStatus":
            sendResponse({ type: "backendStatus", backend: "rules-only", ready: true });
            return;
          case "classifyPage":
            // Stage 1 rules will live here; for scaffold we echo a placeholder.
            sendResponse({
              type: "classifyResult",
              result: {
                verdict: "safe",
                riskScore: 0,
                signals: [],
                reasons: ["scaffold: classifier not yet implemented"],
                backend: "rules-only",
                latencyMs: 0
              }
            });
            return;
          default:
            sendResponse({ type: "error", message: `unknown rpc type` });
        }
      } catch (err) {
        sendResponse({ type: "error", message: (err as Error).message });
      }
    })();
    return true; // keep the message channel open for async sendResponse
  }
);
