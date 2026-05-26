// Service Worker entry — routes messages, owns the rule-layer cascade and
// the per-tab verdict cache. Per plan §3.5 the SW does NOT hold any model.

import type { ClassifyResult, RpcRequest, RpcResponse } from "@/types";
import { runCascade } from "@/signals/cascade";

const OFFSCREEN_DOCUMENT_PATH = "src/offscreen/offscreen.html";

// In-memory per-tab cache. The SW may be evicted; chrome.storage.session would
// survive that and is plan §3.5's eventual home. For now in-memory is fine —
// the cache is just a UX optimization, not load-bearing.
const tabVerdicts = new Map<number, ClassifyResult>();

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

chrome.runtime.onInstalled.addListener(() => {
  console.log("[LocalPhish] Service worker installed.");
});

// Wipe a tab's cached verdict when it closes or navigates away.
chrome.tabs.onRemoved.addListener((tabId) => {
  tabVerdicts.delete(tabId);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url !== undefined) {
    tabVerdicts.delete(tabId);
  }
});

chrome.runtime.onMessage.addListener(
  (msg: RpcRequest, sender, sendResponse: (r: RpcResponse) => void) => {
    void (async () => {
      try {
        switch (msg.type) {
          case "ping":
            sendResponse({ type: "pong", backend: "rules-only" });
            return;
          case "getBackendStatus":
            sendResponse({ type: "backendStatus", backend: "rules-only", ready: true });
            return;
          case "classifyPage": {
            const result = runCascade(msg.features);
            // Prefer the sender's actual tab id over whatever the caller passed.
            const tabId = sender.tab?.id ?? msg.tabId ?? -1;
            if (tabId >= 0) {
              tabVerdicts.set(tabId, result);
            }
            sendResponse({ type: "classifyResult", result });
            return;
          }
          case "getTabVerdict": {
            const cached = tabVerdicts.get(msg.tabId) ?? null;
            sendResponse({ type: "tabVerdict", result: cached });
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
    return true;
  }
);

export { ensureOffscreenDocument };
