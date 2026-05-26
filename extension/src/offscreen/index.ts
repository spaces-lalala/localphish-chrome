// Offscreen Document — persistent host for the LLM router and (later) the
// vision pipeline. Plan §3.5: this is where WebGPU contexts and model engines
// live so the Service Worker can be evicted without losing model state.

import type { OffscreenRequest, OffscreenResponse } from "@/types";
import { LLMRouter } from "@/llm/router";

const router = new LLMRouter("auto");

// Lazy init — wait for the first probe / classify to pay the model-load cost.
let initPromise: Promise<void> | null = null;
function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      const s = await router.init();
      console.log(`[LocalPhish offscreen] router state: ${s.backend} ready=${s.ready} ${s.reason ?? ""}`);
    })();
  }
  return initPromise;
}

chrome.runtime.onMessage.addListener(
  (msg: unknown, _sender, sendResponse: (r: OffscreenResponse) => void) => {
    // Filter messages addressed at this context only.
    if (typeof msg !== "object" || msg === null) return false;
    const m = msg as Partial<OffscreenRequest>;
    if (m.target !== "offscreen") return false;

    void (async () => {
      await ensureInit();
      try {
        switch (m.type) {
          case "probe": {
            const s = router.getState();
            sendResponse({
              type: "offscreenProbe",
              backend: s.backend,
              ready: s.ready,
              reason: s.reason
            });
            return;
          }
          case "stage3Classify": {
            const r = await router.stage3Classify(m.input!);
            sendResponse({
              type: "offscreenStage3Result",
              result: r.result,
              backend: r.backend,
              latencyMs: r.latencyMs,
              error: r.error
            });
            return;
          }
          default:
            sendResponse({
              type: "offscreenStage3Result",
              result: null,
              backend: "rules-only",
              latencyMs: 0,
              error: `offscreen: unknown type "${String(m.type)}"`
            });
        }
      } catch (err) {
        sendResponse({
          type: "offscreenStage3Result",
          result: null,
          backend: "rules-only",
          latencyMs: 0,
          error: (err as Error).message
        });
      }
    })();
    return true;
  }
);

console.log("[LocalPhish] Offscreen document loaded.");
