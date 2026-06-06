// Offscreen Document — persistent host for the LLM router and (later) the
// vision pipeline. Plan §3.5: this is where WebGPU contexts and model engines
// live so the Service Worker can be evicted without losing model state.

import type { OffscreenRequest, OffscreenResponse } from "@/types";
import { LLMRouter, type Profile } from "@/llm/router";

// Profile is read from chrome.storage.local on first init. The SW pushes
// "setProfile" when the user flips the Options selector, which causes us to
// destroy the old backend (releasing WebGPU memory) and probe the new one.
let router = new LLMRouter("lite");
let currentProfile: Profile = "lite";

async function loadProfileFromStorage(): Promise<Profile> {
  try {
    const v = await chrome.storage.local.get("llm_profile");
    const p = v.llm_profile;
    if (p === "auto" || p === "pro" || p === "lite") return p;
  } catch {
    // ignore — fall back to default
  }
  return "lite";
}

let initPromise: Promise<void> | null = null;
function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      currentProfile = await loadProfileFromStorage();
      router = new LLMRouter(currentProfile);
      const s = await router.init();
      console.log(`[LocalPhish offscreen] profile=${currentProfile} router state: ${s.backend} ready=${s.ready} ${s.reason ?? ""}`);
    })();
  }
  return initPromise;
}

async function applyProfile(p: Profile): Promise<void> {
  currentProfile = p;
  // Release the old WebLLM engine's WebGPU buffers + worker before allocating
  // the new one. Without this, a Pro → Lite → Pro flip leaves the previous
  // Qwen engine pinned in IndexedDB / WebGPU and can OOM on the second load.
  // LLMRouter's WebLLM-internal cleanup lives in WebLLMBackend.destroy().
  await router.destroy?.().catch(() => { /* best-effort */ });
  router = new LLMRouter(p);
  const s = await router.init();
  console.log(`[LocalPhish offscreen] re-init profile=${p}: ${s.backend} ready=${s.ready} ${s.reason ?? ""}`);
}

chrome.runtime.onMessage.addListener(
  (msg: unknown, _sender, sendResponse: (r: OffscreenResponse) => void) => {
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
          case "setProfile": {
            if (m.profile === currentProfile) {
              // No-op — but still return current state for caller's UI.
              const s = router.getState();
              sendResponse({
                type: "offscreenSetProfile",
                backend: s.backend,
                ready: s.ready,
                reason: s.reason
              });
              return;
            }
            await applyProfile(m.profile!);
            const s = router.getState();
            sendResponse({
              type: "offscreenSetProfile",
              backend: s.backend,
              ready: s.ready,
              reason: s.reason
            });
            return;
          }
          case "getProgress": {
            const s = router.getState();
            const prog = router.getDownloadProgress();
            sendResponse({
              type: "offscreenProgress",
              progress: prog?.progress ?? (s.ready ? 1 : 0),
              text: prog?.text ?? (s.ready ? "ready" : s.reason ?? "not ready"),
              backend: s.backend,
              ready: s.ready
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
