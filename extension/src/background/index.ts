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
import { installBloomRefresh } from "./bloom-refresh";
import { InferenceQueue } from "./inference-queue";
import { installPreNavInterstitial } from "./pre-nav-interstitial";
import { getDomain } from "tldts";
import {
  addMisjudgment,
  addUserAllowlist,
  listMisjudgments,
  loadProfile,
  loadTabVerdicts,
  loadUserAllowlist,
  persistTabVerdicts,
  removeMisjudgment,
  removeUserAllowlist,
  saveProfile,
  userAllowlistHas,
  watchUserAllowlist
} from "./user-storage";

const OFFSCREEN_DOCUMENT_PATH = "src/offscreen/offscreen.html";

let tabVerdicts = new Map<number, ClassifyResult>();
let cachedBackendStatus: { backend: LLMBackend; ready: boolean; reason?: string } | null = null;

// Restore session state ASAP. SW may have just woken up and the map is empty;
// chrome.storage.session survives short evictions inside one browser session.
void (async () => {
  tabVerdicts = await loadTabVerdicts();
  await loadUserAllowlist();
  watchUserAllowlist();
})();

// Install the on-device 165 反詐騙 bloom-filter daily refresh + restore the
// cached runtime blob from chrome.storage.local. No per-page network call;
// once per ~24 h, single batched download of a static blob. See
// background/bloom-refresh.ts for the privacy invariant.
installBloomRefresh();

// Pre-nav interstitial — for URLs that Stage 1 alone scores ≥ DANGER_FLOOR
// (typosquat / reverse-proxy / bloom hit etc.), redirect the tab to a
// warning page BEFORE the hostile DOM paints. See pre-nav-interstitial.ts
// for the kill-chain-timing rationale (review §10 條 14).
installPreNavInterstitial();

function persistVerdictsSoon(): void {
  // Debounce: storage.session writes are cheap but still serial. Batch them.
  if (persistTimer != null) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    void persistTabVerdicts(tabVerdicts);
  }, 200);
}
let persistTimer: ReturnType<typeof setTimeout> | null = null;

// ---- Toolbar icon three-state ---------------------------------------------
//
// "SAFE doesn't render anything" was confusing — users assumed the extension
// was broken when nothing appeared. We now mirror verdict state on the
// toolbar icon via setBadgeText + setBadgeBackgroundColor so the user can
// always tell at a glance whether the extension is alive.
//
// Mapping (Week 16 v3, addressing review §10 條 26):
//   safe       → "✓" green       ← low-key "protected" tick, ALWAYS visible
//   caution    → "!"  amber
//   suspicious → "!"  orange
//   dangerous  → "!!" red
//   analyzing  → "…"  blue       (cascade in flight)
//   error      → "?"  grey       (LLM unreachable etc.)
function setActionBadge(tabId: number, state: "safe" | "caution" | "suspicious" | "dangerous" | "analyzing" | "error"): void {
  const SPEC: Record<typeof state, { text: string; color: string }> = {
    safe:       { text: "✓",   color: "#16a34a" },
    caution:    { text: "!",   color: "#f59e0b" },
    suspicious: { text: "!",   color: "#f97316" },
    dangerous:  { text: "!!",  color: "#dc2626" },
    analyzing:  { text: "…",   color: "#2563eb" },
    error:      { text: "?",   color: "#71717a" }
  };
  const s = SPEC[state];
  try {
    void chrome.action.setBadgeText({ tabId, text: s.text });
    if (s.text) {
      void chrome.action.setBadgeBackgroundColor({ tabId, color: s.color });
    }
    // Badge text color — Chrome 110+ supports setBadgeTextColor; ignore on
    // older Chrome (the default text color is still readable on these
    // backgrounds).
    if (typeof chrome.action.setBadgeTextColor === "function") {
      void chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
    }
  } catch {
    // chrome.action APIs throw if tabId is gone (race with onRemoved). Safe to ignore.
  }
}

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

async function rawCallStage3(
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

// All Stage 3 invocations go through this queue so the active foreground tab
// always wins over background-tab inference. See inference-queue.ts for the
// full rationale (review §10 條 18: serialized-engine bottleneck on iGPU).
const inferenceQueue = new InferenceQueue(rawCallStage3);

/** SW-internal helper bound to a specific tab — wraps rawCallStage3 with
 *  the queue so cascade.ts can stay tab-unaware. */
function callStage3ForTab(tabId: number) {
  return async (input: Stage3Input) => {
    const r = await inferenceQueue.enqueue(tabId, input);
    return {
      result: r.result,
      backend: r.backend,
      latencyMs: r.latencyMs,
      error: r.cancelled ? "cancelled (tab navigated away)" : r.error,
    };
  };
}

// Track which tab is currently active so the queue can prioritize it.
chrome.tabs.onActivated.addListener((info) => {
  inferenceQueue.setActiveTab(info.tabId);
});

// Local re-import to avoid circular type emission concerns.
type Stage3Output = import("@/types").Stage3Output;

chrome.runtime.onInstalled.addListener(() => {
  console.log("[LocalPhish] Service worker installed.");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabVerdicts.delete(tabId);
  persistVerdictsSoon();
  inferenceQueue.cancelTab(tabId);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url !== undefined) {
    tabVerdicts.delete(tabId);
    persistVerdictsSoon();
    // Wipe the icon badge so a stale verdict from the previous URL doesn't
    // linger after navigation.
    setActionBadge(tabId, "safe");
    // Drop any in-flight Stage 3 work for this tab — the previous page's
    // verdict is no longer wanted on the new URL.
    inferenceQueue.cancelTab(tabId);
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
          // User allowlist short-circuit. Lives in the SW (not Stage 1) so
          // that hot-reload and Options edits take effect without rebuilding
          // any singletons inside the cascade module.
          const url = req.features.url;
          let etld1: string | null = null;
          try {
            etld1 = getDomain(new URL(url).hostname) ?? null;
          } catch {
            etld1 = null;
          }
          const tabIdEarly = sender.tab?.id ?? req.tabId ?? -1;
          // Flip toolbar icon to "analyzing" as soon as cascade starts so
          // the user has feedback during the 3-25 s Stage 3 LLM call. Skip
          // for user-allowlist hits since those resolve synchronously.
          let result: ClassifyResult;
          if (etld1 && userAllowlistHas(etld1)) {
            result = {
              verdict: "safe",
              riskScore: 0,
              signals: [{
                id: "url.user_allowlist_hit",
                stage: "stage1",
                weight: 0,
                detail: `eTLD+1 "${etld1}" is on your personal allow-list`
              }],
              reasons: [`eTLD+1 "${etld1}" is on your personal allow-list`],
              backend: "rules-only",
              latencyMs: 0,
              stagesRan: ["stage1"]
            };
          } else {
            if (tabIdEarly >= 0) setActionBadge(tabIdEarly, "analyzing");
            const stage3 = tabIdEarly >= 0 ? callStage3ForTab(tabIdEarly) : rawCallStage3;
            result = await runCascade(req.features, { stage3 });
          }
          if (tabIdEarly >= 0) {
            tabVerdicts.set(tabIdEarly, result);
            persistVerdictsSoon();
            setActionBadge(tabIdEarly, result.verdict);
          }
          (sendResponse as (r: RpcResponse) => void)({ type: "classifyResult", result });
          return;
        }
        case "getTabVerdict": {
          const cached = tabVerdicts.get(req.tabId) ?? null;
          (sendResponse as (r: RpcResponse) => void)({ type: "tabVerdict", result: cached });
          return;
        }
        case "getUserAllowlist": {
          const set = await loadUserAllowlist();
          (sendResponse as (r: RpcResponse) => void)({ type: "userAllowlist", entries: Array.from(set).sort() });
          return;
        }
        case "addUserAllowlist": {
          await addUserAllowlist(req.etld1);
          (sendResponse as (r: RpcResponse) => void)({ type: "ok" });
          return;
        }
        case "removeUserAllowlist": {
          await removeUserAllowlist(req.etld1);
          (sendResponse as (r: RpcResponse) => void)({ type: "ok" });
          return;
        }
        case "reportMisjudgment": {
          await addMisjudgment({
            url: req.url,
            verdict: req.verdict,
            expectedVerdict: req.expectedVerdict,
            riskScore: req.riskScore,
            reasons: req.reasons,
            ts: Date.now()
          });
          (sendResponse as (r: RpcResponse) => void)({ type: "ok" });
          return;
        }
        case "listMisjudgments": {
          const entries = await listMisjudgments();
          (sendResponse as (r: RpcResponse) => void)({ type: "misjudgmentList", entries });
          return;
        }
        case "removeMisjudgment": {
          await removeMisjudgment(req.ts, req.url);
          (sendResponse as (r: RpcResponse) => void)({ type: "ok" });
          return;
        }
        case "getProfile": {
          const profile = await loadProfile();
          (sendResponse as (r: RpcResponse) => void)({ type: "profile", profile });
          return;
        }
        case "setProfile": {
          await saveProfile(req.profile);
          // Push the new profile into the offscreen document so the LLM router
          // tears down the old backend and probes the new one. This is the
          // moment the user pays a 1.2 GB Qwen download if they picked Pro.
          cachedBackendStatus = null;
          const r = await sendToOffscreen<Extract<OffscreenResponse, { type: "offscreenSetProfile" }>>({
            target: "offscreen",
            type: "setProfile",
            profile: req.profile
          });
          cachedBackendStatus = { backend: r.backend, ready: r.ready, reason: r.reason };
          (sendResponse as (r2: RpcResponse) => void)({ type: "ok" });
          return;
        }
        case "getWebllmProgress": {
          try {
            const r = await sendToOffscreen<Extract<OffscreenResponse, { type: "offscreenProgress" }>>({
              target: "offscreen",
              type: "getProgress"
            });
            (sendResponse as (r2: RpcResponse) => void)({
              type: "webllmProgress",
              progress: r.progress,
              text: r.text,
              backend: r.backend,
              ready: r.ready
            });
          } catch (e) {
            (sendResponse as (r2: RpcResponse) => void)({
              type: "error",
              message: `webllm progress: ${(e as Error).message}`
            });
          }
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
