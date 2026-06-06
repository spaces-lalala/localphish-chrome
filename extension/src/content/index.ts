// Content script — runs in ISOLATED world per plan §3.5.
// Owns Stage 2 DOM extraction and (future) Badge UI.
// MUST NOT load any model; classification is delegated to the SW + Offscreen.

import type { RpcRequest, RpcResponse } from "@/types";
import { extractFeatures } from "./dom-extract";
import { renderBadge, renderProgressBadge, removeBadge } from "./badge";
import { installSubmitInterceptor, setLatestVerdict } from "./submit-intercept";

// Show the "Analyzing…" pill if classify is still in flight after this many ms.
// Tuned so rules-only short-circuits (allow-list hits, <5 ms) never flash a
// loading state, but Stage 3 LLM (3-25 s) always reveals progress before
// the user thinks the extension is dead and hits F5.
const PROGRESS_DELAY_MS = 800;

// SPA route-change debounce window. Apps like Gmail/Notion/FB fire pushState
// dozens of times in a session — debounce the run so a flurry of routes
// becomes one cascade run, not one per route. 350 ms is large enough to
// coalesce typical SPA router transitions and short enough that the user
// can't have interacted with the new view before we look at it.
const ROUTE_CHANGE_DEBOUNCE_MS = 350;

// Per-page result cache. Caches the LAST verdict by URL so consecutive
// route changes that land back on a URL we already classified become a no-op
// (badge re-shown, no DOM extract, no SW round-trip). Bounded to avoid
// growing forever in a long Gmail session; LRU-ish.
const MAX_CACHE = 32;
const cache = new Map<string, RpcResponse>();

let routeTimer: number | null = null;
let inFlight = false;

function cacheGet(url: string): RpcResponse | null {
  const v = cache.get(url);
  if (v == null) return null;
  // Promote LRU position.
  cache.delete(url);
  cache.set(url, v);
  return v;
}

function cacheSet(url: string, v: RpcResponse): void {
  if (cache.has(url)) cache.delete(url);
  cache.set(url, v);
  while (cache.size > MAX_CACHE) {
    const first = cache.keys().next().value;
    if (first === undefined) break;
    cache.delete(first);
  }
}

async function classify(): Promise<void> {
  // Coalesce overlapping classify calls — a burst of pushState during page
  // boot must not fan out to N concurrent SW messages.
  if (inFlight) return;
  inFlight = true;

  const url = location.href;
  // Same-URL cache hit: no DOM extract, no SW message. Repeated SPA route
  // changes that land back on a previously-classified URL hit this path.
  const hit = cacheGet(url);
  if (hit && hit.type === "classifyResult") {
    renderBadge(hit.result);
    setLatestVerdict(hit.result);
    inFlight = false;
    return;
  }

  const features = extractFeatures();
  const req: RpcRequest = { type: "classifyPage", features };

  const progressTimer = window.setTimeout(renderProgressBadge, PROGRESS_DELAY_MS);

  try {
    const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
    window.clearTimeout(progressTimer);
    if (res.type === "classifyResult") {
      console.log(
        "[LocalPhish]",
        res.result.verdict.toUpperCase(),
        "score=" + res.result.riskScore,
        "stages=" + res.result.stagesRan.join("+"),
        res.result.signals.map((s) => `${s.id}+${s.weight}`)
      );
      renderBadge(res.result);
      setLatestVerdict(res.result);
      cacheSet(url, res);
    } else if (res.type === "error") {
      console.warn("[LocalPhish] classify error:", res.message);
      removeBadge();
    }
  } catch (err) {
    window.clearTimeout(progressTimer);
    // Service worker may be evicted between calls; sendMessage rejects.
    // Don't crash the host page — the user can retry via the popup.
    console.warn("[LocalPhish] sendMessage failed:", (err as Error).message);
    removeBadge();
  } finally {
    inFlight = false;
  }
}

function scheduleClassify(): void {
  if (routeTimer != null) window.clearTimeout(routeTimer);
  routeTimer = window.setTimeout(() => {
    routeTimer = null;
    void classify();
  }, ROUTE_CHANGE_DEBOUNCE_MS);
}

// Install the submit-time interceptor as early as possible — we want to
// have form listeners attached before the user can interact, even if the
// cascade hasn't finished yet. With no cached verdict the interceptor
// is a no-op, but if the user is fast and the LLM is slow, we still cover
// the post-cascade window.
installSubmitInterceptor();

// Initial run on page idle (this script's run_at is document_idle). No
// debounce — first load should classify ASAP.
void classify();

// SPA route changes. Two paths cover the cases:
//   - popstate fires on browser back/forward (works without extra wiring).
//   - pushState / replaceState does NOT fire popstate, so the SW listens to
//     chrome.webNavigation.onHistoryStateUpdated and pushes a "spaReClassify"
//     message into this tab, which we handle here.
// Both paths now route through the debounce so a Gmail-style burst becomes
// one cascade run.
window.addEventListener("popstate", () => scheduleClassify());

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (typeof msg !== "object" || msg === null) return false;
  if ((msg as { type?: string }).type !== "spaReClassify") return false;
  scheduleClassify();
  sendResponse({ type: "ok" });
  return false;
});
