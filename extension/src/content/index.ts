// Content script — runs in ISOLATED world per plan §3.5.
// Owns Stage 2 DOM extraction and (future) Badge UI.
// MUST NOT load any model; classification is delegated to the SW + Offscreen.

import type { RpcRequest, RpcResponse } from "@/types";
import { extractFeatures } from "./dom-extract";
import { renderBadge, renderProgressBadge, removeBadge } from "./badge";

// Show the "Analyzing…" pill if classify is still in flight after this many ms.
// Tuned so rules-only short-circuits (allow-list hits, <5 ms) never flash a
// loading state, but Stage 3 LLM (3-25 s) always reveals progress before
// the user thinks the extension is dead and hits F5.
const PROGRESS_DELAY_MS = 800;

async function classify(): Promise<void> {
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
  }
}

// Initial run on page idle (this script's run_at is document_idle).
void classify();

// SPA route changes — for sites that swap routes via History API, the SW also
// has webNavigation.onHistoryStateUpdated to back this up.
window.addEventListener("popstate", () => void classify());
