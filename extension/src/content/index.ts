// Content script — runs in ISOLATED world per plan §3.5.
// Owns Stage 2 DOM extraction and (future) Badge UI.
// MUST NOT load any model; classification is delegated to the SW + Offscreen.

import type { RpcRequest, RpcResponse } from "@/types";
import { extractFeatures } from "./dom-extract";

async function classify(): Promise<void> {
  const features = extractFeatures();
  const req: RpcRequest = { type: "classifyPage", features };
  try {
    const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
    if (res.type === "classifyResult") {
      console.log(
        "[LocalPhish]",
        res.result.verdict.toUpperCase(),
        "score=" + res.result.riskScore,
        "stages=" + res.result.stagesRan.join("+"),
        res.result.signals.map((s) => `${s.id}+${s.weight}`)
      );
    } else if (res.type === "error") {
      console.warn("[LocalPhish] classify error:", res.message);
    }
  } catch (err) {
    // Service worker may be evicted between calls; sendMessage rejects.
    // Don't crash the host page — the user can retry via the popup.
    console.warn("[LocalPhish] sendMessage failed:", (err as Error).message);
  }
}

// Initial run on page idle (this script's run_at is document_idle).
void classify();

// SPA route changes — for sites that swap routes via History API, the SW also
// has webNavigation.onHistoryStateUpdated to back this up.
window.addEventListener("popstate", () => void classify());
