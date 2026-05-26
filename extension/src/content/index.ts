// Content script — runs in ISOLATED world per plan §3.5.
// Owns Stage 2 DOM extraction and Badge UI (Shadow DOM).
// MUST NOT load any model; all classification is delegated via SW → Offscreen RPC.

import type { PageFeatures, RpcRequest, RpcResponse } from "@/types";

function extractFeatures(): PageFeatures {
  const url = location.href;
  // eTLD+1 will be computed properly in signals/url-features.ts using PSL.
  // For scaffold we use a naive split — replace with `psl` lookup later.
  const host = location.hostname;
  const parts = host.split(".");
  const etld1 = parts.length >= 2 ? parts.slice(-2).join(".") : host;

  const hasPasswordField = document.querySelector('input[type="password"]') != null;
  const hasOtpField =
    document.querySelector('input[autocomplete*="one-time-code"]') != null ||
    document.querySelector('input[name*="otp" i]') != null;

  const forms = Array.from(document.querySelectorAll("form"));
  const crossOriginFormAction = forms.some((f) => {
    const action = (f as HTMLFormElement).action;
    if (!action) return false;
    try {
      return new URL(action, location.href).hostname !== location.hostname;
    } catch {
      return false;
    }
  });

  const visibleTextSample =
    (document.body?.innerText ?? "").slice(0, 2000).replace(/\s+/g, " ").trim();

  return {
    url,
    etld1,
    title: document.title,
    visibleTextSample,
    hasPasswordField,
    hasOtpField,
    crossOriginFormAction
  };
}

async function classify(): Promise<void> {
  const features = extractFeatures();
  const req: RpcRequest = { type: "classifyPage", tabId: -1, features };
  const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
  if (res.type === "classifyResult") {
    console.log("[LocalPhish] verdict:", res.result.verdict, "score:", res.result.riskScore);
  }
}

// Initial run on page idle (this script's run_at is document_idle).
void classify();

// SPA route changes — relies on history events; webNavigation listener in SW will
// supplement this for cases where pushState is not dispatched via History API events.
window.addEventListener("popstate", () => void classify());
