import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import {
  emptyFeatures,
  type ClassifyResult,
  type RpcRequest,
  type RpcResponse,
  type Signal,
  type Verdict
} from "@/types";

const verdictLabel: Record<Verdict, string> = {
  safe: "SAFE",
  caution: "CAUTION",
  suspicious: "SUSPICIOUS",
  dangerous: "DANGEROUS"
};

// Cache poll: the content script kicks off classify when the page loads but
// the cascade can run 3-25 s before the SW caches a verdict. Poll the cache
// so the popup eventually shows the real result (including Stage 3 LLM
// signals) instead of dropping straight to URL-only fallback.
const POLL_INTERVAL_MS = 400;
const MAX_POLL_MS = 28_000; // tracks the Nano timeout (25 s) + small headroom

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function getVerdictForActiveTab(
  onProgress?: (elapsedMs: number) => void,
  abortRef?: { aborted: boolean }
): Promise<ClassifyResult> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) throw new Error("no active tab URL");

  if (tab.id != null && tab.id >= 0) {
    const start = Date.now();
    const deadline = start + MAX_POLL_MS;
    while (Date.now() < deadline) {
      if (abortRef?.aborted) throw new Error("aborted");
      const req: RpcRequest = { type: "getTabVerdict", tabId: tab.id };
      const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
      if (res.type === "tabVerdict" && res.result) {
        return res.result;
      }
      onProgress?.(Date.now() - start);
      await sleep(POLL_INTERVAL_MS);
    }
  }

  // Fallback: classify the URL directly. Content script may not have run on
  // chrome:// / about: / extension URLs, or the SW may have just restarted.
  const features = emptyFeatures(tab.url, tab.title ?? "");
  const req: RpcRequest = { type: "classifyPage", tabId: tab.id ?? -1, features };
  const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
  if (res.type === "error") throw new Error(res.message);
  if (res.type !== "classifyResult") throw new Error(`unexpected: ${res.type}`);
  return res.result;
}

function groupByStage(signals: Signal[]): Record<string, Signal[]> {
  const out: Record<string, Signal[]> = {};
  for (const s of signals) {
    (out[s.stage] ??= []).push(s);
  }
  return out;
}

function App() {
  const [result, setResult] = useState<ClassifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState<number>(0);

  useEffect(() => {
    const abortRef = { aborted: false };
    void (async () => {
      try {
        const r = await getVerdictForActiveTab((ms) => setElapsed(ms), abortRef);
        if (!abortRef.aborted) setResult(r);
      } catch (e) {
        if (!abortRef.aborted) setError((e as Error).message);
      }
    })();
    return () => {
      abortRef.aborted = true;
    };
  }, []);

  if (error) {
    return (
      <div>
        <h1>LocalPhish</h1>
        <p style={{ color: "#991b1b" }}>Error: {error}</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div>
        <h1>
          LocalPhish
          <span class="badge" style={{ background: "#e5e7eb", color: "#374151" }}>
            ANALYZING
          </span>
        </h1>
        <div class="loading-row">
          <span class="loading-spinner" aria-hidden="true"></span>
          <span>Running cascade…</span>
          {elapsed >= 1500 && (
            <span style={{ marginLeft: "auto", fontSize: 11, opacity: 0.6 }}>
              {(elapsed / 1000).toFixed(1)}s
            </span>
          )}
        </div>
        <p class="loading-note">
          Stage&nbsp;3 (on-device LLM) can take 5–25&nbsp;s on heavy pages. Keep this popup
          open or reopen later.
        </p>
      </div>
    );
  }

  const byStage = groupByStage(result.signals);
  const stageLabels: Record<string, string> = {
    stage1: "URL rules",
    stage2: "DOM features",
    stage3: "LLM reasoning",
    stage4a: "Logo retrieval",
    stage4b: "Visual reasoning"
  };

  return (
    <div>
      <h1>
        LocalPhish
        <span class={`badge badge-${result.verdict}`}>{verdictLabel[result.verdict]}</span>
      </h1>
      <div class="score-row">
        <span>Risk score</span>
        <span class="score">{result.riskScore}</span>
      </div>

      {result.signals.length === 0 ? (
        <p style={{ fontSize: 12, opacity: 0.7 }}>No risk signals detected.</p>
      ) : (
        Object.entries(byStage).map(([stage, sigs]) => (
          <div style={{ marginTop: 6 }}>
            <div style={{ fontSize: 11, opacity: 0.7, fontWeight: 600, textTransform: "uppercase" }}>
              {stageLabels[stage] ?? stage}
            </div>
            <ul class="reasons">
              {sigs.map((s) => (
                <li>
                  {s.detail ?? s.id}
                  {s.weight > 0 && (
                    <span style={{ color: "#dc2626", fontWeight: 600 }}> +{s.weight}</span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))
      )}

      <button class="deep" disabled>
        Deep visual check (Stage 4b) — coming soon
      </button>
      <div class="backend">
        Stages: <strong>{result.stagesRan.join(" → ")}</strong> ·{" "}
        backend <strong>{result.backend}</strong> · {result.latencyMs.toFixed(1)} ms
        <br />
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            void chrome.runtime.openOptionsPage();
          }}
        >
          Open URL Tester →
        </a>
      </div>
    </div>
  );
}

render(<App />, document.getElementById("root")!);
