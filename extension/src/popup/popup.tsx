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

async function getVerdictForActiveTab(): Promise<ClassifyResult> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) throw new Error("no active tab URL");

  if (tab.id != null && tab.id >= 0) {
    const req: RpcRequest = { type: "getTabVerdict", tabId: tab.id };
    const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
    if (res.type === "tabVerdict" && res.result) {
      return res.result;
    }
  }

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

  useEffect(() => {
    void (async () => {
      try {
        setResult(await getVerdictForActiveTab());
      } catch (e) {
        setError((e as Error).message);
      }
    })();
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
        <h1>LocalPhish</h1>
        <p>Analyzing…</p>
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
