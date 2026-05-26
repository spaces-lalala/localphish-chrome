import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { ClassifyResult, RpcRequest, RpcResponse, Verdict } from "@/types";

const verdictLabel: Record<Verdict, string> = {
  safe: "SAFE",
  caution: "CAUTION",
  suspicious: "SUSPICIOUS",
  dangerous: "DANGEROUS"
};

function App() {
  const [result, setResult] = useState<ClassifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const ping: RpcRequest = { type: "ping" };
        const res = (await chrome.runtime.sendMessage(ping)) as RpcResponse;
        if (res.type === "pong") {
          setResult({
            verdict: "safe",
            riskScore: 0,
            signals: [],
            reasons: ["Scaffold OK — classifier not yet wired up."],
            backend: res.backend,
            latencyMs: 0
          });
        } else if (res.type === "error") {
          setError(res.message);
        }
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
      <ul class="reasons">
        {result.reasons.map((r) => (
          <li>{r}</li>
        ))}
      </ul>
      <button class="deep" disabled>
        Deep visual check (Stage 4b) — coming soon
      </button>
      <div class="backend">
        Active backend: <strong>{result.backend}</strong>
      </div>
    </div>
  );
}

render(<App />, document.getElementById("root")!);
