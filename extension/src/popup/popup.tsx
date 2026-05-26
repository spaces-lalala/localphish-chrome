import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { ClassifyResult, PageFeatures, RpcRequest, RpcResponse, Verdict } from "@/types";

const verdictLabel: Record<Verdict, string> = {
  safe: "SAFE",
  caution: "CAUTION",
  suspicious: "SUSPICIOUS",
  dangerous: "DANGEROUS"
};

async function classifyActiveTab(): Promise<ClassifyResult> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) throw new Error("no active tab URL");

  // Popup-initiated classify carries only the URL; richer DOM features arrive
  // via the content script on page-load. Stage 1 needs only the URL anyway.
  const features: PageFeatures = {
    url: tab.url,
    etld1: "",
    title: tab.title ?? "",
    visibleTextSample: "",
    hasPasswordField: false,
    hasOtpField: false,
    crossOriginFormAction: false
  };

  const req: RpcRequest = { type: "classifyPage", tabId: tab.id ?? -1, features };
  const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
  if (res.type === "error") throw new Error(res.message);
  if (res.type !== "classifyResult") throw new Error(`unexpected rpc reply: ${res.type}`);
  return res.result;
}

function App() {
  const [result, setResult] = useState<ClassifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setResult(await classifyActiveTab());
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
      {result.reasons.length === 0 ? (
        <p style={{ fontSize: 12, opacity: 0.7 }}>No risk signals detected.</p>
      ) : (
        <ul class="reasons">
          {result.reasons.map((r) => (
            <li>{r}</li>
          ))}
        </ul>
      )}
      <button class="deep" disabled>
        Deep visual check (Stage 4b) — coming soon
      </button>
      <div class="backend">
        Active backend: <strong>{result.backend}</strong> · {result.latencyMs.toFixed(1)} ms
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
