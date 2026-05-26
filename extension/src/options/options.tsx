import { render } from "preact";
import { useState } from "preact/hooks";
import { emptyFeatures, type ClassifyResult, type RpcRequest, type RpcResponse, type Verdict } from "@/types";

interface Preset {
  label: string;
  url: string;
  expected: string;
}

const PRESETS: Preset[] = [
  {
    label: "Allow-list hit",
    url: "https://www.google.com/search?q=phishing",
    expected: "SAFE — eTLD+1 on Tranco starter list"
  },
  {
    label: "Typosquat — paypa1.com",
    url: "https://paypa1.com/login",
    expected: "SUSPICIOUS — Levenshtein 1 from paypal.com"
  },
  {
    label: "Typosquat — microsft.com",
    url: "https://login.microsft.com/account/signin",
    expected: "SUSPICIOUS — Levenshtein 1 from microsoft.com"
  },
  {
    label: "Subdomain brand abuse",
    url: "https://paypal.com.account-verify.example-secure.tk/login",
    expected: "DANGEROUS — paypal in subdomain, .tk TLD, many hyphens"
  },
  {
    label: "Punycode — Cyrillic 'apple'",
    url: "https://xn--pple-43d.com/icloud",
    expected: "DANGEROUS — IDN decodes to lookalike of 'apple'"
  },
  {
    label: "IP-as-host login",
    url: "http://192.168.1.50:8080/wp-admin/login.php",
    expected: "DANGEROUS — IP host + non-standard port"
  },
  {
    label: "@-sign userinfo trick",
    url: "https://www.microsoft.com@evil-update.tk/auth",
    expected: "DANGEROUS — @ before host hides real destination .tk"
  },
  {
    label: "High-risk TLD only",
    url: "https://random-business.zip/about",
    expected: "CAUTION — .zip TLD (recently rolled out, abuse-prone)"
  },
  {
    label: "Many hyphens + brand in path",
    url: "https://my-secure-bank-update-now.com/chase/verify",
    expected: "SUSPICIOUS — hyphens + path mentions chase"
  },
  {
    label: "High-entropy path",
    url: "https://example.click/a3f9c2e1b8d7f6a2c1e9b8a7d6/login",
    expected: "SUSPICIOUS — high-risk TLD + entropy + path"
  },
  {
    label: "Legit GitHub (clean)",
    url: "https://github.com/anthropics/claude-code",
    expected: "SAFE — allow-list hit"
  },
  {
    label: "Legit TW bank (clean)",
    url: "https://www.cathaybk.com.tw/personal/online-banking",
    expected: "SAFE — allow-list hit"
  }
];

function verdictClass(v: Verdict): string {
  return v;
}

async function classify(url: string): Promise<ClassifyResult> {
  const features = emptyFeatures(url);
  const req: RpcRequest = { type: "classifyPage", tabId: -1, features };
  const res = (await chrome.runtime.sendMessage(req)) as RpcResponse;
  if (res.type === "error") throw new Error(res.message);
  if (res.type !== "classifyResult") throw new Error(`unexpected: ${res.type}`);
  return res.result;
}

function App() {
  const [url, setUrl] = useState<string>("https://paypa1.com/login");
  const [result, setResult] = useState<ClassifyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(target: string) {
    setBusy(true);
    setError(null);
    setResult(null);
    setUrl(target);
    try {
      const r = await classify(target);
      setResult(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>LocalPhish — URL Tester</h1>
      <p class="note">
        Paste any URL string below and run Stage 1 against it. The URL is never fetched;
        only its structure is analyzed. Useful for verifying detector behavior without
        navigating to a real phishing site.
      </p>

      <form
        class="tester"
        onSubmit={(e) => {
          e.preventDefault();
          void run(url);
        }}
      >
        <input
          type="text"
          value={url}
          onInput={(e) => setUrl((e.target as HTMLInputElement).value)}
          placeholder="https://example.com/path"
          spellcheck={false}
          autocomplete="off"
        />
        <button type="submit" disabled={busy}>
          {busy ? "Running…" : "Analyze"}
        </button>
      </form>

      {error && <p style={{ color: "#ef4444" }}>Error: {error}</p>}

      {result && (
        <div class={`result ${verdictClass(result.verdict)}`}>
          <div class="result-header">
            <span class="verdict">{result.verdict.toUpperCase()}</span>
            <span class="score">{result.riskScore}</span>
            <span class="meta">{result.latencyMs.toFixed(2)} ms · {result.backend}</span>
          </div>
          {result.signals.length === 0 ? (
            <p style={{ margin: 0, fontSize: 12.5 }}>No risk signals detected.</p>
          ) : (
            <ul class="signals">
              {result.signals.map((s) => (
                <li>
                  <span class="id">{s.id}</span>
                  <span class="weight">+{s.weight}</span>
                  {s.detail && <> — {s.detail}</>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <h2>Presets</h2>
      <p class="note">Click any preset to load it into the analyzer.</p>
      <div class="presets">
        {PRESETS.map((p) => (
          <button class="preset" onClick={() => void run(p.url)}>
            <span class="label">{p.label}</span>
            <span class="url">{p.url}</span>
            <span style={{ fontSize: 11, color: "#6b7280" }}>{p.expected}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

render(<App />, document.getElementById("root")!);
