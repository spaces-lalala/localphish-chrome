import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
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
  },
  {
    label: "TW: 偽 gov.tw 子網域",
    url: "https://etax.gov.tw.refund-2026.tax-payment.xyz/login",
    expected: "DANGEROUS — gov.tw substring in hostname but eTLD+1 isn't .gov.tw + high-risk TLD"
  },
  {
    label: "TW: gov-tw 連字變體",
    url: "https://www.gov-tw.com/notice",
    expected: "DANGEROUS — domain label 'gov-tw' mimics .gov.tw"
  },
  {
    label: "TW: 假冒中華郵政 typosquat",
    url: "https://chunghwapost-tw.fake-claim.tk/parcel/customs",
    expected: "SUSPICIOUS+ — subdomain brand abuse + high-risk TLD"
  },
  {
    label: "TW: ETC 催繳 path-brand",
    url: "https://fast-toll-overdue.click/etc/fetc-pay",
    expected: "CAUTION — high-risk TLD + path mentions etc/fetc"
  },
  {
    label: "Evilginx: brand FQDN as subdomain",
    url: "https://login.microsoftonline.com.attacker-fake.tk/oauth2/v2.0/authorize?client_id=x",
    expected: "DANGEROUS — reverse_proxy_fqdn + phishlet_endpoint + high-risk TLD"
  },
  {
    label: "Evilginx: hyphen-flattened FQDN",
    url: "https://login-microsoftonline-com.evil-fake.xyz/login",
    expected: "DANGEROUS — reverse_proxy_hyphen_fqdn"
  },
  {
    label: "Phishlet: /login_data callback",
    url: "https://random-host.zip/login_data?session=abc",
    expected: "SUSPICIOUS+ — phishlet_endpoint + high-risk TLD"
  },
  {
    label: "Unicode: bidi override in path",
    url: "https://example-fake.tk/Invoice%E2%80%AEexe.pdf",
    expected: "SUSPICIOUS+ — bidi_override_in_url"
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

      <ProfileSelector />
      <AllowlistEditor />
      <MisjudgmentLog />
    </div>
  );
}

// ---- LLM Profile selector (auto / pro / lite) --------------------------
// Pro means downloading Qwen 2.5-1.5B q4f16 (~1.2 GB). We let the user opt in
// explicitly so a fresh install doesn't surprise them. WebLLM progress is
// polled while the model loads so the user knows we're not frozen.

type ProfileVal = "auto" | "pro" | "lite";

function ProfileSelector() {
  const [profile, setProfileState] = useState<ProfileVal>("lite");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ progress: number; text: string; backend: string; ready: boolean } | null>(null);

  async function refresh() {
    const res = (await chrome.runtime.sendMessage({ type: "getProfile" } as RpcRequest)) as RpcResponse;
    if (res.type === "profile") setProfileState(res.profile);
    const p = (await chrome.runtime.sendMessage({ type: "getWebllmProgress" } as RpcRequest)) as RpcResponse;
    if (p.type === "webllmProgress") {
      setProgress({ progress: p.progress, text: p.text, backend: p.backend, ready: p.ready });
    }
  }

  useEffect(() => {
    void refresh();
    // Poll while a Pro download is in flight. Stop polling once ready.
    const id = setInterval(() => { void refresh(); }, 1500);
    return () => clearInterval(id);
  }, []);

  async function select(p: ProfileVal) {
    if (busy || p === profile) return;
    setBusy(true);
    await chrome.runtime.sendMessage({ type: "setProfile", profile: p } as RpcRequest);
    await refresh();
    setBusy(false);
  }

  const profileMeta: Record<ProfileVal, { label: string; sub: string }> = {
    auto:  { label: "Auto",  sub: "Nano if available, otherwise rules-only. No background download." },
    lite:  { label: "Lite",  sub: "Chrome built-in Nano only. English-only LLM output. ~0 MB download." },
    pro:   { label: "Pro",   sub: "WebLLM Qwen 2.5-1.5B q4f16 via WebGPU. 繁中 native output. ~1.2 GB first-time download." }
  };

  return (
    <section style={{ marginTop: 32 }}>
      <h2>LLM profile</h2>
      <p class="note">
        Pick which on-device model the cascade's Stage&nbsp;3 should use. Switching
        Pro on triggers a one-time 1.2&nbsp;GB Qwen download — happens in the offscreen
        document, cached in the browser's IndexedDB, never re-downloaded.
      </p>
      <div style={{ display: "grid", gap: 8 }}>
        {(["auto", "lite", "pro"] as ProfileVal[]).map((p) => (
          <label
            style={{
              display: "flex",
              gap: 10,
              padding: 10,
              border: `1px solid ${profile === p ? "#0078d4" : "#d1d5db"}`,
              background: profile === p ? "rgba(0, 120, 212, 0.06)" : "transparent",
              borderRadius: 6,
              cursor: busy ? "wait" : "pointer"
            }}
          >
            <input
              type="radio"
              name="profile"
              checked={profile === p}
              disabled={busy}
              onChange={() => void select(p)}
              style={{ marginTop: 3 }}
            />
            <div>
              <div style={{ fontWeight: 600 }}>{profileMeta[p].label}</div>
              <div style={{ fontSize: 12, opacity: 0.75 }}>{profileMeta[p].sub}</div>
            </div>
          </label>
        ))}
      </div>

      {progress && (
        <div style={{ marginTop: 14, padding: 10, background: "rgba(0, 120, 212, 0.06)", border: "1px solid #93c5fd", borderRadius: 6 }}>
          <div style={{ fontSize: 12, opacity: 0.8 }}>
            backend: <strong>{progress.backend}</strong> · ready: <strong>{String(progress.ready)}</strong>
          </div>
          {progress.progress > 0 && progress.progress < 1 && (
            <>
              <div style={{ marginTop: 6, height: 8, background: "#dbeafe", borderRadius: 4, overflow: "hidden" }}>
                <div style={{ width: `${(progress.progress * 100).toFixed(1)}%`, height: "100%", background: "#0078d4", transition: "width 0.4s" }} />
              </div>
              <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>
                {progress.text} — {(progress.progress * 100).toFixed(1)}%
              </div>
            </>
          )}
          {progress.ready && (
            <div style={{ fontSize: 12, color: "#065f46", marginTop: 4 }}>✓ {progress.text}</div>
          )}
          {!progress.ready && progress.progress === 0 && (
            <div style={{ fontSize: 11, color: "#92400e", marginTop: 4 }}>{progress.text}</div>
          )}
        </div>
      )}
    </section>
  );
}

// ---- Personal allowlist editor ------------------------------------------

function AllowlistEditor() {
  const [entries, setEntries] = useState<string[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const res = (await chrome.runtime.sendMessage({ type: "getUserAllowlist" } as RpcRequest)) as RpcResponse;
    if (res.type === "userAllowlist") setEntries(res.entries);
  }

  useEffect(() => { void refresh(); }, []);

  async function add() {
    setError(null);
    const v = input.trim().toLowerCase();
    // accept either a bare eTLD+1 ("example.com") or a URL — extract host.
    let etld1 = v;
    if (v.includes("/")) {
      try {
        etld1 = new URL(v.startsWith("http") ? v : `https://${v}`).hostname;
      } catch {
        setError("can't parse that URL");
        return;
      }
    }
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(etld1)) {
      setError("must look like a domain (e.g. example.com)");
      return;
    }
    setBusy(true);
    await chrome.runtime.sendMessage({ type: "addUserAllowlist", etld1 } as RpcRequest);
    setInput("");
    await refresh();
    setBusy(false);
  }

  async function remove(etld1: string) {
    await chrome.runtime.sendMessage({ type: "removeUserAllowlist", etld1 } as RpcRequest);
    await refresh();
  }

  return (
    <section style={{ marginTop: 32 }}>
      <h2>Personal allow-list</h2>
      <p class="note">
        eTLD+1s on this list are treated as safe and short-circuit the cascade.
        Use it for internal tools or sites the Tranco starter list doesn't cover.
        Stored locally; never uploaded.
      </p>
      <form
        onSubmit={(e) => { e.preventDefault(); void add(); }}
        style={{ display: "flex", gap: 8, marginBottom: 12 }}
      >
        <input
          type="text"
          value={input}
          onInput={(e) => setInput((e.target as HTMLInputElement).value)}
          placeholder="example.com or https://example.com/path"
          style={{ flex: 1, padding: 8 }}
          spellcheck={false}
          autocomplete="off"
        />
        <button type="submit" disabled={busy}>Add</button>
      </form>
      {error && <p style={{ color: "#ef4444", fontSize: 12.5 }}>{error}</p>}
      {entries.length === 0 ? (
        <p style={{ fontSize: 12.5, opacity: 0.7 }}>(no entries yet)</p>
      ) : (
        <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {entries.map((e) => (
            <li style={{ display: "flex", padding: "4px 0", fontSize: 13 }}>
              <span style={{ flex: 1 }}>{e}</span>
              <button onClick={() => void remove(e)} style={{ background: "transparent", border: 0, color: "#dc2626", cursor: "pointer" }}>
                remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ---- Misjudgment log viewer ---------------------------------------------

function MisjudgmentLog() {
  const [entries, setEntries] = useState<Array<{ url: string; verdict: Verdict; expectedVerdict: Verdict; riskScore: number; reasons: string[]; ts: number }>>([]);

  async function refresh() {
    const res = (await chrome.runtime.sendMessage({ type: "listMisjudgments" } as RpcRequest)) as RpcResponse;
    if (res.type === "misjudgmentList") setEntries(res.entries);
  }

  useEffect(() => { void refresh(); }, []);

  async function remove(ts: number, url: string) {
    await chrome.runtime.sendMessage({ type: "removeMisjudgment", ts, url } as RpcRequest);
    await refresh();
  }

  if (entries.length === 0) return null;

  return (
    <section style={{ marginTop: 32 }}>
      <h2>Reported misjudgments ({entries.length})</h2>
      <p class="note">
        Pages you marked as misclassified via the popup's <em>Report misjudgment</em> button. Local-only — click <em>remove</em> to delete any entry.
      </p>
      <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 12.5 }}>
        {entries.slice(0, 20).map((e) => (
          <li style={{ padding: "8px 0", borderBottom: "1px solid #e5e7eb", display: "flex", gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div><strong>{e.verdict.toUpperCase()} {e.riskScore}</strong> → expected <strong>{e.expectedVerdict.toUpperCase()}</strong></div>
              <div style={{ fontFamily: "monospace", opacity: 0.85, wordBreak: "break-all" }}>{e.url}</div>
              <div style={{ fontSize: 11, opacity: 0.6 }}>{new Date(e.ts).toLocaleString()}</div>
            </div>
            <button
              onClick={() => void remove(e.ts, e.url)}
              style={{ alignSelf: "start", background: "transparent", border: 0, color: "#dc2626", cursor: "pointer", fontSize: 12 }}
            >
              remove
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

render(<App />, document.getElementById("root")!);
