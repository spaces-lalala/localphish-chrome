# LocalPhish — On-Device LLM Phishing Sentinel for Chrome

A privacy-first Chrome extension that scores any page for phishing risk
**entirely on-device**, using a cascade of cheap URL rules → DOM features →
local LLM reasoning → visual brand verification. **No URL, no DOM, no page
content ever leaves your browser.**

## Why

Mainstream phishing defenses (Google Safe Browsing, SmartScreen, e-mail
gateways) upload URLs and page summaries to remote services and rely on
blacklists that lag 12–48 hours behind new campaigns — long after the first
wave of victims is hit. LocalPhish runs the full pipeline locally, so you get:

- **Zero data exfiltration.** Verdicts and reasons stay on your machine.
- **No blacklist lag.** Decisions come from rules + a local language model,
  not from a remote feed.
- **Semantic understanding.** The LLM stage detects urgency cues, brand
  impersonation, and social-engineering tone that regex misses.

## Architecture (cascade pipeline)

| Stage | What | Where it runs | Latency |
|---|---|---|---|
| 1 | URL rules (IDN, typosquat, suspicious TLD, Tranco allow-list) | Service worker, pure JS | ~5 ms |
| 2 | DOM features (forms, password/OTP fields, hidden iframes, favicon hash) | Content script, ISOLATED world | ~20 ms |
| 3 | Local LLM (Qwen2.5-1.5B via WebLLM, or Gemini Nano via `window.ai`) | Offscreen Document, WebGPU/WASM | 150 ms – 2 s |
| 4a | CLIP logo-embedding retrieval vs Top-300 brand library | Offscreen Document | ~50 ms |
| 4b | VLM screenshot reasoning (Moondream 2, opt-in) | Offscreen Document, WebGPU | 0.8 – 7 s |

Each stage short-circuits if the verdict is already decisive, so 95% of pages
never wake the LLM.

## Repo layout

| Path | Purpose |
|---|---|
| [extension/](extension/) | MV3 Chrome extension (TypeScript + Vite + @crxjs + Preact). |
| [eval/](eval/) | Tier A (static) + Tier B (Playwright-rendered) evaluation pipelines (Python, uv). |
| [docs/](docs/) | Architecture notes and design docs. |

## Quick start — load the extension unpacked

```bash
cd extension
npm install
npm run build       # emits extension/dist/
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select `extension/dist`
4. Click the LocalPhish action icon on any page — popup shows the verdict and active backend.

For dev with HMR:

```bash
cd extension
npm run dev
```

Then load `extension/dist` the same way; @crxjs reloads on save.

## Evaluation suite

```bash
cd eval
uv sync
uv run python tier_a_static.py --backend rules-only
```

See [eval/README.md](eval/README.md) for Tier B (Playwright) setup.

## Status

- [x] MV3 manifest, SW, content script, popup, options, offscreen — wired and buildable
- [x] RPC envelope and shared types
- [x] uv-managed eval project skeleton
- [ ] Stage 1 URL rule engine (Punycode, typosquat, Tranco allow-list)
- [ ] Stage 2 DOM extractor v1
- [ ] Gemini Nano probe + WebLLM probe
- [ ] Brand DB build script
- [ ] Tier A signal extractors + metrics

## Known dev-only audit warnings

`npm audit` flags vulnerabilities in `esbuild`/`rollup` — both are dev tooling
(dev-server CORS + path traversal in build artifacts). Neither ships in the
packaged extension. Tracked but not force-fixed; `npm audit fix --force` would
downgrade @crxjs to v1, which lacks Offscreen Document support.

## License

TBD.
