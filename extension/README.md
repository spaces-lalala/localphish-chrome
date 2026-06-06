# LocalPhish — Chrome MV3 extension

Chrome MV3 擴充功能，cascade 四階段釣魚偵測。完整專案說明見 [../README.md](../README.md)。

## Build & install

需要 Node 22+。

```bash
npm install
npm run build       # 含 tsc --noEmit，產出 dist/
```

載入到 Chrome：

1. 開 `chrome://extensions`
2. 右上開「**開發人員模式**」
3. 「**載入未封裝**」→ 選 `extension/dist`

## Development

```bash
npm run dev          # Vite + HMR；@crxjs 在 src/ 改檔時自動 reload extension
npm run typecheck    # tsc 只跑 type check
npm test             # vitest 43 個 regression test
npm run pack-crx     # 打成可上架 Chrome Web Store 的 .zip
```

## 結構

```
src/
├── background/         Service worker
│                       - index.ts (RPC router + tabVerdicts cache)
│                       - bloom-refresh.ts (165 feed daily update)
│                       - inference-queue.ts (cross-tab LLM 排程)
│                       - pre-nav-interstitial.ts (DOM paint 前攔截)
│                       - user-storage.ts (allowlist + profile)
├── content/            Content scripts (ISOLATED world)
│                       - index.ts (entry: extract → SW → badge)
│                       - dom-extract.ts (DOM scanner)
│                       - badge.ts (Shadow DOM badge UI)
│                       - submit-intercept.ts (form submit confirm 攔截)
├── offscreen/          Offscreen Document — LLM 模型住這
├── popup/              Preact popup
├── options/            URL Tester + Allowlist editor + Profile selector
├── interstitial/       Pre-nav 紅底警告頁
├── signals/            Stage 1 + Stage 2 detectors
│                       - signal-spec.json 的 loader (weights.ts)
│                       - bloom.ts (165 bloom decoder)
│                       - stage1.ts / stage2.ts (orchestrators)
│                       - 個別 detector 檔
├── llm/                LLM backends
│                       - nano.ts (Chrome built-in Prompt API)
│                       - webllm.ts (WebLLM + Qwen 2.5-0.5B)
│                       - router.ts (profile-based selection + 重試)
├── prompts/            v1 英文 / v2 台灣化 / v3 Qwen 繁中
└── data/               Bundled JSON resources
    - brand-list.json
    - brand-favicon-cdns.json
    - tranco-sample.json (Top-5000 global allowlist)
    - taiwan-allowlist.json (88 TW institutions)
    - tw-scam-bloom.json (165 phish domains as bloom filter)
    - signal-spec.json (canonical weight source)
    - known-idp-allowlist.json (OAuth IDPs)
    - suspicious-tlds.json (TLD risk tiers)
```

## 第一次跑遇到的 gotchas

詳見 [../CLAUDE.md](../CLAUDE.md) 的 **Critical gotchas** 段落（10 條）。
最容易踩到的：

1. **Reload extension 後要 F5 已開的分頁** — content script 需要重載
2. **Nano 需要 `outputLanguage` 在三個 API call 都標** — `availability()` /
   `create()` / `prompt()` 任何一個漏標都會 runtime fail
3. **Pro Profile dGPU 不可用問題**：Windows hybrid graphics 機器上
   Chromium 強制選用 Intel iGPU（[crbug 369219127](https://crbug.com/369219127)），
   Qwen 0.5B 推論 30-90 秒。在 Windows 顯示器設定把 Chrome 加為「高效能」
   並重啟 Chrome 強迫使用 dGPU 可降到 1-3 秒
