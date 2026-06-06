> 📚 **課程作業**：本專案為 TAICA 課程「大型語言模型與資訊安全系統」期末
> 專案內容。此專案由 Claude 協助完成，若有錯誤可隨時告知。**使用該套件不
> 代表為完全的安全保障**，還是提醒各位要保持警惕，切勿隨意洩漏個資等重
> 要資訊。

# LocalPhish — On-Device LLM Phishing Sentinel for Chrome

LocalPhish 是 Chrome MV3 擴充功能，把整條釣魚偵測 pipeline 搬到使用者
本機。透過四階段 cascade（URL 規則 → DOM 特徵 → 本地 LLM → 視覺/比對），
任何 URL / DOM / 頁面內容 **絕不離開瀏覽器**。

## 設計重點

- **隱私不變式**：runtime 中單一 URL / DOM / 文字「絕不」對外送。
  外部服務（GSB / WHOIS / CT log 等）僅在 `eval/` 端 offline 調用，
  絕不進 extension runtime。
- **Taiwan-localized**：除了通用釣魚偵測（typosquat、IDN、reverse-proxy
  FQDN、bidi-override 等），還有
  - 88 筆台灣本土機構 first-class allowlist（cathaybk、esun、中信、中華
    郵政、健保署、國稅局、momoshop、7-11…）
  - 57,801 筆 165 反詐騙專線「遭停止解析涉詐網站」on-device bloom filter
    （[data.gov.tw 176455](https://data.gov.tw/dataset/176455), CC BY 4.0）
  - 偽 `.gov.tw` 變體網域 + 跨海峽用語破綻（短信／激活／賬號 在自稱台灣
    機構的頁面上）+ 身分證字號 / 卡 / OTP combo
- **Cascade `max(rules, llm)` 設計取捨**：在最接近 production 的設定
  （rendered DOM + Ollama Qwen 2.5-0.5B），LLM 對結構像登入頁的合法頁面
  （如 cathaybk）有 over-fire 傾向。cascade 的「LLM 只能升級不能降級」
  特性對抗 prompt injection 是硬防線、但 false-positive 也救不了。詳見
  Honest limitations 段。

## 四階段 cascade

```
┌─────────────────────────────────────────────────────────────────────┐
│ Stage 0  pre-nav URL 攔截 (webNavigation.onBeforeNavigate)           │
│   Stage 1 alone ≥ 85 或 165 bloom 命中 → DOM paint 前 redirect       │
│   到專屬警告頁 (src/interstitial/)                                    │
├─────────────────────────────────────────────────────────────────────┤
│ Stage 1  URL 規則層 (~5 ms, pure JS in Service Worker)               │
│   ~25 detector：IDN/Punycode、typosquat、reverse-proxy FQDN、       │
│   phishlet、bidi/zero-width、fake-gov-tw、Tranco + TWNIC + TW       │
│   first-class allowlist 短路、165 bloom filter 短路                 │
├─────────────────────────────────────────────────────────────────────┤
│ Stage 2  DOM 特徵層 (~5 ms, in SW over content-script payload)      │
│   ~22 detector：password/OTP/card 跨 eTLD+1、seed-phrase grid、    │
│   tw_pii_combo (身分證 + 卡 + OTP off-allowlist)、hidden iframe、 │
│   cross-strait 用語、cloaking widget、favicon CDN mismatch          │
├─────────────────────────────────────────────────────────────────────┤
│ Stage 3  本地 LLM (15 ≤ rules+dom ≤ 84 灰色帶才啟動)                 │
│   Lite Profile: Gemini Nano (Chrome 內建 LanguageModel API)         │
│   Pro Profile:  WebLLM + Qwen 2.5-0.5B-Instruct (q4f16)            │
│   Cross-tab InferenceQueue 把背景分頁排在前景之後                   │
├─────────────────────────────────────────────────────────────────────┤
│ Stage 4  視覺 (未實作)：CLIP logo retrieval + 可選 Moondream VLM     │
└─────────────────────────────────────────────────────────────────────┘
        ▼
   verdict = max(rules, llm)
        ▼
   Toolbar action icon 六態 + in-page Shadow DOM badge
        + submit-time form interception (DOM paint 後第二道防線)
```

## Quick start — extension

需要：Node 22+、npm

```bash
cd extension
npm install
npm run build        # 產出 extension/dist/，含 tsc --noEmit
```

載入到 Chrome：

1. 開 `chrome://extensions`
2. 右上角開「**開發人員模式**」
3. 「**載入未封裝**」→ 選 `extension/dist`

開發迭代：

```bash
cd extension
npm run dev          # Vite + HMR；@crxjs 自動 reload
npm run typecheck    # tsc 只檢查
npm test             # vitest 43 個 regression test
npm run pack-crx     # 打成可上架的 .zip
```

## 165 bloom filter 怎麼產生 / 更新

repo 已包含 populated blob（57,801 domains, 8.31 Mbit, snapshot 2026-06-06）
位於 [`extension/src/data/tw-scam-bloom.json`](extension/src/data/tw-scam-bloom.json)。
要重新產生 / 更新成新版 feed：

```bash
cd eval
uv sync
uv run python fetch_tw_scam_domains.py    # 從 data.gov.tw 176455 抓 CSV
uv run python build_bloom_filter.py       # 編碼為 bloom blob
cd ../extension
npm run build                              # 把新 blob 打進 dist/
```

Extension runtime 跑 `chrome.alarms` 每日刷新；user 不需要手動跑上面這
段。Fresh clone 時 bundled blob 已 populated，因此**安裝後立刻可用**。

## Evaluation suite

完整 8 個 tier 的評估管線在 `eval/`。詳見 [eval/README.md](eval/README.md)。
摘要：

| Tier | 量什麼 | base | 主要結果 |
|---|---|---|---|
| A | 靜態 BS4 rules-only | PhreshPhish 1000 | F1@50 = 0.004 |
| B | 靜態 vs 渲染特徵 drift | golden 117 | 渲染後 ~9% 訊號漂移 |
| C | 真實 extension via Playwright | golden 117 | F1@50 = 0.255、recall 14.6%、**FPR 0%** |
| D | Python rules + Ollama Qwen 0.5B (靜態 base) | golden 117 | F1@50 = 0.500、recall 33.3%、FPR 0% (規則層功勞) |
| E + E.5 | Adversarial prompt-injection on Stage 3 LLM | 3 fixture | LLM 被騙 2/3、cascade max() 守住 3/3 |
| F | rendered rules + Ollama LLM (production-proxy) | golden 117 | **recall 75% 但 FPR 52%** — 本期 main finding |
| F2 | Tier F + post-hoc TW allowlist | golden 117 | FPR 0.522 → 0.478 |
| G | Stage 1 + 2 on 9 個 TW phishing fixtures | TW themed | **recall 89% @ thr 50** |
| H | Google Safe Browsing external baseline | golden + Tier G | 🟡 harness only — 待 GSB API key |

## Repo 結構

```
.
├── README.md                ← this file
├── LICENSE                  ← MIT
├── ATTRIBUTIONS.md          ← 165 feed (CC BY 4.0) + 其他第三方資料來源
├── extension/               Chrome MV3 擴充（TypeScript + Vite + @crxjs + Preact）
│   ├── src/
│   │   ├── background/      Service worker + bloom-refresh + inference queue + pre-nav interstitial
│   │   ├── content/         Content scripts + Shadow DOM badge + submit-intercept
│   │   ├── offscreen/       Offscreen Document — LLM 模型住這
│   │   ├── popup/           Preact popup
│   │   ├── options/         URL Tester + Allowlist editor + Profile selector
│   │   ├── interstitial/    Pre-nav 紅底警告頁
│   │   ├── signals/         Stage 1+2 detectors + bloom decoder + signal-spec loader
│   │   ├── llm/             Nano + WebLLM + router
│   │   ├── prompts/         v1 英文 / v2 台灣化 / v3 Qwen 繁中
│   │   └── data/            brand-list, tranco-sample, TW allowlist, 165 bloom blob,
│   │                        signal-spec.json (canonical weight source)
│   └── manifest.config.ts   @crxjs declarative manifest
│
├── eval/                    Python 評估 (uv)
│   ├── src/localphish_eval/ rules.py + dom_features.py (Python port, 讀同一份 signal-spec)
│   ├── check_signal_spec_parity.py  自動防 TS / Python drift
│   ├── fetch_*.py           data.gov.tw 165 feed + Tranco + PhreshPhish + 165 文章
│   ├── build_bloom_filter.py
│   └── tier_*.py            8 個 tier + F2 後處理 + 2a per-signal precision
│
└── test/
    └── fixtures/            9 個 TW-themed phish + 3 adversarial + 3 hard-benign +
                              通用 microsoft/paypal/crypto 等
```

## Honest limitations

需要使用者知道的 5 條主要限制：

1. **Tier F production-proxy 設定下 52% benign FPR** — Qwen 2.5-0.5B 對
   台灣銀行 / 政府這類「結構像登入頁」的合法頁面嚴重 over-fire。Cascade
   `max(rules, llm)` 救不了。
2. **GSB external baseline 沒實際對比數字** — `eval/tier_h_gsb_baseline.py`
   harness 寫好但待提供 GSB API key 才能跑出真實對比；本專案目前不主張
   vs SOTA。
3. **Tier C / D / F 未在當前 detector 集合下重跑** — 需 Playwright + Ollama；
   direct measurement 確認本期新加偵測器在 golden_200 fire 0 次，所以 52%
   FPR 數字仍正確，但 golden_200 不是測台灣防禦的合適 benchmark。
4. **真實 in-the-wild TW 釣魚樣本不足**：本期 Tier G 9 fixtures 是依照
   165 article 描述自寫的，不是 archive 抓的真實樣本。
5. **Cert org / domain age**：Chrome MV3 平台限制（W3C #882 仍 draft），
   所有可行查詢路徑都違反隱私不變式 — 不會做。

## 隱私 / 安全 commitments

- Extension runtime **絕不**對外送單一 URL / DOM / 文字。
- 唯一對外網路調用是 `chrome.alarms` 每日 batch 下載 165 bloom blob 的
  靜態 URL（同一個 blob 給所有使用者，不洩漏使用者識別）。本期 blob 直
  接 bundle 進 dist，refresh URL 在 [`extension/src/background/bloom-refresh.ts`](extension/src/background/bloom-refresh.ts)
  預設關閉。
- 所有評估端工具（含 GSB / archive 抓取）僅在 `eval/` offline 使用，
  runtime 程式碼 import path 不會碰到。

## License

[MIT](LICENSE) — 程式碼。

第三方資料的授權見 [ATTRIBUTIONS.md](ATTRIBUTIONS.md)：
- **165 反詐騙 phishing-domain feed**：政府資料開放授權條款第 1 版
  （CC BY 4.0 相容）— 重分發需註明來源。
- **Tranco list**：CC BY 4.0
- **PhreshPhish dataset**：研究用途授權
- 其他 brand 名稱屬各自所有人。

## Credits

- 課程：TAICA「大型語言模型與資訊安全系統」（2026 春）
- 投影片 / curriculum：Dr. Raymund Lin / AI Nina
- Cascade architecture inspiration：arXiv 2511.09606
- 受啟發但未復現的相關工作：PhishLLM (USENIX 2024)、KnockKnock (NDSS 2024)、PhishIntent (USENIX 2023)
