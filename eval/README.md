# LocalPhish — Evaluation Suite

10 個 eval scripts，從靜態 BS4 baseline 到 production-proxy + GSB external
baseline harness。完整方法論討論在 [docs/final_report.md](../docs/final_report.md)。

## Setup (uv)

```bash
cd eval
uv sync                      # 安裝 runtime deps
uv sync --extra dev          # 加 dev 工具（ruff / pytest / mypy）
```

Tier B / C / E / G 用 Playwright Chromium 渲染：

```bash
uv run playwright install chromium
```

Tier D / E.5 / F 需要本機 Ollama daemon 跑 Qwen 2.5-0.5B：

```bash
ollama serve &
ollama pull qwen2.5:0.5b
```

Tier H 需要 Google Safe Browsing API key（[Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
免費 tier 每天 10k queries）：

```bash
export GSB_API_KEY=AIza...
```

## Tiers

| Tier | 命令 | 量什麼 | base | 主要結果 |
|---|---|---|---|---|
| A | `uv run python tier_a_static.py` | 靜態 BS4 rules-only | PhreshPhish 1000 | F1@50 = 0.004 |
| B | `uv run python tier_b_rendered.py` | 靜態 vs 渲染特徵 drift | golden 117 | 渲染後 ~9% 訊號漂移 |
| C | `uv run python tier_c_cascade_llm.py` | 真實 extension 載入 + cascade rules-only | golden 117 | F1@50 = 0.255、recall 14.6%、**FPR 0%** |
| D | `uv run python tier_d_python_llm.py` | Python rules + Ollama Qwen 0.5B | golden 117 靜態 base | F1@50 = 0.500、recall 33.3%、FPR 0% |
| D 補測 | `uv run python tier_d_benign_fpr.py` | force_llm on 3 hard-benign fixtures | 自造 | LLM-alone FPR 3/3 |
| E | `uv run python tier_e_adversarial.py` | rules-only 對 prompt injection 抗性 | 3 adversarial pairs | 3/3 max held |
| E.5 | `uv run python tier_e_llm_in_loop.py` | LLM 被 prompt-injection 騙的成功率 | 3 adversarial pairs | LLM fooled 2/3、cascade 守住 3/3 |
| F | `uv run python tier_f_production.py` | rendered rules + Ollama LLM (production-proxy) | golden 117 | **recall 75% 但 FPR 52%** ← 報告 main finding |
| F2 | `uv run python tier_f2_tw_allowlist_effect.py` | Tier F post-hoc + TW allowlist 短路 | Tier F 結果 | FPR 0.522 → 0.478 |
| G | `uv run python tier_g_tw_phish.py` | Stage 1+2 on 9 個 TW phishing fixtures | TW themed | recall **89% @ thr 50** |
| H | `uv run python tier_h_gsb_baseline.py` | GSB Lookup API external baseline | golden + Tier G | 🟡 harness only — 待 API key |
| 2a | `uv run python tier_c_per_signal_precision.py` | 每個 signal 在 rendered base 上的 precision | Tier B rendered features | Stage 1 weighted signals precision = 1.000 |

## Stage 0 parity check (執行任何 tier 前先跑)

`signal-spec.json` 是 TS extension 與 Python eval 都讀同一份的 canonical
weight source。修改 signal 後必須先跑 parity check 確認雙端對齊：

```bash
uv run python check_signal_spec_parity.py
# 預期：PARITY CHECK PASSED — TS and Python both bind to signal-spec.json
```

## 165 反詐騙 bloom filter 重建

repo 已 bundle populated blob (snapshot 2026-06-06, n=57,801)。要拉新版：

```bash
uv run python fetch_tw_scam_domains.py    # data.gov.tw 176455 CSV
uv run python build_bloom_filter.py       # 輸出 ../extension/src/data/tw-scam-bloom.json
cd ../extension && npm run build           # 把新 blob 打進 dist/
```

Feed source: data.gov.tw 176455「165反詐騙諮詢專線_遭停止解析涉詐網站」
（CC BY 4.0 相容、可重分發）。每月更新 1-2 次。

## 抓 dataset 的 prerequisites

PhreshPhish dataset (Tier A 用) 需要從 HuggingFace 抓 + sample：

```bash
uv run python fetch_phreshphish.py        # 抓 + sample 1000 row
```

Tranco list (allowlist 來源) 預設已抓並放在 `../extension/src/data/tranco-sample.json`。
重抓：

```bash
uv run python fetch_tranco.py --top 5000
```

Golden 200 (matched mixed set 來源) 由 `build_golden_200.py` 從上面兩個
資料源 sample 而來：

```bash
uv run python build_golden_200.py
```

## Output 位置

- `results/tier_*_results.csv` — 每個 row 的 verdict（gitignored，重跑會覆蓋）
- `results/tier_*_summary.json` — aggregate metrics（gitignored）
- `results/TIER_A_*_RUN.md` — 人類可讀的歷次跑分析（committed）
