# Third-party data attributions

LocalPhish 程式碼以 MIT 授權（見 [LICENSE](LICENSE)）。本檔列舉 repo 內
bundled 的第三方資料來源、授權條款、以及重分發義務。

---

## 1. 165 反詐騙 / 內政部警政署 phishing-domain feed

- **資料集名稱**：165 反詐騙諮詢專線_遭停止解析涉詐網站
- **來源**：[data.gov.tw 176455](https://data.gov.tw/dataset/176455)
- **發布機關**：中華民國內政部警政署
- **授權**：政府資料開放授權條款 第 1 版（與 CC BY 4.0 相容）
- **使用方式**：以 bloom filter 格式 bundle 於
  `extension/src/data/tw-scam-bloom.json`（snapshot 2026-06-06，n=57,801
  unique domains）。建構流程：`eval/fetch_tw_scam_domains.py` + `eval/build_bloom_filter.py`。
- **重分發義務**：必須註明來源。本 repo 在 (a) 此檔、(b) README.md
  「設計重點」段、(c) `extension/src/data/tw-scam-bloom.json` 內 `_attribution`
  欄位、(d) extension Options 頁面均註明。

## 2. Tranco list（網域熱門度排名）

- **來源**：[tranco-list.eu](https://tranco-list.eu)
- **list_id**：4342X (fetched 2026-05-26)
- **授權**：CC BY 4.0
- **使用方式**：取 Top-5000 eTLD+1 作為 Stage 1 全域 allowlist，bundle 於
  `extension/src/data/tranco-sample.json`。
- **重新抓取**：`eval/fetch_tranco.py --top 5000`

## 3. PhreshPhish 釣魚樣本資料集

- **來源**：arXiv 2507.10854；[HuggingFace `phreshphish/phreshphish`](https://huggingface.co/datasets/phreshphish/phreshphish)
- **授權**：研究用途（research-use license）
- **使用方式**：僅在 `eval/` 端跑 Tier A baseline；**不 bundle 進 extension**。
  `eval/fetch_phreshphish.py` 抓並 sample 1000 row（gitignored）。

## 4. 165 反詐騙 case taxonomy（詐騙手法分類）

- **來源**：[165 反詐騙網](https://165.npa.gov.tw/) JSON API
- **使用方式**：74 篇 article 標題用於 Stage 3 LLM prompt 撰寫的 case
  taxonomy 參考。`eval/fetch_165_articles.py` 抓取。**不 bundle 進
  extension**，僅 prompt 字串內提及。

## 5. 第三方 brand 名稱與 logo

`extension/src/data/brand-list.json`（102 entries、46 Taiwan）含以下品牌
的名稱、域名、aliases：

- 通用：Microsoft、Google、Apple、Amazon、Yahoo、Meta/Facebook、PayPal、
  Adobe、Coinbase、Binance、Netflix、GitHub 等
- 台灣機構：中華郵政、健保署、國稅局（國稅局五區）、財政部、勞保局、
  監理服務網、165 反詐騙、各銀行（國泰世華、玉山、中信、台新、富邦、
  兆豐、第一、合作金庫、台灣銀行）、LINE Pay、悠遊卡、ETC（遠通電收）、
  PChome、momo、蝦皮、Costco 等

**重要**：本資料僅作為防詐騙偵測之 detect-and-warn 用途；不蘊含這些品牌
對本專案的背書、合作、或授權。Brand 名稱與商標屬其各自所有人。

`extension/src/data/brand-favicon-cdns.json` 紀錄常見品牌 favicon CDN
hostname，用於 favicon mismatch detector。同樣不蘊含合作關係。

## 6. WebLLM (Stage 3 Pro Profile)

- **套件**：[@mlc-ai/web-llm](https://github.com/mlc-ai/web-llm) v0.2.84
- **授權**：Apache-2.0
- **模型**：Qwen 2.5-0.5B-Instruct（q4f16 quantization），由 WebLLM
  CDN 首次載入時下載到使用者本機 IndexedDB。模型權重由 MLC 與 Alibaba
  Cloud 共同維護。

## 7. Chrome Built-in AI (Stage 3 Lite Profile)

- **API**：[Chrome Prompt API](https://developer.chrome.com/docs/ai/prompt-api)（Gemini Nano）
- 內建於 Chrome；使用者無需個別授權步驟，但需要 `chrome://flags` 啟用實
  驗性 API（截至 2026-06）。

---

## 給後續貢獻者的提醒

若新增資料集 / model weights / 第三方 corpus，請在本檔追加一筆。重點：

1. 標明確切的授權名稱（不要只寫 "open license"）
2. 標明是否允許重分發 + 是否要求 attribution
3. 標明 bundle 路徑或 download 流程
4. **CC BY、CC BY-SA、CC BY-NC**：可以 bundle，必須註明
5. **CC BY-NC-ND**：不能 bundle，僅可 reference
6. **未明示授權**：預設不能 bundle、需聯絡作者
