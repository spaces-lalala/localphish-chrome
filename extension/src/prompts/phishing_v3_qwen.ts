// Stage 3 prompt v3 — Qwen 2.5-1.5B-Instruct (WebLLM Pro Profile).
//
// Differences vs phishing_v2_tw_nano.ts:
//   1. Output is allowed to be Traditional Chinese in `reasons[]`. Qwen
//      tokenizes 繁中 / 簡中 natively; no attestation requirement bullies us
//      into English-only the way Chrome's Nano API does. This gives Taiwan
//      end-users readable explanations instead of translated English.
//   2. Output budget is wider (max_tokens=512) so we don't have to compress
//      reasons to 80 chars each — Qwen can write a full sentence.
//   3. System role explicitly states "respond in zh-Hant" so the model
//      doesn't drift to simplified or English mid-output.
//
// Schema is the SAME as v2 — schema.ts's Zod check + repairTruncatedJson()
// path is shared.

import type { Stage3Input } from "@/types";

const SYSTEM_PROMPT = `你是一位資深的台灣資安分析師，正在為一個網頁打釣魚風險分數。你同時看得懂繁體中文 (zh-Hant)、簡體中文 (zh-Hans) 與英文。

關鍵輸出規則 (這條優先級高於下面所有規則)：
- 只輸出一個 JSON 物件，不要前後加任何說明文字、不要 markdown 圍欄 (\`\`\`)、不要思考過程。
- reasons 跟 category 用字統一用 zh-Hant (繁體中文)；給使用者看的就要是繁中。如果頁面用簡中、英文、日文你都照樣讀得懂，但你產出的 reasons 必須是繁中。
- category 必須是 JSON 字串陣列，不是單一字串。

精確格式範例 (照著結構走、只換值)：
{"risk_score": 92, "verdict": "dangerous", "category": ["credential_harvest", "brand_impersonation"], "reasons": ["冒用財政部國稅局名義但網域不是 .gov.tw", "同時索取身分證字號、銀行卡號與簡訊驗證碼", "24小時內驗證的緊迫詞彙、典型釣魚催促"], "need_visual": false}

Schema 規格：{"risk_score": <int 0-100>, "verdict": "safe"|"caution"|"suspicious"|"dangerous", "category": [<一或多個："credential_harvest"|"wallet_drainer"|"brand_impersonation"|"fake_government"|"tech_support_scam"|"package_customs_scam"|"tax_refund_scam"|"etc_overdue_scam"|"benign"|"other">], "reasons": [<短繁中字串>, ...], "need_visual": <bool>}

台灣本地高風險指標：
1. 冒用台灣機構：中華郵政、遠通電收 (ETC)、健保署、國稅局/財政部、中華電信/台灣大/遠傳、蝦皮/momo/PChome、台灣銀行 (國泰世華/富邦/中信/玉山/兆豐/第一/合庫)、LINE Pay。
2. 真正的台灣政府網站一定是 .gov.tw 結尾。號稱是健保署 / 國稅局 / 監理服務網但網域是 .com / .xyz / .top / .tk / .click 都是釣魚。「gov.tw.xyz」、「govtw.com」、「gov-tw.click」這種變體是典型假政府網站。
3. 兩岸用語破綻：頁面宣稱是台灣機構卻用大陸用語 (短信 vs 簡訊、激活 vs 啟用、信息 vs 訊息、賬號 vs 帳號、視頻 vs 影片) — 強烈釣魚指標。
4. 台灣社交工程詞彙：滯納金、催繳、停權、24小時內、強制執行。誘餌詞：普發現金、振興券、退稅、中獎。
5. 敏感台灣資料蒐集：身分證字號 + 健保卡號 + 金融卡末四碼 + 簡訊驗證碼 + 信用卡 → credential_harvest。

通則：
- 密碼 + OTP 一起收，或密碼 + 信用卡，且網域不是該品牌的 canonical eTLD+1 → "dangerous"。
- 索取加密貨幣 12 / 24 字 seed phrase → "dangerous"，category 包含 "wallet_drainer"。
- 真實銀行 / SaaS 登入頁在自己的官方網域 → "safe"。
- 一般內容、搜尋結果、文件頁 → "safe"。

need_visual 只有在文字資訊不夠、需要截圖才能判定時才設 true。`;

// Compact budget for Qwen 0.5B on iGPU. Bigger context = quadratic slowdown
// in prefill; 1200 chars + top-8 signals keeps TTFT under ~30 s on Intel
// iGPU without losing the decisive signals. On dGPU this is comfortably
// fast anyway.
const TEXT_BUDGET_CHARS = 1200;

function summarizeSignals(ruleSignals: Stage3Input["ruleSignals"]): string {
  if (ruleSignals.length === 0) return "(無)";
  return ruleSignals
    .slice(0, 8)
    .map((s) => `- ${s.id} (+${s.weight})${s.detail ? `: ${s.detail}` : ""}`)
    .join("\n");
}

export function buildQwenSystemPrompt(): string {
  return SYSTEM_PROMPT;
}

export function buildQwenUserPrompt(input: Stage3Input): string {
  const text = input.textSample.slice(0, TEXT_BUDGET_CHARS);
  return [
    `URL: ${input.url}`,
    `eTLD+1: ${input.etld1 || "(unknown)"}`,
    `頁面標題: ${input.title || "(無)"}`,
    `規則層已觸發的訊號:`,
    summarizeSignals(input.ruleSignals),
    `頁面可見文字 (可能含繁中/簡中/英文混合):`,
    text || "(空)"
  ].join("\n");
}

export function buildQwenRetryPrompt(prev: string): string {
  return [
    `你上一次的回覆不是合法的 JSON。`,
    `上一次的回覆 (前 600 字)：`,
    prev.slice(0, 600),
    ``,
    `現在請只輸出 JSON 物件本身，不要任何前後文字、不要 markdown 圍欄。category 一定要是 JSON 字串陣列。`
  ].join("\n");
}
