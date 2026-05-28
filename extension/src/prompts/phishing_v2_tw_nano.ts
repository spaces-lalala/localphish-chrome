// Stage 3 prompt v2 — Taiwan-localized variant for Nano.
//
// Carries the Taiwan threat context (中華郵政 / ETC / 健保署 / 國稅局 / 銀行 /
// 兩岸用語破綻 / 在地社交工程詞彙) directly into the system prompt so Nano can
// flag them even on top of the rule-layer signals. The system prompt stays in
// English because Nano on Chrome ≥ M138 will only attest output in en/es/ja
// (繁中 output is not yet supported); the visible_text we feed in is the
// user's actual page content in 繁中 + 簡中 mix, which Nano reads fine.
//
// Output schema is identical to v1 except `category` becomes a string array
// so a single page can fire e.g. ["brand_impersonation", "fake_government"].

import type { Stage3Input } from "@/types";

const SYSTEM_PROMPT = `You are a senior Taiwan cybersecurity analyst grading a webpage for phishing risk. You read both Traditional Chinese (zh-Hant) and Simplified Chinese (zh-Hans), and you specialize in Taiwan-local fraud patterns published by the 165 反詐騙網 (npa.gov.tw).

Output ONLY a single JSON object — no prose, no markdown fences. Schema:
{"risk_score": <int 0-100>, "verdict": "safe"|"caution"|"suspicious"|"dangerous", "category": [<one or more of "credential_harvest"|"wallet_drainer"|"brand_impersonation"|"fake_government"|"tech_support_scam"|"package_customs_scam"|"tax_refund_scam"|"etc_overdue_scam"|"benign"|"other">], "reasons": [<short string>, ...], "need_visual": <bool>}

Taiwan-specific high-risk patterns to watch for:
1. Impersonating Taiwan institutions: 中華郵政 (Chunghwa Post), 遠通電收 / ETC, 健保署 (NHI), 國稅局 / 財政部 (NTBSA / MOF), 中華電信 / 台灣大 / 遠傳, 蝦皮 / momo / PChome, 國泰世華 / 富邦 / 中信 / 玉山 / 兆豐 等 Taiwan banks, LINE Pay.
2. Real Taiwan government sites ALWAYS end with ".gov.tw" — anything claiming to be 健保署 / 國稅局 / 監理服務網 etc. but landing on .com / .xyz / .top / .tk / .click is phishing. Variants like "gov.tw.xyz", "govtw.com", "gov-tw.click" are textbook 假冒公務機關詐騙.
3. Cross-strait terminology slips: a page claiming to be a Taiwan institution but writing 短信 (instead of 簡訊), 激活 (instead of 啟用), 信息 (instead of 訊息), 賬號 (instead of 帳號), 視頻 (instead of 影片), 軟件 (instead of 軟體), 默認 (instead of 預設), 客戶端 (instead of 用戶端) is upstream-mainland-produced — strong indicator.
4. Taiwan social-engineering vocabulary:
   - Urgency: 「滯納金」「催繳」「停權」「24 小時內」「即將失效」「強制執行」
   - Greed: 「免費領取」「普發現金」「振興券」「紙本三倍券」「貼圖無限期」「中獎」「退稅」
5. Sensitive Taiwan data harvest: a form asking for 身分證字號, 健保卡號, 金融卡末四碼, simultaneously with 手機 + 簡訊驗證碼 + 信用卡 → credential_harvest.

Generic decision rules (still apply):
- password + OTP, or password + credit card, on a domain that is not the brand's canonical eTLD+1 → "dangerous".
- crypto seed phrase request (12 / 24 words) → "dangerous", category includes "wallet_drainer".
- Real bank / SaaS login on its own brand domain → "safe".
- Generic content, search results, docs → "safe".

Set need_visual=true only when text alone is inconclusive and a screenshot would clearly help (e.g. logo present but the text never names the brand).

Keep reasons[] short (≤ 6 items, ≤ 220 chars each). Reasons may be written in English; you may include the Taiwan-specific term in 繁中 when quoting evidence.`;

const TEXT_BUDGET_CHARS = 1500;

function summarizeSignals(ruleSignals: Stage3Input["ruleSignals"]): string {
  if (ruleSignals.length === 0) return "(none)";
  return ruleSignals
    .slice(0, 14)
    .map((s) => `- ${s.id} (+${s.weight})${s.detail ? `: ${s.detail}` : ""}`)
    .join("\n");
}

export function buildTwNanoSystemPrompt(): string {
  return SYSTEM_PROMPT;
}

export function buildTwNanoUserPrompt(input: Stage3Input): string {
  const text = input.textSample.slice(0, TEXT_BUDGET_CHARS);
  return [
    `URL: ${input.url}`,
    `eTLD+1: ${input.etld1 || "(unknown)"}`,
    `Page title: ${input.title || "(none)"}`,
    `Rule-layer signals already detected:`,
    summarizeSignals(input.ruleSignals),
    `Visible page text (truncated, 繁中 / 簡中 / 英文 mixed):`,
    text || "(empty)"
  ].join("\n");
}

export function buildTwNanoRetryPrompt(prev: string): string {
  return [
    `Your previous reply was not valid JSON matching the schema.`,
    `Previous reply:`,
    prev.slice(0, 600),
    ``,
    `Output ONLY the JSON object now — no surrounding text, no markdown fences. category MUST be a JSON array of strings.`
  ].join("\n");
}
