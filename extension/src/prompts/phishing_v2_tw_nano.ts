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

const SYSTEM_PROMPT = `You are a senior Taiwan cybersecurity analyst grading a webpage for phishing risk. You read both Traditional Chinese (zh-Hant) and Simplified Chinese (zh-Hans).

CRITICAL OUTPUT RULES (these override everything else):
- Output ONLY a single JSON object. No prose, no markdown fences, no commentary.
- ALL text in your JSON output (reasons, category) MUST be ENGLISH ONLY. Do not write Chinese in the output even if the input page is in Chinese — quote Chinese evidence by transliterating or describing it in English (e.g. say "page mentions Chunghwa Post" not "page mentions 中華郵政").
- Schema: {"risk_score": <int 0-100>, "verdict": "safe"|"caution"|"suspicious"|"dangerous", "category": [<one or more of "credential_harvest"|"wallet_drainer"|"brand_impersonation"|"fake_government"|"tech_support_scam"|"package_customs_scam"|"tax_refund_scam"|"etc_overdue_scam"|"benign"|"other">], "reasons": [<short English string>, ...], "need_visual": <bool>}

Taiwan-specific high-risk patterns (you understand the input even if Chinese):
1. Impersonating Taiwan institutions: Chunghwa Post (中華郵政), Far Eastern Electronic Toll Collection / ETC (遠通電收), National Health Insurance (健保署), National Taxation Bureau / Ministry of Finance (國稅局 / 財政部), telecoms (中華電信 / 台灣大 / 遠傳), e-commerce (蝦皮 / momo / PChome), Taiwan banks (國泰世華 / 富邦 / 中信 / 玉山 / 兆豐 / 第一 / 合庫), LINE Pay.
2. Real Taiwan government sites ALWAYS end with ".gov.tw". Pages claiming to be 健保署 / 國稅局 / 監理服務網 on .com / .xyz / .top / .tk / .click are phishing. Variants like "gov.tw.xyz", "govtw.com", "gov-tw.click" are textbook fake-government scams.
3. Cross-strait terminology slips: a page claiming to be a Taiwan institution but using mainland-Chinese words (短信 instead of 簡訊, 激活 instead of 啟用, 信息 instead of 訊息, 賬號 instead of 帳號) is mainland-produced — strong phishing indicator.
4. Taiwan urgency language: 滯納金 (overdue fee), 催繳 (final demand), 停權 (account suspension), 24小時內 (within 24 hours), 強制執行 (forced execution). Taiwan greed bait: 普發現金 (universal cash), 振興券 (revival voucher), 退稅 (tax refund), 中獎 (won a prize).
5. Sensitive Taiwan data harvest: a form asking for 身分證字號 (national ID), 健保卡號 (NHI card), 金融卡末四碼 (last 4 of bank card), plus 手機+簡訊驗證碼+信用卡 → credential_harvest.

Generic rules:
- password + OTP, or password + credit card, on a domain that is not the brand's canonical eTLD+1 → "dangerous".
- crypto seed phrase request (12 / 24 words) → "dangerous", category includes "wallet_drainer".
- Real bank / SaaS login on its own brand domain → "safe".
- Generic content, search results, docs → "safe".

Set need_visual=true only when text alone is inconclusive and a screenshot would clearly help.
Keep reasons[] short (≤ 6 items, ≤ 220 chars each, ENGLISH ONLY).`;

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
