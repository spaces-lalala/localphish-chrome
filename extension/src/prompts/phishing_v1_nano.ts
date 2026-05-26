// Stage 3 prompt — Nano variant (4K context budget).
// Plan §7 principles:
//   1. Role = senior security analyst
//   2. Explicit signal categories enumerated
//   3. Chain-of-thought tolerated internally, only JSON is consumed
//   4. Zero-shot (few-shot blows Nano's token budget)
//   5. temperature=0 (set on the session, not in the prompt)

import type { Stage3Input } from "@/types";

const SYSTEM_PROMPT = `You are a senior security analyst grading a webpage for phishing risk.

Output ONLY a single JSON object, no prose, no markdown fences. Use this schema:
{"risk_score": <int 0-100>, "verdict": "safe"|"caution"|"suspicious"|"dangerous", "category": "credential_harvest"|"wallet_drainer"|"brand_impersonation"|"tech_support_scam"|"benign"|"other", "reasons": [<short string>, ...], "need_visual": <bool>}

Decision guide:
- A page asking for password + OTP, or password + credit card, on a domain
  that is not the real brand's canonical eTLD+1 → "dangerous", category
  "credential_harvest".
- A page asking for a crypto seed phrase (12 or 24 words) → "dangerous",
  category "wallet_drainer".
- Urgent language ("account will be suspended in 24 hours", "verify
  immediately") combined with brand impersonation → "suspicious" or higher.
- Real bank / SaaS login on its own brand domain → "safe".
- Generic content, blogs, search results, docs → "safe".
- Set need_visual=true ONLY when you cannot decide from the text alone and a
  screenshot would clearly help (e.g. brand logo present but the text never
  names the brand).

Keep reasons[] short (≤ 6 items, ≤ 220 chars each).`;

const TEXT_BUDGET_CHARS = 1500;

function summarizeSignals(ruleSignals: Stage3Input["ruleSignals"]): string {
  if (ruleSignals.length === 0) return "(none)";
  return ruleSignals
    .slice(0, 12)
    .map((s) => `- ${s.id} (+${s.weight})${s.detail ? `: ${s.detail}` : ""}`)
    .join("\n");
}

export function buildNanoSystemPrompt(): string {
  return SYSTEM_PROMPT;
}

export function buildNanoUserPrompt(input: Stage3Input): string {
  const text = input.textSample.slice(0, TEXT_BUDGET_CHARS);
  return [
    `URL: ${input.url}`,
    `eTLD+1: ${input.etld1 || "(unknown)"}`,
    `Page title: ${input.title || "(none)"}`,
    `Rule-layer signals already detected:`,
    summarizeSignals(input.ruleSignals),
    `Visible page text (truncated):`,
    text || "(empty)"
  ].join("\n");
}

export function buildRetryPrompt(prev: string): string {
  return [
    `Your previous reply was not valid JSON matching the schema.`,
    `Previous reply:`,
    prev.slice(0, 600),
    ``,
    `Output ONLY the JSON object now, with no surrounding text or fences.`
  ].join("\n");
}
