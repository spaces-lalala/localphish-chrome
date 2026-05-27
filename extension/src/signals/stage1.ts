// Stage 1 orchestrator — pure URL-layer scoring.
//
// Decision contract (plan §3):
//   raw_score < 15  -> "safe"          short-circuit, skip downstream stages
//   raw_score > 85  -> "dangerous"     short-circuit, skip downstream stages
//   otherwise       -> "caution"/"suspicious" — caller should promote to Stage 2+

import type { Signal, StageId, Verdict } from "@/types";

import brandListRaw from "@/data/brand-list.json";
import suspiciousTldsRaw from "@/data/suspicious-tlds.json";
import trancoSample from "@/data/tranco-sample.json";

import { parseUrl, type ParsedUrl } from "./parse-url";
import { urlFeatureSignals } from "./url-features";
import { homographSignals } from "./homograph";
import { typosquatSignals, buildBrandIndex, type Brand } from "./typosquat";
import { compileTldTable, suspiciousTldSignals, type TldTable } from "./suspicious-tld";
import { AllowList } from "./allowlist";

// ---- Module-level singletons (built once, reused across every page) ------

const BRANDS: Brand[] = (brandListRaw as { brands: Brand[] }).brands;
const BRAND_INDEX = buildBrandIndex(BRANDS);
const BRAND_DOMAIN_LABELS = new Set(BRANDS.map((b) => b.domain.split(".")[0]));
const TLD_TABLE = compileTldTable(suspiciousTldsRaw as unknown as TldTable);
const ALLOWLIST = new AllowList((trancoSample as { domains: string[] }).domains);

// ---- Public API ----------------------------------------------------------

export interface Stage1Result {
  /** 0–100. Sum of signal weights, capped. */
  rawScore: number;
  /** Suggested verdict for this stage only. Downstream stages can override. */
  verdict: Verdict;
  /** Whether Stage 1 alone is conclusive (allow-list hit, or score < 15 / > 85). */
  shortCircuit: boolean;
  /** All signals fired, in collection order. */
  signals: Signal[];
  /** Cheap diagnostic: stages that participated. Stage 1 only here. */
  stagesRan: StageId[];
  /** ms elapsed inside the orchestrator. */
  latencyMs: number;
  /** Parsed URL — passed to downstream stages so they don't reparse. */
  parsed: ParsedUrl | null;
}

const SAFE_THRESHOLD = 15;
const DANGER_THRESHOLD = 85;

export function runStage1(rawUrl: string): Stage1Result {
  const t0 = performance.now();

  const parsed = parseUrl(rawUrl);
  if (!parsed) {
    return {
      rawScore: 0,
      verdict: "safe",
      shortCircuit: true,
      signals: [{
        id: "url.parse_failed",
        stage: "stage1",
        weight: 0,
        detail: `unparseable URL: ${rawUrl.slice(0, 80)}`
      }],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed: null
    };
  }

  // chrome-internal / extension / file URLs: not a phishing target. Pass through.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      rawScore: 0,
      verdict: "safe",
      shortCircuit: true,
      signals: [],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed
    };
  }

  // Allow-list short-circuit. Skip every other detector — these are the top
  // popular legit eTLD+1s and we don't want to false-positive on, e.g.,
  // google.com hitting "url.long" because the search URL is enormous.
  if (ALLOWLIST.has(parsed.etld1)) {
    return {
      rawScore: 0,
      verdict: "safe",
      shortCircuit: true,
      signals: [{
        id: "url.allowlist_hit",
        stage: "stage1",
        weight: 0,
        detail: `eTLD+1 "${parsed.etld1}" is on the bundled Tranco allow-list`
      }],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed
    };
  }

  // Run every detector. Each appends its signals; weights sum into rawScore.
  const signals: Signal[] = [];
  signals.push(...urlFeatureSignals(parsed));
  signals.push(...homographSignals(parsed, BRAND_DOMAIN_LABELS));
  signals.push(...typosquatSignals(parsed, BRAND_INDEX));
  signals.push(...suspiciousTldSignals(parsed, TLD_TABLE));

  const rawScore = Math.min(100, signals.reduce((s, sig) => s + sig.weight, 0));

  // Only an explicit allow-list hit (handled earlier in this function) or a
  // catastrophic Stage 1 score ≥ DANGER_THRESHOLD should skip downstream
  // stages. A low Stage 1 score just means the URL string looks innocuous —
  // it says nothing about the rendered DOM, so Stage 2 still needs to run.
  let verdict: Verdict;
  let shortCircuit = false;
  if (rawScore >= DANGER_THRESHOLD) {
    verdict = "dangerous";
    shortCircuit = true;
  } else if (rawScore >= 50) {
    verdict = "suspicious";
  } else if (rawScore < SAFE_THRESHOLD) {
    verdict = "safe";
  } else {
    verdict = "caution";
  }

  return {
    rawScore,
    verdict,
    shortCircuit,
    signals,
    stagesRan: ["stage1"],
    latencyMs: performance.now() - t0,
    parsed
  };
}
