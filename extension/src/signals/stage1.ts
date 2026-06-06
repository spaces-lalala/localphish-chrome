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
import taiwanAllowlistRaw from "@/data/taiwan-allowlist.json";

import { parseUrl, type ParsedUrl } from "./parse-url";
import { urlFeatureSignals } from "./url-features";
import { homographSignals } from "./homograph";
import { typosquatSignals, buildBrandIndex, type Brand, type BrandIndex } from "./typosquat";
import { compileTldTable, suspiciousTldSignals, type TldTable } from "./suspicious-tld";
import { fakeGovTwSignals } from "./fake-gov-tw";
import { reverseProxySignals } from "./reverse-proxy";
import { phishletSignals } from "./phishlet-fingerprint";
import { unicodeTrickeryUrlSignals } from "./unicode-trickery";
import { AllowList } from "./allowlist";
import { SAFE_CEILING, DANGER_FLOOR, SUSPICIOUS_FLOOR } from "./thresholds";
import { bloomHas, getActiveBloom } from "./bloom";
import { weight as W } from "./weights";

// ---- Module-level singletons (built once, reused across every page) ------

const BRANDS: Brand[] = (brandListRaw as { brands: Brand[] }).brands;
const BRAND_INDEX: BrandIndex = buildBrandIndex(BRANDS);
const BRAND_DOMAIN_LABELS = new Set(BRANDS.map((b) => b.domain.split(".")[0]));
const TLD_TABLE = compileTldTable(suspiciousTldsRaw as unknown as TldTable);
const ALLOWLIST = new AllowList((trancoSample as { domains: string[] }).domains);
const TW_ALLOWLIST = new AllowList((taiwanAllowlistRaw as { domains: string[] }).domains);

/** Stage 2 reuses the brand index for favicon mismatch lookup. */
export function getBrandIndex(): BrandIndex {
  return BRAND_INDEX;
}

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

// Thresholds re-exported from ./thresholds.ts so Stage 2 and cascade share
// the same numbers. Aliasing here for backwards compatibility of any
// existing readers of these names.
const SAFE_THRESHOLD = SAFE_CEILING;
const DANGER_THRESHOLD = DANGER_FLOOR;

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

  // TWNIC institutional-TLD short-circuit. ".edu.tw" and ".gov.tw" are
  // tightly registered: TWNIC requires verified institutional identity
  // (academic or government) for second-level domains. Successfully
  // registering a fake .edu.tw / .gov.tw is essentially impossible, so
  // any eTLD+1 ending in these suffixes is treated as safe at Stage 1.
  // This MUST come before the TW first-class allowlist and before the
  // bloom check, so even an accidentally-poisoned blob can never burn
  // a legit Taiwan government / education page.
  //
  // Note: fake-gov-tw.ts still catches *spoofed* .gov.tw — that detector
  // looks for hostnames that contain "gov.tw" but whose eTLD+1 does NOT
  // end in .gov.tw (e.g., gov.tw.attacker.xyz or gov-tw.click).
  const lowerEtld1 = parsed.etld1?.toLowerCase() ?? "";
  if (lowerEtld1.endsWith(".edu.tw") || lowerEtld1.endsWith(".gov.tw")) {
    return {
      rawScore: 0,
      verdict: "safe",
      shortCircuit: true,
      signals: [{
        id: "url.tw_institutional_tld",
        stage: "stage1",
        weight: 0,
        detail: `eTLD+1 "${parsed.etld1}" is a TWNIC-verified institutional TLD (.edu.tw / .gov.tw) — short-circuited safe`
      }],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed
    };
  }

  // Taiwan first-class allowlist. Heavy attacker targets that don't make
  // global Tranco Top-5000 (cathaybk, esun, shopee.tw, momoshop, ...) live
  // here. Addresses Tier F production-proxy finding that 52% of benign rows
  // over-fired through the LLM stage because Tranco-only allowlist let them
  // accumulate 15-49 grey-band points on rendered DOM.
  if (TW_ALLOWLIST.has(parsed.etld1)) {
    return {
      rawScore: 0,
      verdict: "safe",
      shortCircuit: true,
      signals: [{
        id: "url.tw_allowlist_hit",
        stage: "stage1",
        weight: 0,
        detail: `eTLD+1 "${parsed.etld1}" is on the Taiwan-curated institution allow-list`
      }],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed
    };
  }

  // On-device 165 / 警政署 bloom-filter check. The blob ships with the
  // extension and is refreshed daily by chrome.alarms (background/bloom-
  // refresh.ts). A hit means data.gov.tw dataset 176455 listed this domain
  // as 遭停止解析涉詐網站 — authoritative TW government source, so we
  // short-circuit DANGEROUS without running the LLM. Order is intentional:
  // institutional TLD + first-class allowlist run FIRST so a corrupted
  // blob can never burn legit cathaybk / nhi.gov.tw.
  const hostForBloom = parsed.hostname.toLowerCase();
  const etld1ForBloom = (parsed.etld1 || "").toLowerCase();
  if (bloomHas(hostForBloom) || (etld1ForBloom && bloomHas(etld1ForBloom))) {
    return {
      rawScore: W("url.bloomfilter_blacklist_hit"),
      verdict: "dangerous",
      shortCircuit: true,
      signals: [{
        id: "url.bloomfilter_blacklist_hit",
        stage: "stage1",
        weight: W("url.bloomfilter_blacklist_hit"),
        detail: `hostname matches the on-device 165 反詐騙 phishing-domain feed (eTLD+1 "${parsed.etld1}")`
      }],
      stagesRan: ["stage1"],
      latencyMs: performance.now() - t0,
      parsed
    };
  }
  // Reference getActiveBloom() once so the bundled JSON is decoded eagerly
  // at module-load time (catches malformed blobs at extension boot).
  void getActiveBloom;

  // Run every detector. Each appends its signals; weights sum into rawScore.
  const signals: Signal[] = [];
  signals.push(...urlFeatureSignals(parsed));
  signals.push(...homographSignals(parsed, BRAND_DOMAIN_LABELS));
  signals.push(...typosquatSignals(parsed, BRAND_INDEX));
  signals.push(...suspiciousTldSignals(parsed, TLD_TABLE));
  signals.push(...fakeGovTwSignals(parsed));
  signals.push(...reverseProxySignals(parsed, BRAND_INDEX));
  signals.push(...phishletSignals(parsed));
  signals.push(...unicodeTrickeryUrlSignals(parsed));

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
  } else if (rawScore >= SUSPICIOUS_FLOOR) {
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
