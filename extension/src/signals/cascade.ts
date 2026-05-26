// Cascade orchestrator — Stage 1 + Stage 2.
// Stage 3 (LLM) and Stage 4 (vision) will hook in here when they land.

import type { ClassifyResult, PageFeatures, Signal, StageId } from "@/types";

import { runStage1 } from "./stage1";
import { runStage2, verdictFromScore } from "./stage2";

const DANGER_FLOOR = 85;
const SAFE_CEILING = 15;

export function runCascade(features: PageFeatures): ClassifyResult {
  const t0 = performance.now();
  const stagesRan: StageId[] = [];
  const signals: Signal[] = [];

  // ---- Stage 1 — URL rules -----------------------------------------------
  const s1 = runStage1(features.url);
  stagesRan.push("stage1");
  signals.push(...s1.signals);

  // Allow-list hit / bad URL → don't waste time on DOM.
  if (s1.shortCircuit) {
    return {
      verdict: s1.verdict,
      riskScore: s1.rawScore,
      signals,
      reasons: signals.map((s) => s.detail ?? s.id),
      backend: "rules-only",
      latencyMs: performance.now() - t0,
      stagesRan
    };
  }

  // ---- Stage 2 — DOM features --------------------------------------------
  // Only meaningful when the content script has actually populated DOM data.
  // URL-only synthetic features (popup fallback) skip Stage 2 cleanly because
  // every boolean is false and every list is empty → Stage 2 emits no signals.
  const pageEtld1 = s1.parsed?.etld1 ?? null;
  const s2 = runStage2(features, pageEtld1);
  stagesRan.push("stage2");
  signals.push(...s2.signals);

  const total = Math.min(100, s1.rawScore + s2.rawScore);

  let verdict: ClassifyResult["verdict"];
  if (total >= DANGER_FLOOR) verdict = "dangerous";
  else if (total < SAFE_CEILING) verdict = "safe";
  else if (total >= 50) verdict = "suspicious";
  else verdict = verdictFromScore(total).verdict;

  return {
    verdict,
    riskScore: total,
    signals,
    reasons: signals.map((s) => s.detail ?? s.id),
    backend: "rules-only",
    latencyMs: performance.now() - t0,
    stagesRan
  };
}
