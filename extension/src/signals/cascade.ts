// Cascade orchestrator — Stage 1 + Stage 2 + (optional) Stage 3.
// Stage 4 (vision) will hook in here when it lands.

import type {
  ClassifyResult,
  LLMBackend,
  PageFeatures,
  Signal,
  Stage3Input,
  Stage3Output,
  StageId
} from "@/types";

import { runStage1 } from "./stage1";
import { runStage2 } from "./stage2";

const DANGER_FLOOR = 85;
const SAFE_CEILING = 15;
const STAGE3_GREY_MIN = 15; // inclusive
const STAGE3_GREY_MAX = 84; // inclusive — Stage 1+2 ≥85 already conclusive

export type Stage3Fn = (input: Stage3Input) => Promise<{
  result: Stage3Output | null;
  backend: LLMBackend;
  latencyMs: number;
  error?: string;
}>;

export interface CascadeOptions {
  /** Called when the rule-layer score sits in the grey band. Skipped otherwise. */
  stage3?: Stage3Fn;
}

export async function runCascade(
  features: PageFeatures,
  opts: CascadeOptions = {}
): Promise<ClassifyResult> {
  const t0 = performance.now();
  const stagesRan: StageId[] = [];
  const signals: Signal[] = [];

  // ---- Stage 1 — URL rules -----------------------------------------------
  const s1 = runStage1(features.url);
  stagesRan.push("stage1");
  signals.push(...s1.signals);

  // Allow-list / parse-fail / Stage 1 shortcut — bail before touching the DOM.
  if (s1.shortCircuit) {
    return finalize({
      signals,
      score: s1.rawScore,
      stagesRan,
      t0,
      backend: "rules-only"
    });
  }

  // ---- Stage 2 — DOM features --------------------------------------------
  const pageEtld1 = s1.parsed?.etld1 ?? null;
  const s2 = runStage2(features, pageEtld1);
  stagesRan.push("stage2");
  signals.push(...s2.signals);

  let total = Math.min(100, s1.rawScore + s2.rawScore);
  let backend: LLMBackend = "rules-only";

  // ---- Stage 3 — local LLM (grey band only) ------------------------------
  const inGreyBand = total >= STAGE3_GREY_MIN && total <= STAGE3_GREY_MAX;
  if (opts.stage3 && inGreyBand) {
    const stage3Input: Stage3Input = {
      url: features.url,
      etld1: pageEtld1 ?? features.etld1 ?? "",
      title: features.title,
      textSample: features.visibleTextSample,
      ruleSignals: signals.map((s) => ({ id: s.id, weight: s.weight, detail: s.detail }))
    };
    const r = await opts.stage3(stage3Input);
    backend = r.backend;

    if (r.result) {
      stagesRan.push("stage3");
      const categoryStr = r.result.category.join("+");
      // LLM contributes one informational signal per reason; weight=0 because
      // we use MAX(rules, llm) for the final score (LLM can escalate but not
      // de-escalate).
      for (const reason of r.result.reasons) {
        signals.push({
          id: `llm.${r.result.category[0] ?? "other"}`,
          stage: "stage3",
          weight: 0,
          detail: reason
        });
      }
      // Surface the LLM's own score as a single weight-bearing signal so the
      // UI can show the contribution explicitly.
      signals.push({
        id: "llm.score",
        stage: "stage3",
        weight: r.result.riskScore,
        detail: `LLM (${backend}) risk_score=${r.result.riskScore}, verdict=${r.result.verdict}, category=${categoryStr}`
      });
      total = Math.max(total, r.result.riskScore);
    } else if (r.error) {
      signals.push({
        id: "llm.unavailable",
        stage: "stage3",
        weight: 0,
        detail: r.error
      });
    }
  }

  return finalize({ signals, score: total, stagesRan, t0, backend });
}

// ---- Small helper to keep the result shape consistent across exits -------

interface FinalizeArgs {
  signals: Signal[];
  score: number;
  stagesRan: StageId[];
  t0: number;
  backend: LLMBackend;
}

function finalize({ signals, score, stagesRan, t0, backend }: FinalizeArgs): ClassifyResult {
  const verdict: ClassifyResult["verdict"] =
    score >= DANGER_FLOOR
      ? "dangerous"
      : score < SAFE_CEILING
      ? "safe"
      : score >= 50
      ? "suspicious"
      : "caution";

  return {
    verdict,
    riskScore: Math.round(score),
    signals,
    reasons: signals.map((s) => s.detail ?? s.id),
    backend,
    latencyMs: performance.now() - t0,
    stagesRan
  };
}
