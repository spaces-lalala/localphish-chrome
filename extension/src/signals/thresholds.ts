// Verdict thresholds — single source of truth.
//
// Both Stage 1 orchestrator (stage1.ts) and the cascade finalizer
// (cascade.ts, stage2.ts:verdictFromScore) used to hard-code these
// numbers separately. Any future tuning needs to bump both in lockstep
// or the Stage-1 short-circuit decision will disagree with the final
// verdict mapping. Re-export from one place to prevent drift.

/** rawScore < SAFE_CEILING → "safe" verdict (Stage 1 short-circuits if no other stage runs). */
export const SAFE_CEILING = 15;
/** rawScore ≥ DANGER_FLOOR → "dangerous" verdict; Stage 1 short-circuits, downstream stages skipped. */
export const DANGER_FLOOR = 85;
/** SUSPICIOUS_FLOOR ≤ rawScore < DANGER_FLOOR → "suspicious"; otherwise "caution". */
export const SUSPICIOUS_FLOOR = 50;

/** Grey-band bounds for Stage 3 LLM gating (inclusive). Outside this range
 *  the cascade has enough rule-layer confidence not to need the LLM. */
export const STAGE3_GREY_MIN = 15;
export const STAGE3_GREY_MAX = 84;
