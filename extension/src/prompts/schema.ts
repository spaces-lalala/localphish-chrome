// Zod schema for the strict JSON the LLM must emit on Stage 3.
// Plan §7: chain-of-thought is allowed but invisible; only the JSON object is parsed.

import { z } from "zod";

import type { Stage3Output } from "@/types";

// Accept both forms: v1 uses string, v2 (Taiwan-localized) uses string[].
// We normalize to string[] downstream so callers don't care which prompt fired.
const CategoryField = z.union([
  z.string().min(1).max(40).transform((s) => [s]),
  z.array(z.string().min(1).max(40)).min(1).max(4)
]);

export const Stage3OutputSchema = z.object({
  risk_score: z.number().int().min(0).max(100),
  verdict: z.enum(["safe", "caution", "suspicious", "dangerous"]),
  category: CategoryField,
  // reasons[] is OPTIONAL — Nano sometimes truncates inside the category array
  // before reaching reasons. We'd rather recover the verdict + category from
  // a half-output than fail the whole parse. The cascade will fill a synthetic
  // "LLM output was truncated" reason downstream when this happens.
  reasons: z.array(z.string().min(1).max(220)).max(8).optional().default([]),
  need_visual: z.boolean().optional().default(false)
});

export type Stage3OutputRaw = z.infer<typeof Stage3OutputSchema>;

/** Pull the first balanced top-level JSON object out of free-form model text.
 *  Tolerates models that prepend "Here's the JSON:" or wrap with ```json fences. */
export function extractJsonObject(s: string): string | null {
  const fenceStripped = s.replace(/```(?:json)?\s*/gi, "").replace(/```/g, "");
  const start = fenceStripped.indexOf("{");
  if (start < 0) return null;

  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < fenceStripped.length; i++) {
    const c = fenceStripped[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return fenceStripped.slice(start, i + 1);
    }
  }
  return null;
}

/** Last-resort JSON repair for models that truncate their own output mid-token.
 *  Walks from the first `{`, tracks open string/array/object state, and on
 *  reaching the end of input closes whatever was left open. If the truncation
 *  happened mid-element, we also drop the trailing partial element so the
 *  closing brace lands on a valid position.
 *
 *  Nano under the v2 prompt sometimes emits e.g.
 *    `{"risk_score": 95, ..., "reasons": ["A", "B`
 *  and cuts off mid-string. The repair becomes
 *    `{"risk_score": 95, ..., "reasons": ["A"]}`
 *  which loses partial reason B but preserves everything before it. */
export function repairTruncatedJson(s: string): string | null {
  const fenceStripped = s.replace(/```(?:json)?\s*/gi, "").replace(/```/g, "");
  const start = fenceStripped.indexOf("{");
  if (start < 0) return null;

  let depth = 0;
  let inStr = false;
  let esc = false;
  // Stack of open containers as `{` or `[`, with the byte offset of the most
  // recent comma seen at that depth — we use it to truncate to the last
  // complete element if we end up inside a half-written one.
  const stack: { kind: "{" | "["; lastCommaIdx: number }[] = [];
  let safeEnd = -1; // index of the last position known to be at the top of a balanced state

  for (let i = start; i < fenceStripped.length; i++) {
    const c = fenceStripped[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === "{") { stack.push({ kind: "{", lastCommaIdx: -1 }); depth++; continue; }
    if (c === "[") { stack.push({ kind: "[", lastCommaIdx: -1 }); depth++; continue; }
    if (c === "}") {
      stack.pop();
      depth--;
      if (depth === 0) { safeEnd = i; break; }
      continue;
    }
    if (c === "]") {
      stack.pop();
      depth--;
      continue;
    }
    if (c === "," && stack.length > 0) {
      stack[stack.length - 1].lastCommaIdx = i;
    }
  }

  // Already balanced — caller didn't need repair, but return it anyway.
  if (safeEnd >= 0) return fenceStripped.slice(start, safeEnd + 1);
  if (stack.length === 0) return null;

  // Truncated. Walk from the deepest open container, trimming half-written
  // elements back to the last comma we observed at that depth, then close.
  let cut = fenceStripped.length;
  // If we ended inside a string, the partial element is incomplete; back up to
  // the most recent comma in the innermost container (if any) — otherwise back
  // up to the container open itself, leaving an empty list.
  if (inStr) {
    const inner = stack[stack.length - 1];
    cut = inner.lastCommaIdx > 0 ? inner.lastCommaIdx : findOpenOf(fenceStripped, stack, start) + 1;
  } else {
    // Check whether the byte right before cut looks like a half-written element
    // (e.g. unfinished number or bare word). If we're sitting after a comma
    // already, nothing to trim. Otherwise back up to last comma at this depth.
    const tail = fenceStripped.slice(0, cut).trimEnd();
    if (tail.length > 0 && tail[tail.length - 1] !== "," && tail[tail.length - 1] !== "{" && tail[tail.length - 1] !== "[") {
      const inner = stack[stack.length - 1];
      if (inner.lastCommaIdx > 0) cut = inner.lastCommaIdx;
    }
  }

  let repaired = fenceStripped.slice(start, cut);
  // Append closing tokens in stack-order (innermost first).
  for (let i = stack.length - 1; i >= 0; i--) {
    repaired += stack[i].kind === "{" ? "}" : "]";
  }
  return repaired;
}

function findOpenOf(s: string, stack: { kind: "{" | "[" }[], start: number): number {
  // Best-effort: find index of nth-deepest open bracket — used only for the
  // degenerate "no commas observed in container" case.
  let depth = 0;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (c === "{" || c === "[") {
      if (depth === stack.length - 1) return i;
      depth++;
    } else if (c === "}" || c === "]") {
      depth--;
    }
  }
  return start;
}

export function parseStage3Output(raw: string): Stage3Output | null {
  // Try the strict-balanced extractor first. If that fails (Nano truncation),
  // fall back to the repair pass that closes dangling braces/brackets.
  const candidates: (string | null)[] = [extractJsonObject(raw), repairTruncatedJson(raw)];

  for (const json of candidates) {
    if (!json) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      continue;
    }
    const result = Stage3OutputSchema.safeParse(parsed);
    if (!result.success) continue;
    const v = result.data;
    // If reasons[] came back empty (truncated mid-output), surface a synthetic
    // marker so the UI shows the user the model did decide, just lost the
    // explanation. The verdict + category are the load-bearing fields.
    const reasons = v.reasons.length > 0
      ? v.reasons
      : ["LLM verdict + category recovered; reasons truncated mid-output"];
    return {
      riskScore: v.risk_score,
      verdict: v.verdict,
      category: v.category,
      reasons,
      needVisual: v.need_visual ?? false
    };
  }
  return null;
}
