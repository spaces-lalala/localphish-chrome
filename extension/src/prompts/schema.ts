// Zod schema for the strict JSON the LLM must emit on Stage 3.
// Plan §7: chain-of-thought is allowed but invisible; only the JSON object is parsed.

import { z } from "zod";

import type { Stage3Output } from "@/types";

export const Stage3OutputSchema = z.object({
  risk_score: z.number().int().min(0).max(100),
  verdict: z.enum(["safe", "caution", "suspicious", "dangerous"]),
  category: z.string().min(1).max(40),
  reasons: z.array(z.string().min(1).max(220)).max(6),
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

export function parseStage3Output(raw: string): Stage3Output | null {
  const json = extractJsonObject(raw);
  if (!json) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  const result = Stage3OutputSchema.safeParse(parsed);
  if (!result.success) return null;
  const v = result.data;
  return {
    riskScore: v.risk_score,
    verdict: v.verdict,
    category: v.category,
    reasons: v.reasons,
    needVisual: v.need_visual ?? false
  };
}
