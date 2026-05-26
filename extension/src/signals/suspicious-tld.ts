// Stage 1 — TLD risk lookup. Pure JSON table; no per-page allocation.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";

export interface TldTable {
  high: { _weight: number; tlds: string[] };
  medium: { _weight: number; tlds: string[] };
  low: { _weight: number; tlds: string[] };
}

interface CompiledTldTable {
  high: { weight: number; set: Set<string> };
  medium: { weight: number; set: Set<string> };
  low: { weight: number; set: Set<string> };
}

export function compileTldTable(t: TldTable): CompiledTldTable {
  return {
    high:   { weight: t.high._weight,   set: new Set(t.high.tlds.map((s) => s.toLowerCase())) },
    medium: { weight: t.medium._weight, set: new Set(t.medium.tlds.map((s) => s.toLowerCase())) },
    low:    { weight: t.low._weight,    set: new Set(t.low.tlds.map((s) => s.toLowerCase())) }
  };
}

export function suspiciousTldSignals(p: ParsedUrl, table: CompiledTldTable): Signal[] {
  if (!p.etld1) return [];
  // Take the last label (public suffix's final segment) as the TLD bucket key.
  // For ccTLDs like ".co.uk" we still bucket by "uk"; the JSON table keys are
  // single-label so this is consistent.
  const tld = p.etld1.split(".").pop()!.toLowerCase();
  const out: Signal[] = [];

  if (table.high.set.has(tld)) {
    out.push({
      id: "url.tld_high_risk",
      stage: "stage1",
      weight: table.high.weight,
      detail: `eTLD+1 uses high-risk TLD ".${tld}"`
    });
  } else if (table.medium.set.has(tld)) {
    out.push({
      id: "url.tld_medium_risk",
      stage: "stage1",
      weight: table.medium.weight,
      detail: `eTLD+1 uses elevated-risk TLD ".${tld}"`
    });
  } else if (table.low.set.has(tld)) {
    out.push({
      id: "url.tld_low_risk",
      stage: "stage1",
      weight: table.low.weight,
      detail: `eTLD+1 uses mildly elevated-risk TLD ".${tld}"`
    });
  }
  return out;
}
