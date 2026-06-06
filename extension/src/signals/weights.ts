// Single-source weight + signal-description loader.
//
// The historical pattern was `const W_FOO = 25` inside each detector. That
// meant every weight change had to be mirrored manually in the Python eval
// port (eval/src/localphish_eval/{rules.py,dom_features.py}); drift was
// caught only after-the-fact via Tier B comparison. signal-spec.json now
// holds every weight; both sides read from it.
//
// Usage:
//   import { weight, description } from "@/signals/weights";
//   signals.push({ id: "url.ip_as_host", stage: "stage1",
//                  weight: weight("url.ip_as_host"),
//                  detail: description("url.ip_as_host") });
//
// Calling `weight()` with an unknown id throws at module-eval time so a
// typo in a detector is caught the first time the file loads, not on a
// silent zero-score in production.

import spec from "@/data/signal-spec.json";

interface SignalSpec {
  stage: "stage1" | "stage2" | "stage3" | "stage4a" | "stage4b";
  weight: number;
  description: string;
}

const SIGNALS = (spec as { signals: Record<string, SignalSpec> }).signals;
const CAPS = (spec as { _caps?: Record<string, number> })._caps ?? {};

export function weight(id: string): number {
  const s = SIGNALS[id];
  if (!s) throw new Error(`signal-spec: unknown signal id "${id}"`);
  return s.weight;
}

export function description(id: string): string {
  const s = SIGNALS[id];
  if (!s) throw new Error(`signal-spec: unknown signal id "${id}"`);
  return s.description;
}

export function cap(id: string): number {
  const c = CAPS[id];
  if (c == null) throw new Error(`signal-spec: unknown cap id "${id}"`);
  return c;
}

/** Every signal id known to the spec. Used by validators to assert every
 *  emitted id was declared first. */
export function knownSignalIds(): ReadonlySet<string> {
  return new Set(Object.keys(SIGNALS));
}
