// Common contract every concrete LLM backend (Nano, WebLLM, ...) implements.
// The router selects one according to capability + user preference, the cascade
// just sees this minimal surface.

import type { LLMBackend } from "@/types";

export interface ProbeResult {
  available: boolean;
  reason?: string;
}

export interface LLMRunOptions {
  /** Hard timeout for a single prompt+completion round-trip. */
  timeoutMs?: number;
}

export interface LLMBackendImpl {
  /** Stable identifier reported back to the UI. */
  readonly id: LLMBackend;
  /** Becomes true after a successful `init()`. */
  ready: boolean;

  /** Probe + initialize the underlying engine. Idempotent. */
  init(): Promise<ProbeResult>;

  /** Run a single prompt, return the raw model completion as text. */
  run(prompt: string, opts?: LLMRunOptions): Promise<string>;

  /** Best-effort teardown; safe to call when the engine was never created. */
  destroy?(): Promise<void>;
}
