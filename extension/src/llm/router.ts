// LLM router — picks a concrete backend and runs Stage 3 classification.
//
// Plan §3.6 三層降級鏈:
//   Auto: WebGPU? → WebLLM. Else Nano? → Nano. Else rules-only.
//   Pro:  force WebLLM. On failure → Nano. On failure → rules-only.
//   Lite: force Nano. On failure → rules-only. (don't auto-download 1 GB WebLLM)
//
// This first cut only ships Nano; WebLLM lands in a follow-up commit. The
// interface is already shaped to absorb it without further refactor.

import type { LLMBackend, Stage3Input, Stage3Output } from "@/types";

import type { LLMBackendImpl } from "./backend";
import { NanoBackend } from "./nano";
import {
  buildTwNanoUserPrompt,
  buildTwNanoRetryPrompt
} from "@/prompts/phishing_v2_tw_nano";
import { parseStage3Output } from "@/prompts/schema";

export type Profile = "auto" | "pro" | "lite";

export interface RouterState {
  backend: LLMBackend;
  ready: boolean;
  reason?: string;
}

export class LLMRouter {
  private nano: NanoBackend | null = null;
  private state: RouterState = { backend: "rules-only", ready: false };

  constructor(private profile: Profile = "auto") {}

  async init(): Promise<RouterState> {
    // Lite or auto: try Nano. (Pro/WebLLM lands later.)
    if (this.profile === "lite" || this.profile === "auto") {
      const n = new NanoBackend();
      const probe = await n.init();
      if (probe.available) {
        this.nano = n;
        this.state = { backend: "nano", ready: true };
        return this.state;
      }
      this.state = { backend: "rules-only", ready: false, reason: probe.reason };
      return this.state;
    }

    // profile === "pro": WebLLM not yet implemented in this commit.
    this.state = {
      backend: "rules-only",
      ready: false,
      reason: "WebLLM (Pro profile) not yet wired up; install Nano or wait for the next release."
    };
    return this.state;
  }

  getState(): RouterState {
    return this.state;
  }

  /**
   * @returns null when the LLM is unavailable, the response is malformed
   *          twice in a row, or the call times out. Callers MUST treat null
   *          as "no Stage 3 signal" and fall back to rule-layer results.
   */
  async stage3Classify(
    input: Stage3Input
  ): Promise<{ result: Stage3Output | null; backend: LLMBackend; latencyMs: number; error?: string }> {
    const t0 = performance.now();
    const backend = this.activeBackend();
    if (!backend) {
      return {
        result: null,
        backend: "rules-only",
        latencyMs: 0,
        error: this.state.reason ?? "no LLM backend available"
      };
    }

    const userPrompt = buildTwNanoUserPrompt(input);

    let raw: string;
    try {
      raw = await backend.run(userPrompt);
    } catch (e) {
      return {
        result: null,
        backend: backend.id,
        latencyMs: performance.now() - t0,
        error: `first prompt failed: ${(e as Error).message}`
      };
    }

    let parsed = parseStage3Output(raw);
    if (parsed) {
      return { result: parsed, backend: backend.id, latencyMs: performance.now() - t0 };
    }

    // Retry once with a corrective system message in-band.
    try {
      const retryRaw = await backend.run(buildTwNanoRetryPrompt(raw));
      parsed = parseStage3Output(retryRaw);
      if (parsed) {
        return { result: parsed, backend: backend.id, latencyMs: performance.now() - t0 };
      }
    } catch (e) {
      return {
        result: null,
        backend: backend.id,
        latencyMs: performance.now() - t0,
        error: `retry failed: ${(e as Error).message}`
      };
    }

    return {
      result: null,
      backend: backend.id,
      latencyMs: performance.now() - t0,
      error: "LLM returned non-JSON twice"
    };
  }

  private activeBackend(): LLMBackendImpl | null {
    if (this.nano?.ready) return this.nano;
    return null;
  }
}
