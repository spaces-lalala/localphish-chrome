// LLM router — picks a concrete backend and runs Stage 3 classification.
//
// Plan §3.6 fallback chain:
//   Auto: WebGPU? → WebLLM. Else Nano? → Nano. Else rules-only.
//   Pro:  force WebLLM. On failure → Nano. On failure → rules-only.
//   Lite: force Nano. On failure → rules-only. (don't auto-download 1 GB WebLLM)
//
// Per-profile, per-backend prompt selection:
//   Nano  → phishing_v2_tw_nano (English-only output, attestation hell)
//   WebLLM→ phishing_v3_qwen   (繁中 native output, max_tokens controllable)

import type { LLMBackend, Stage3Input, Stage3Output } from "@/types";

import type { LLMBackendImpl } from "./backend";
import { NanoBackend } from "./nano";
import { WebLLMBackend } from "./webllm";
import {
  buildTwNanoUserPrompt,
  buildTwNanoRetryPrompt
} from "@/prompts/phishing_v2_tw_nano";
import {
  buildQwenSystemPrompt,
  buildQwenUserPrompt,
  buildQwenRetryPrompt
} from "@/prompts/phishing_v3_qwen";
import { parseStage3Output } from "@/prompts/schema";

export type Profile = "auto" | "pro" | "lite";

export interface RouterState {
  backend: LLMBackend;
  ready: boolean;
  reason?: string;
  /** WebLLM only — present during model download / compile. */
  progress?: { progress: number; text: string };
}

export class LLMRouter {
  private nano: NanoBackend | null = null;
  private webllm: WebLLMBackend | null = null;
  private state: RouterState = { backend: "rules-only", ready: false };

  constructor(private profile: Profile = "auto") {}

  setProfile(p: Profile): void {
    this.profile = p;
  }

  /** Tear down all backends. Called when the offscreen document is told to
   *  swap profiles — releases WebGPU buffers, terminates the WebLLM worker,
   *  and clears any Nano session so the new router starts from a known state. */
  async destroy(): Promise<void> {
    const tasks: Promise<void>[] = [];
    if (this.webllm) tasks.push(this.webllm.destroy().catch(() => undefined));
    if (this.nano) tasks.push(this.nano.destroy().catch(() => undefined));
    await Promise.all(tasks);
    this.webllm = null;
    this.nano = null;
    this.state = { backend: "rules-only", ready: false };
  }

  /** Surfacing WebLLM's progress so the offscreen handler can echo it
   *  back to popup polls during a 1.2 GB download. */
  getDownloadProgress(): { progress: number; text: string } | null {
    return this.webllm?.getProgress() ?? null;
  }

  async init(): Promise<RouterState> {
    // Reset between profile swaps. Destroy any backend not used by the new profile.
    if (this.profile === "lite" && this.webllm) {
      void this.webllm.destroy();
      this.webllm = null;
    }

    // ---- Profile: pro ---------------------------------------------------
    if (this.profile === "pro") {
      const w = new WebLLMBackend(buildQwenSystemPrompt());
      const probe = await w.init();
      if (probe.available) {
        this.webllm = w;
        this.state = { backend: "webllm", ready: true };
        return this.state;
      }
      // Fall through to Nano as best-effort second-best.
      const n = new NanoBackend();
      const np = await n.init();
      if (np.available) {
        this.nano = n;
        this.state = {
          backend: "nano",
          ready: true,
          reason: `WebLLM unavailable (${probe.reason}); fell back to Nano`
        };
        return this.state;
      }
      this.state = {
        backend: "rules-only",
        ready: false,
        reason: `WebLLM unavailable (${probe.reason}); Nano also unavailable (${np.reason})`
      };
      return this.state;
    }

    // ---- Profile: lite --------------------------------------------------
    if (this.profile === "lite") {
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

    // ---- Profile: auto --------------------------------------------------
    // Auto picks WebLLM only if WebGPU is present AND the user previously
    // committed to a Pro download. We probe Nano first because it's a
    // no-cost capability check; only escalate to WebLLM if Nano is
    // unavailable. This avoids surprising the user with a 1.2 GB download
    // on a fresh install. The Options page's explicit "Pro" toggle is the
    // sanctioned way to trigger WebLLM.
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

    // Different backends, different prompts. Nano gets the constrained
    // English-only prompt; WebLLM (Qwen) gets the prompt that allows native
    // 繁中 output.
    const buildUser = backend.id === "webllm" ? buildQwenUserPrompt : buildTwNanoUserPrompt;
    const buildRetry = backend.id === "webllm" ? buildQwenRetryPrompt : buildTwNanoRetryPrompt;
    const userPrompt = buildUser(input);

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
    let retryRaw = "";
    try {
      retryRaw = await backend.run(buildRetry(raw));
      parsed = parseStage3Output(retryRaw);
      if (parsed) {
        return { result: parsed, backend: backend.id, latencyMs: performance.now() - t0 };
      }
    } catch (e) {
      // Surface both the first attempt's raw text and the retry exception so we
      // can tell from the offscreen console whether Nano went silent, blurted
      // Chinese, or just emitted broken JSON.
      console.warn("[LocalPhish] Nano retry threw. First raw output was:", raw);
      return {
        result: null,
        backend: backend.id,
        latencyMs: performance.now() - t0,
        error: `retry failed: ${(e as Error).message} | first 200 chars: ${snippet(raw)}`
      };
    }

    console.warn(
      "[LocalPhish] Nano returned non-JSON twice. First:",
      raw,
      "\nRetry:",
      retryRaw
    );
    return {
      result: null,
      backend: backend.id,
      latencyMs: performance.now() - t0,
      error: `LLM returned non-JSON twice. first[0..120]="${snippet(raw, 120)}" retry[0..120]="${snippet(retryRaw, 120)}"`
    };
  }

  private activeBackend(): LLMBackendImpl | null {
    // Prefer WebLLM when ready (Pro profile and Auto-with-webllm-promoted).
    if (this.webllm?.ready) return this.webllm;
    if (this.nano?.ready) return this.nano;
    return null;
  }
}

function snippet(s: string, n = 200): string {
  if (!s) return "(empty)";
  const clipped = s.slice(0, n).replace(/\s+/g, " ").trim();
  return clipped.length < s.length ? `${clipped}…` : clipped;
}
