// WebLLM backend — Qwen 2.5-1.5B-Instruct (q4f16) via @mlc-ai/web-llm.
//
// Lives inside the Offscreen Document, which is the only context with both
// a persistent lifetime and WebGPU access (plan §3.5). On first init():
//   1. Probe navigator.gpu + request adapter — bail cleanly if absent.
//   2. CreateMLCEngine downloads the model (~1.2 GB) on first run; cached
//      in the document's IndexedDB on subsequent loads.
//   3. Engine instance is held for the document's lifetime.
//
// Unlike Nano:
//   - No outputLanguage attestation. Qwen happily outputs 繁中.
//   - max_tokens is configurable, so we don't have to hand-write truncated-
//     JSON repair (though repairTruncatedJson() still runs as belt-and-braces).
//   - Cold start is heavy (5–20 s depending on whether the model is cached).
//     The probe completes WITHOUT loading the model so the popup's backend
//     indicator can show "webllm" immediately and `run()` triggers the load.

import * as webllm from "@mlc-ai/web-llm";

import type { LLMBackendImpl, ProbeResult, LLMRunOptions } from "./backend";

// Default Pro model: Qwen 2.5-0.5B-Instruct (q4f16). Originally we planned
// 1.5B per plan §4.1 but on Windows hybrid graphics laptops Chromium reliably
// picks the Intel iGPU instead of the discrete GPU (crbug.com/369219127), at
// which point 1.5B inference takes 60–180+ s per call and the popup keeps
// timing out. 0.5B at the same quantization is ~270 MB, generates 2-3x
// faster, and still produces clean TC JSON output. The Week 16 report
// documents this as the empirical iGPU/dGPU tradeoff.
const MODEL_ID = "Qwen2.5-0.5B-Instruct-q4f16_1-MLC";

// Minimal WebGPU types — @types/webgpu isn't in our deps and the runtime
// shape is all we need (existence check + requestAdapter call + device.lost
// listener for context-loss recovery on laptop sleep/driver crash).
interface GPUDeviceLostInfo { reason: string; message: string }
interface GPUDeviceStub {
  lost: Promise<GPUDeviceLostInfo>;
}
interface GPUAdapterStub {
  requestDevice?: () => Promise<GPUDeviceStub>;
}
interface GPUStub {
  requestAdapter(): Promise<GPUAdapterStub | null>;
}

// Generation parameters. Qwen tolerates strict JSON better than Nano so we
// can keep the budget tight without hitting truncation. Empirically 384
// tokens is enough for the v3 schema (verdict + 3 reasons + 3 categories).
const MAX_TOKENS = 384;
const TEMPERATURE = 0;

export interface WebLLMProgress {
  /** 0.0 - 1.0 */
  progress: number;
  /** "init" | "download" | "compile" | … */
  text: string;
}

export class WebLLMBackend implements LLMBackendImpl {
  readonly id = "webllm" as const;
  ready = false;

  private engine: webllm.MLCEngine | null = null;
  private systemPrompt: string;
  private latestProgress: WebLLMProgress = { progress: 0, text: "" };
  /** True after device.lost has fired. Subsequent run() calls trigger
   *  one-shot recovery (rebuild engine + reload model) instead of throwing
   *  obscure WebGPU errors. */
  private deviceLost = false;
  private restartInFlight: Promise<void> | null = null;

  constructor(systemPrompt: string) {
    this.systemPrompt = systemPrompt;
  }

  /** Cheap synchronous getter — the offscreen RPC handler relays this to popup. */
  getProgress(): WebLLMProgress {
    return this.latestProgress;
  }

  async init(): Promise<ProbeResult> {
    // 1. WebGPU presence check. navigator.gpu exists on Chromium 113+ with
    // the right flags; in the Offscreen Document it should be available
    // out of the box on Chrome 120+.
    const gpu = (navigator as Navigator & { gpu?: GPUStub }).gpu;
    if (!gpu) {
      return { available: false, reason: "navigator.gpu unavailable in this context" };
    }
    let adapter: GPUAdapterStub | null = null;
    try {
      adapter = await gpu.requestAdapter();
    } catch (e) {
      return { available: false, reason: `navigator.gpu.requestAdapter threw: ${(e as Error).message}` };
    }
    if (!adapter) {
      return { available: false, reason: "navigator.gpu.requestAdapter returned null (no WebGPU adapter)" };
    }

    // Attach a device.lost listener. The MLCEngine owns its own device but
    // we also hold a fresh probe device to detect adapter-wide loss events
    // (driver update / Chrome sleep). When fired we flip deviceLost so the
    // next run() rebuilds the engine instead of returning stale outputs.
    try {
      const probeDevice = await adapter.requestDevice?.();
      if (probeDevice) {
        void probeDevice.lost.then((info) => {
          this.deviceLost = true;
          this.ready = false;
          console.warn(`[LocalPhish WebLLM] WebGPU device.lost: ${info.reason} — ${info.message}`);
        });
      }
    } catch {
      // requestDevice may fail on some adapter implementations — non-fatal,
      // we still rely on MLCEngine to surface its own errors.
    }

    // 2. Engine creation — does NOT load model yet, that happens at first
    // chat.completions.create call (or eagerly when we call reload()).
    // We use the lazy form: construct the engine, set progress callback,
    // then trigger reload to download/compile.
    try {
      this.engine = new webllm.MLCEngine();
      this.engine.setInitProgressCallback((report: webllm.InitProgressReport) => {
        this.latestProgress = {
          progress: report.progress,
          text: report.text
        };
        // Helpful for debugging in offscreen console without us proxying
        // every progress callback over chrome.runtime.sendMessage.
        if (report.progress === 0 || report.progress === 1) {
          console.log(`[LocalPhish WebLLM] ${report.text} (${(report.progress * 100).toFixed(0)}%)`);
        }
      });

      // Eagerly load the model. This is the long step (~1.2 GB download on
      // first run, then ~5 s reload from cache). We do it during init so
      // `ready` flips true only when the model can actually answer.
      await this.engine.reload(MODEL_ID);
      this.ready = true;
      return { available: true };
    } catch (e) {
      const msg = (e as Error).message;
      // Common failure modes worth surfacing:
      //   - WebGPU OOM ("OutOfMemoryError")
      //   - HF download blocked / network
      //   - Bundle / version mismatch
      this.engine = null;
      return {
        available: false,
        reason: `WebLLM init failed: ${msg.slice(0, 200)}`
      };
    }
  }

  async run(prompt: string, opts: LLMRunOptions = {}): Promise<string> {
    // device.lost happened since last run — try one-shot rebuild before
    // surrendering. Most laptop sleep/resume cycles fire device.lost and
    // a fresh requestAdapter immediately succeeds, so without this the
    // user would see "WebLLMBackend not initialized" until they manually
    // re-toggled the profile.
    if (this.deviceLost) {
      if (!this.restartInFlight) {
        this.restartInFlight = (async () => {
          try {
            await this.engine?.unload();
          } catch { /* ignore */ }
          this.engine = null;
          this.ready = false;
          this.deviceLost = false;
          const probe = await this.init();
          if (!probe.available) {
            throw new Error(`WebLLM restart after device.lost failed: ${probe.reason}`);
          }
        })();
      }
      try {
        await this.restartInFlight;
      } finally {
        this.restartInFlight = null;
      }
    }
    if (!this.ready || !this.engine) {
      throw new Error("WebLLMBackend not initialized");
    }
    // CRITICAL — MLCEngine maintains an internal KV cache between
    // chat.completions.create() calls. Without an explicit reset, the
    // previous page's tokens stay resident and bleed into the next
    // classification (real bug observed in the wild: classifying NTU's
    // course page right after the 國稅局 fixture produced reasons
    // referencing 國稅局 / 身分證 / 銀行卡 that don't exist on the NTU
    // page). resetChat() clears the KV cache while keeping the model
    // loaded — fast (a few ms), so we call it on every run.
    try {
      await this.engine.resetChat();
    } catch {
      // resetChat may not be available on every WebLLM version; if it
      // throws we fall through and accept the bleed risk for that one
      // call. The MLCEngine messages parameter is still the primary
      // source of context.
    }

    // 180 s budget. Empirically: warm Qwen 2.5-1.5B-Instruct on a real
    // dGPU returns in 1-3 s; on Intel iGPU (when Chromium picks the wrong
    // adapter via crbug.com/369219127) the same prompt takes 30-90 s.
    // The popup shows ANALYZING progress so the user can tell we're not
    // hung — better to wait than to abort and fall back to rules-only.
    const timeoutMs = opts.timeoutMs ?? 180_000;

    const completion = await withTimeout(
      this.engine.chat.completions.create({
        messages: [
          { role: "system", content: this.systemPrompt },
          { role: "user", content: prompt }
        ],
        temperature: TEMPERATURE,
        max_tokens: MAX_TOKENS
      }),
      timeoutMs
    );

    return completion.choices[0]?.message?.content ?? "";
  }

  async destroy(): Promise<void> {
    try {
      await this.engine?.unload();
    } catch {
      // ignore
    }
    this.engine = null;
    this.ready = false;
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`WebLLM call exceeded ${ms} ms`)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); }
    );
  });
}
