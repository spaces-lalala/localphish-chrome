// Cross-tab inference queue + active-tab priority + stale cancellation.
//
// Problem (review §10 條 18): the WebLLM engine in the Offscreen Document
// serializes one generation at a time. With multiple tabs open, the SW used
// to fire callStage3 concurrently — but the offscreen RPC serialized them
// anyway, so a foreground tab could end up waiting behind 30-90 s of
// background-tab inference on the user's iGPU.
//
// This queue enforces:
//   1. Only one in-flight Stage 3 inference at a time (matches the engine).
//   2. Pending requests for the SAME tab are coalesced — a fresh navigation
//      cancels the previous request for that tab (it's about to be obsolete
//      anyway).
//   3. Active-tab priority — if the user switches tabs while a background-
//      tab inference is queued, the active-tab request jumps the queue.
//   4. Inflight requests can be cancelled when the user closes the tab or
//      navigates away. We don't have a real "cancel" hook into WebLLM (its
//      chat.completions.create() is unstoppable mid-stream), so we mark the
//      result as cancelled and DROP it on arrival — the inference still
//      completes on the GPU, just the result is discarded so it doesn't
//      pollute the verdict cache.
//
// Caveat we surface in the report: WebLLM cannot truly cancel a generation
// in flight. The queue prevents NEW backgrounded requests from blocking the
// active tab, but a generation already started will finish (just be ignored
// when it returns). For Qwen 0.5B on dGPU this is fine; for iGPU Qwen 1.5B
// it's the visible bottleneck.

import type {
  ClassifyResult,
  LLMBackend,
  Stage3Input,
  Stage3Output,
} from "@/types";

export interface QueuedRequest {
  tabId: number;
  /** Monotonically increasing seq used for cancellation: any earlier seq
   *  for the same tab is dropped on arrival. */
  seq: number;
  input: Stage3Input;
  /** Resolves with the Stage 3 result. Resolves with null when the request
   *  was superseded by a later one for the same tab. */
  resolve: (r: {
    result: Stage3Output | null;
    backend: LLMBackend;
    latencyMs: number;
    error?: string;
    cancelled?: boolean;
  }) => void;
}

type Stage3Caller = (
  input: Stage3Input
) => Promise<{ result: Stage3Output | null; backend: LLMBackend; latencyMs: number; error?: string }>;

export class InferenceQueue {
  private pending: QueuedRequest[] = [];
  private activeTabId: number | null = null;
  private running = false;
  /** Per-tab generation counter — every enqueue bumps the tab's counter, so
   *  the queue knows which earlier requests are stale. */
  private tabSeq: Map<number, number> = new Map();
  /** Latest accepted result per tab (so we can drop late-arriving stale
   *  results in the resolver). */
  private latestSeqResolvedFor: Map<number, number> = new Map();

  constructor(private caller: Stage3Caller) {}

  setActiveTab(tabId: number | null): void {
    this.activeTabId = tabId;
    // Re-prioritize the queue if a queued active-tab request exists.
    this.reorder();
  }

  /** Drop every request for a tab — used on chrome.tabs.onRemoved and on
   *  chrome.tabs.onUpdated when the URL changes (the previous URL's verdict
   *  is no longer wanted). Bumps tabSeq so any IN-FLIGHT request for this
   *  tab will be discarded on arrival (we can't actually stop WebLLM
   *  mid-generation, but we drop the result on the floor). */
  cancelTab(tabId: number): void {
    const removed = this.pending.filter((r) => r.tabId === tabId);
    this.pending = this.pending.filter((r) => r.tabId !== tabId);
    for (const r of removed) {
      r.resolve({ result: null, backend: "rules-only", latencyMs: 0, cancelled: true });
    }
    // Bump seq — must NOT delete the entry, or the runOne arrival check
    // (`latestSeq > req.seq`) collapses to `0 > req.seq` which is false
    // and the stale result would slip through. Keeping the bumped value
    // is what makes "result discarded on arrival" actually work.
    const bumped = (this.tabSeq.get(tabId) ?? 0) + 1;
    this.tabSeq.set(tabId, bumped);
  }

  enqueue(tabId: number, input: Stage3Input): Promise<{
    result: Stage3Output | null;
    backend: LLMBackend;
    latencyMs: number;
    error?: string;
    cancelled?: boolean;
  }> {
    // Bump seq; any earlier request for the same tab still in queue is
    // dropped (its work is obsolete).
    const seq = (this.tabSeq.get(tabId) ?? 0) + 1;
    this.tabSeq.set(tabId, seq);

    // Coalesce: drop any earlier pending request for the same tab.
    const dropped: QueuedRequest[] = [];
    this.pending = this.pending.filter((r) => {
      if (r.tabId === tabId) {
        dropped.push(r);
        return false;
      }
      return true;
    });
    for (const r of dropped) {
      r.resolve({ result: null, backend: "rules-only", latencyMs: 0, cancelled: true });
    }

    return new Promise((resolve) => {
      this.pending.push({ tabId, seq, input, resolve });
      this.reorder();
      this.tick();
    });
  }

  private reorder(): void {
    if (this.activeTabId == null) return;
    const active: QueuedRequest[] = [];
    const others: QueuedRequest[] = [];
    for (const r of this.pending) {
      (r.tabId === this.activeTabId ? active : others).push(r);
    }
    this.pending = [...active, ...others];
  }

  private tick(): void {
    if (this.running) return;
    const next = this.pending.shift();
    if (!next) return;
    this.running = true;
    void this.runOne(next).finally(() => {
      this.running = false;
      // Drain anything that piled up while we were waiting.
      this.tick();
    });
  }

  private async runOne(req: QueuedRequest): Promise<void> {
    try {
      const r = await this.caller(req.input);
      // Stale-arrival check: if a newer seq for this tab has been enqueued
      // since we started, the user has moved on. Discard.
      const latestSeq = this.tabSeq.get(req.tabId) ?? 0;
      if (latestSeq > req.seq) {
        req.resolve({ result: null, backend: r.backend, latencyMs: r.latencyMs, cancelled: true });
        return;
      }
      this.latestSeqResolvedFor.set(req.tabId, req.seq);
      req.resolve(r);
    } catch (err) {
      req.resolve({
        result: null,
        backend: "rules-only",
        latencyMs: 0,
        error: `inference queue: ${(err as Error).message}`,
      });
    }
  }

  /** Useful for telemetry / debugging via the popup. */
  describe(): { pending: number; active_tab: number | null; running: boolean } {
    return { pending: this.pending.length, active_tab: this.activeTabId, running: this.running };
  }
}

/** Convenience for the test suite. */
export function makeQueue(caller: Stage3Caller): InferenceQueue {
  return new InferenceQueue(caller);
}

/** Helper: same shape as ClassifyResult.signals union when we need to
 *  embed a cancellation marker in the cascade output. */
export const CANCELLED_RESULT: Partial<ClassifyResult> = {
  reasons: ["LocalPhish: classification cancelled (tab navigated away)"],
  riskScore: 0,
};
