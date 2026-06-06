// Chrome built-in Prompt API ("Gemini Nano") wrapper.
//
// The surface has thrashed during origin trials:
//   - older Chrome (≤126): window.ai.assistant.{capabilities, create}
//   - mid Chrome (127–137): window.ai.languageModel.{capabilities, create}
//   - newer Chrome (138+):  global LanguageModel.{availability, create}
//
// We probe each surface in order and adapt. Plan §3.6 demands that any
// availability failure produces a clean "not ready" probe result; the extension
// must NEVER crash because Nano isn't installed.

import type { LLMBackendImpl, ProbeResult, LLMRunOptions } from "./backend";
import { buildTwNanoSystemPrompt } from "@/prompts/phishing_v2_tw_nano";

// Loose duck-typed shapes — the API is unstable enough that we can't depend on
// a single set of TS declarations. Each surface is detected at runtime.

interface NanoSessionModern {
  prompt(
    text: string,
    opts?: { outputLanguage?: string; language?: string }
  ): Promise<string>;
  destroy?(): void;
  /** Chrome 138+: branch a fresh session that shares the parent's pre-tokenised
   *  system prompt but has empty user-turn history. Cheap (~50–100 ms). */
  clone?(): Promise<NanoSessionModern>;
}

type LanguageHint = { type: "text"; languages: string[] };

interface LanguageHintBag {
  expectedInputs?: LanguageHint[];
  expectedOutputs?: LanguageHint[];
}

interface LanguageModelGlobal {
  availability?(opts?: LanguageHintBag): Promise<string>;
  capabilities?(opts?: LanguageHintBag): Promise<{ available?: string }>;
  create(opts: LanguageHintBag & {
    temperature?: number;
    topK?: number;
    initialPrompts?: Array<{ role: "system" | "user"; content: string }>;
    systemPrompt?: string;
    /** Required in some Chrome ≥ M138 builds as an alternative spelling. */
    outputLanguage?: string;
  }): Promise<NanoSessionModern>;
}

interface OldNanoNamespace {
  languageModel?: LanguageModelGlobal;
  assistant?: LanguageModelGlobal;
}

interface NanoGlobal {
  ai?: OldNanoNamespace;
  LanguageModel?: LanguageModelGlobal;
}

function getApis(): { modern?: LanguageModelGlobal; old?: LanguageModelGlobal } {
  const g = globalThis as unknown as NanoGlobal;
  return {
    modern: g.LanguageModel,
    old: g.ai?.languageModel ?? g.ai?.assistant
  };
}

function isAvailable(status: string): boolean {
  // Spec values across versions: "available" | "readily" | "after-download" |
  // "downloadable" | "downloading" | "no" | "unavailable".
  return ["available", "readily", "after-download", "downloadable", "downloading"].includes(status);
}

export class NanoBackend implements LLMBackendImpl {
  readonly id = "nano" as const;
  ready = false;

  private session: NanoSessionModern | null = null;
  private api: LanguageModelGlobal | null = null;
  private apiKind: "modern" | "old" | null = null;

  async init(): Promise<ProbeResult> {
    const { modern, old } = getApis();
    // M148+ enforces language attestation on availability() too, not only
    // create() — pass the hint everywhere we touch the API.
    const langBag: LanguageHintBag = {
      expectedInputs: [{ type: "text", languages: ["en"] }],
      expectedOutputs: [{ type: "text", languages: ["en"] }]
    };

    if (modern && typeof modern.availability === "function") {
      try {
        const status = await modern.availability(langBag);
        if (!isAvailable(status)) {
          return { available: false, reason: `LanguageModel.availability()=${status}` };
        }
        this.api = modern;
        this.apiKind = "modern";
      } catch (e) {
        return { available: false, reason: `LanguageModel.availability() threw: ${(e as Error).message}` };
      }
    } else if (old && typeof old.capabilities === "function") {
      try {
        const caps = await old.capabilities(langBag);
        const status = caps?.available ?? "no";
        if (!isAvailable(status)) {
          return { available: false, reason: `ai.languageModel.capabilities().available=${status}` };
        }
        this.api = old;
        this.apiKind = "old";
      } catch (e) {
        return { available: false, reason: `ai.languageModel.capabilities() threw: ${(e as Error).message}` };
      }
    } else {
      return { available: false, reason: "no built-in LanguageModel API found in this Chrome" };
    }

    // Lazy-create the session on first run() — `create()` triggers the model
    // download on machines where availability=after-download, and we don't
    // want to pay that on probe.
    this.ready = true;
    return { available: true };
  }

  async run(prompt: string, opts: LLMRunOptions = {}): Promise<string> {
    if (!this.ready || !this.api) {
      throw new Error("NanoBackend not initialized");
    }
    if (!this.session) {
      this.session = await this.createSession();
    }

    // CRITICAL — Chrome Prompt API sessions are multi-turn by design: every
    // session.prompt() call appends to the conversation history, so reusing
    // one session across pages would feed Page A's content + verdict back
    // into Page B's classification (real bug observed in the wild: NTU
    // coursework page was classified as 國稅局 phishing right after the
    // user had just visited the ntbsa-tax-refund fixture).
    // Fix: clone() before each call. clone() shares the parent's pre-
    // tokenised system prompt + few-shot example so it's cheap (~50–100 ms),
    // and the clone has empty user-turn history. Destroy the clone in
    // `finally` so its KV cache doesn't leak.
    const turnSession = await this.makeTurnSession();
    const timeoutMs = opts.timeoutMs ?? 25_000;
    try {
      // Some Chrome M138/M139 builds still demand a language hint at prompt()
      // time even when the session declared it; pass it again as belt-and-
      // braces. Extras are ignored by versions that don't care.
      return await withTimeout(
        turnSession.prompt(prompt, { outputLanguage: "en", language: "en" }),
        timeoutMs
      );
    } finally {
      if (turnSession !== this.session) {
        try {
          turnSession.destroy?.();
        } catch {
          // best-effort cleanup
        }
      }
    }
  }

  /** Return a per-classification session with fresh history. Prefers clone()
   *  for speed; falls back to the shared session on older Chrome that
   *  doesn't expose clone() — accepts the bleed-over risk in that case
   *  rather than paying 1–3 s for a fresh create(). */
  private async makeTurnSession(): Promise<NanoSessionModern> {
    if (!this.session) throw new Error("session not initialized");
    if (typeof this.session.clone === "function") {
      try {
        return await this.session.clone();
      } catch {
        // fall through
      }
    }
    return this.session;
  }

  async destroy(): Promise<void> {
    try {
      this.session?.destroy?.();
    } catch {
      // ignore
    }
    this.session = null;
    this.ready = false;
  }

  private async createSession(): Promise<NanoSessionModern> {
    if (!this.api) throw new Error("api missing");
    const sys = buildTwNanoSystemPrompt();

    // The prompt and our expected JSON output are both English; declare so
    // explicitly. Chrome ≥ M138 requires this — the model errors out otherwise.
    const langHint: LanguageHint[] = [{ type: "text", languages: ["en"] }];

    if (this.apiKind === "modern") {
      return await this.api.create({
        temperature: 0,
        topK: 1,
        initialPrompts: [{ role: "system", content: sys }],
        outputLanguage: "en",
        expectedInputs: langHint,
        expectedOutputs: langHint
      });
    }
    // older API takes systemPrompt directly.
    return await this.api.create({
      temperature: 0,
      topK: 1,
      systemPrompt: sys,
      outputLanguage: "en",
      expectedInputs: langHint,
      expectedOutputs: langHint
    });
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`LLM call exceeded ${ms} ms`)), ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); }
    );
  });
}
