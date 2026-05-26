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
import { buildNanoSystemPrompt } from "@/prompts/phishing_v1_nano";

// Loose duck-typed shapes — the API is unstable enough that we can't depend on
// a single set of TS declarations. Each surface is detected at runtime.

interface NanoSessionModern {
  prompt(text: string): Promise<string>;
  destroy?(): void;
}

interface LanguageModelGlobal {
  availability?(): Promise<string>;
  capabilities?(): Promise<{ available?: string }>;
  create(opts: {
    temperature?: number;
    topK?: number;
    initialPrompts?: Array<{ role: "system" | "user"; content: string }>;
    systemPrompt?: string;
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

    if (modern && typeof modern.availability === "function") {
      try {
        const status = await modern.availability();
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
        const caps = await old.capabilities();
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

    const timeoutMs = opts.timeoutMs ?? 15_000;
    return await withTimeout(this.session.prompt(prompt), timeoutMs);
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
    const sys = buildNanoSystemPrompt();

    if (this.apiKind === "modern") {
      return await this.api.create({
        temperature: 0,
        topK: 1,
        initialPrompts: [{ role: "system", content: sys }]
      });
    }
    // older API takes systemPrompt directly.
    return await this.api.create({
      temperature: 0,
      topK: 1,
      systemPrompt: sys
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
