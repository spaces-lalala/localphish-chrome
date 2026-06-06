// Regression coverage for the Stage 1 + Stage 2 detectors added in
// Week 15 / Week 16. Vitest, runs against the real production modules
// (no mocking) — these are pure functions so we can call them directly.

import { describe, expect, it } from "vitest";

import { parseUrl } from "./parse-url";
import { runStage1 } from "./stage1";
import { runStage2 } from "./stage2";
import { BloomFilter, type BloomSpec, setRuntimeBloom } from "./bloom";
import { InferenceQueue } from "../background/inference-queue";
import type { LLMBackend, Stage3Input, Stage3Output } from "@/types";
import { reverseProxySignals } from "./reverse-proxy";
import { phishletSignals } from "./phishlet-fingerprint";
import {
  unicodeTrickeryUrlSignals,
  unicodeTrickeryTextSignals
} from "./unicode-trickery";
import { cloakingSignals } from "./cloaking";
import { faviconMismatchSignals } from "./favicon-mismatch";
import { buildBrandIndex } from "./typosquat";

import type { PageFeatures } from "@/types";
import brandListRaw from "@/data/brand-list.json";

const BRANDS = (brandListRaw as { brands: { name: string; domain: string; aliases: string[] }[] }).brands;
const BRAND_INDEX = buildBrandIndex(BRANDS);

function parse(url: string) {
  const p = parseUrl(url);
  if (!p) throw new Error(`unparseable: ${url}`);
  return p;
}

function emptyPageFeatures(overrides: Partial<PageFeatures> = {}): PageFeatures {
  return {
    url: "https://example.com/",
    title: "",
    pageProtocol: "https:",
    visibleTextSample: "",
    hasPasswordField: false,
    hasOtpField: false,
    hasCreditCardField: false,
    seedPhraseGridPattern: false,
    formActions: [],
    externalScriptUrls: [],
    hiddenIframeCount: 0,
    tinyElementCount: 0,
    hasAntiDebug: false,
    hasTurnstileWidget: false,
    hasHCaptchaWidget: false,
    bodyTextLength: 0,
    faviconUrl: null,
    etld1: "",
    ...overrides
  };
}

// ---- Reverse-proxy hostname fingerprint --------------------------------

describe("reverseProxySignals", () => {
  it("fires on brand FQDN embedded as subdomain prefix", () => {
    const sigs = reverseProxySignals(
      parse("https://login.microsoftonline.com.attacker.tk/oauth2/v2.0/authorize"),
      BRAND_INDEX
    );
    const ids = sigs.map((s) => s.id);
    expect(ids).toContain("url.reverse_proxy_fqdn");
  });

  it("fires on hyphen-flattened brand FQDN", () => {
    const sigs = reverseProxySignals(
      parse("https://login-microsoftonline-com.evil.xyz/login"),
      BRAND_INDEX
    );
    expect(sigs.map((s) => s.id)).toContain("url.reverse_proxy_hyphen_fqdn");
  });

  it("does NOT fire on the real Microsoft login host", () => {
    const sigs = reverseProxySignals(
      parse("https://login.microsoftonline.com/oauth2/v2.0/authorize"),
      BRAND_INDEX
    );
    expect(sigs).toHaveLength(0);
  });

  it("does NOT fire on benign sites containing 'login' label", () => {
    const sigs = reverseProxySignals(parse("https://login-help.example.org/"), BRAND_INDEX);
    expect(sigs).toHaveLength(0);
  });
});

// ---- Phishlet URL endpoint fingerprint ---------------------------------

describe("phishletSignals", () => {
  it("fires on Evilginx /login_data callback", () => {
    const sigs = phishletSignals(parse("https://random-host.zip/login_data?id=1"));
    expect(sigs.map((s) => s.id)).toContain("url.phishlet_endpoint");
  });

  it("fires on Microsoft OAuth path on non-Microsoft host", () => {
    const sigs = phishletSignals(parse("https://evil.tk/common/oauth2/v2.0/authorize?cid=x"));
    expect(sigs.map((s) => s.id)).toContain("url.phishlet_endpoint");
  });

  it("does NOT fire on the real Microsoft OAuth endpoint", () => {
    const sigs = phishletSignals(parse("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"));
    expect(sigs).toHaveLength(0);
  });

  it("does NOT fire on a legit OIDC discovery doc hosted by Okta", () => {
    const sigs = phishletSignals(parse("https://tenant.okta.com/.well-known/openid-configuration"));
    expect(sigs).toHaveLength(0);
  });
});

// ---- Unicode trickery (URL) --------------------------------------------

describe("unicodeTrickeryUrlSignals", () => {
  // NOTE: U+200B / U+202E in *hostname* gets stripped by IDNA during
  // new URL() parsing, so the detector never sees it there in practice.
  // Real-world attack surface is the path/query, where percent-encoding
  // survives — our detector decodes p.href before scanning to catch that.

  it("fires on percent-encoded zero-width in URL path", () => {
    const sigs = unicodeTrickeryUrlSignals(parse("https://example.com/login%E2%80%8B"));
    expect(sigs.map((s) => s.id)).toContain("url.zero_width_in_url");
  });

  it("fires on bidi-override character in URL path", () => {
    const sigs = unicodeTrickeryUrlSignals(parse("https://example.tk/file‮exe.pdf"));
    expect(sigs.map((s) => s.id)).toContain("url.bidi_override_in_url");
  });

  it("does NOT fire on plain ASCII URL", () => {
    const sigs = unicodeTrickeryUrlSignals(parse("https://example.com/login"));
    expect(sigs).toHaveLength(0);
  });
});

// ---- Unicode trickery (text) -------------------------------------------

describe("unicodeTrickeryTextSignals", () => {
  it("fires on zero-width in page title", () => {
    const sigs = unicodeTrickeryTextSignals("Doc‌uSign", "");
    expect(sigs.map((s) => s.id)).toContain("dom.zero_width_in_text");
  });

  it("fires on bidi-override in body text", () => {
    const sigs = unicodeTrickeryTextSignals("ok", "filename: receipt‮exe.pdf");
    expect(sigs.map((s) => s.id)).toContain("dom.bidi_override_in_text");
  });

  it("does NOT fire on plain ASCII title+body", () => {
    expect(unicodeTrickeryTextSignals("hello", "world")).toHaveLength(0);
  });
});

// ---- Cloaking / verify-wall --------------------------------------------

describe("cloakingSignals", () => {
  it("fires STRONG when Turnstile present + body empty + no form", () => {
    const sigs = cloakingSignals(
      emptyPageFeatures({ hasTurnstileWidget: true, bodyTextLength: 50, formActions: [] })
    );
    expect(sigs.map((s) => s.id)).toContain("dom.cloaking_verify_wall_strong");
  });

  it("fires WEAK when Turnstile present + thin body + has form", () => {
    const sigs = cloakingSignals(
      emptyPageFeatures({
        hasTurnstileWidget: true,
        bodyTextLength: 100,
        formActions: ["/submit"],
        hasPasswordField: true
      })
    );
    expect(sigs.map((s) => s.id)).toContain("dom.cloaking_verify_wall");
  });

  it("does NOT fire when widget present on a content-heavy page", () => {
    const sigs = cloakingSignals(
      emptyPageFeatures({ hasTurnstileWidget: true, bodyTextLength: 5000 })
    );
    expect(sigs).toHaveLength(0);
  });

  it("does NOT fire when no widget at all", () => {
    const sigs = cloakingSignals(emptyPageFeatures({ bodyTextLength: 10 }));
    expect(sigs).toHaveLength(0);
  });
});

// ---- Favicon CDN hot-link mismatch -------------------------------------

describe("faviconMismatchSignals", () => {
  it("fires when favicon hot-linked from microsoft.com but page is elsewhere", () => {
    const sigs = faviconMismatchSignals(
      emptyPageFeatures({
        url: "https://signin-microsoft-com.attacker.tk/",
        faviconUrl: "https://www.microsoft.com/favicon.ico"
      }),
      "attacker.tk",
      BRAND_INDEX
    );
    expect(sigs.length).toBeGreaterThan(0);
    expect(sigs[0].id).toMatch(/favicon_brand/);
  });

  it("does NOT fire when favicon is same-origin", () => {
    const sigs = faviconMismatchSignals(
      emptyPageFeatures({
        url: "https://example.com/",
        faviconUrl: "https://example.com/favicon.ico"
      }),
      "example.com",
      BRAND_INDEX
    );
    expect(sigs).toHaveLength(0);
  });

  it("does NOT fire when no favicon declared", () => {
    const sigs = faviconMismatchSignals(
      emptyPageFeatures({ faviconUrl: null }),
      "example.com",
      BRAND_INDEX
    );
    expect(sigs).toHaveLength(0);
  });
});

// ---- Integration: full Stage 1 orchestrator ----------------------------

describe("runStage1 integration", () => {
  it("allowlist short-circuits Google", () => {
    const r = runStage1("https://www.google.com/search?q=phishing");
    expect(r.shortCircuit).toBe(true);
    expect(r.verdict).toBe("safe");
  });

  it("Evilginx-style URL accumulates reverse-proxy + phishlet + TLD signals", () => {
    const r = runStage1("https://login.microsoftonline.com.attacker.tk/oauth2/v2.0/authorize");
    const ids = r.signals.map((s) => s.id);
    expect(ids).toContain("url.reverse_proxy_fqdn");
    expect(ids).toContain("url.phishlet_endpoint");
    expect(r.rawScore).toBeGreaterThanOrEqual(75);
  });

  // Regression: NTU coursework page was misclassified as phishing because
  // (a) cascade ran the LLM with stale session state from a previous fixture,
  // (b) there's no Tranco entry for ntu.edu.tw. The TWNIC institutional-TLD
  // short-circuit ensures .edu.tw / .gov.tw bypass cascade entirely.
  it("short-circuits .edu.tw (NTU coursework)", () => {
    const r = runStage1("https://cool.ntu.edu.tw/courses/57494/assignments/392614");
    expect(r.shortCircuit).toBe(true);
    expect(r.verdict).toBe("safe");
    expect(r.signals.some((s) => s.id === "url.tw_institutional_tld")).toBe(true);
  });

  it("short-circuits .gov.tw (real government page)", () => {
    const r = runStage1("https://www.nhi.gov.tw/Content_List.aspx?id=ABC123");
    expect(r.shortCircuit).toBe(true);
    expect(r.verdict).toBe("safe");
  });

  it("still flags spoofed gov.tw embedded in attacker hostname", () => {
    const r = runStage1("https://etax.gov.tw.refund-2026.click/login");
    expect(r.shortCircuit).toBe(false); // attacker eTLD+1 is .click, not .gov.tw
    expect(r.signals.some((s) => s.id === "url.gov_tw_substring_abuse")).toBe(true);
  });

  // Taiwan first-class allowlist regression — addresses Tier F 52% FPR
  // root cause where global Tranco missed cathaybk / esun / shopee.tw.
  it("short-circuits cathaybk.com.tw via Taiwan allowlist", () => {
    const r = runStage1("https://www.cathaybk.com.tw/personal/login");
    expect(r.shortCircuit).toBe(true);
    expect(r.verdict).toBe("safe");
    expect(r.signals.some((s) => s.id === "url.tw_allowlist_hit")).toBe(true);
  });

  it("short-circuits momoshop.com.tw via Taiwan allowlist (not in global Tranco)", () => {
    const r = runStage1("https://www.momoshop.com.tw/main/Main.jsp");
    expect(r.shortCircuit).toBe(true);
    expect(r.signals.some((s) => s.id === "url.tw_allowlist_hit")).toBe(true);
  });

  it("does NOT short-circuit a typosquat of cathaybk", () => {
    const r = runStage1("https://cathaybk-login.tw-secure.com/personal");
    expect(r.signals.every((s) => s.id !== "url.tw_allowlist_hit")).toBe(true);
  });
});

// ---- 165 / 警政署 on-device bloom-filter ------------------------------

/** Build a synthetic BloomSpec containing `domains` using the exact same
 *  algorithm as eval/build_bloom_filter.py. Lets us test the BloomFilter
 *  decoder + Stage 1 integration without depending on the bundled blob. */
function buildSyntheticBloom(domains: string[]): BloomSpec {
  const FNV_PRIME = 0x01000193;
  const SEED_A = 0x811C9DC5;
  const SEED_B = 0xCBF29CE4;

  const fnv1a = (s: string, seed: number): number => {
    let h = seed >>> 0;
    const bytes = new TextEncoder().encode(s);
    for (let i = 0; i < bytes.length; i++) {
      h = (h ^ bytes[i]) >>> 0;
      h = Math.imul(h, FNV_PRIME) >>> 0;
    }
    return h >>> 0;
  };

  // Same sizing rule as build_bloom_filter.py with target_fpr=0.001 and
  // growth=10x. We round-up m to a multiple of 8.
  const n = Math.max(1, domains.length * 10);
  const rawM = Math.ceil((-n * Math.log(0.001)) / (Math.log(2) ** 2));
  const m = Math.ceil(rawM / 8) * 8;
  const k = Math.max(1, Math.ceil((m / n) * Math.log(2)));

  const bytes = new Uint8Array(m / 8);
  for (const d of domains) {
    const h1 = fnv1a(d, SEED_A);
    const h2 = fnv1a(d, SEED_B) | 1;
    for (let i = 0; i < k; i++) {
      const pos = (((h1 + Math.imul(i, h2)) >>> 0) % m) >>> 0;
      bytes[pos >>> 3] |= 1 << (7 - (pos % 8));
    }
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);

  return {
    version: 1,
    hash_family: "double-fnv1a-32",
    fnv_offset_a: SEED_A,
    fnv_offset_b: SEED_B,
    fnv_prime: FNV_PRIME,
    m_bits: m,
    k_hashes: k,
    n_inserted: domains.length,
    planned_capacity: n,
    target_fpr: 0.001,
    empirical_fpr: 0,
    bits_b64: b64,
  };
}

describe("BloomFilter decoder", () => {
  const SAMPLE_DOMAINS = [
    "fake-cathaybk.click",
    "esunbank-verify.top",
    "ntbsa-refund-2025.com",
  ];
  const spec = buildSyntheticBloom(SAMPLE_DOMAINS);

  it("hits every inserted domain", () => {
    const f = new BloomFilter(spec);
    for (const d of SAMPLE_DOMAINS) {
      expect(f.has(d)).toBe(true);
    }
  });

  it("does not hit random non-members (1000 trials, FPR << 1%)", () => {
    const f = new BloomFilter(spec);
    let fp = 0;
    for (let i = 0; i < 1000; i++) {
      const probe = `random-${i}-${Math.random().toString(36).slice(2)}.invalid`;
      if (SAMPLE_DOMAINS.includes(probe)) continue;
      if (f.has(probe)) fp++;
    }
    expect(fp).toBeLessThan(50); // generous bound; with target FPR 0.001 we expect ~1
  });

  it("empty filter (n=0) never matches", () => {
    const empty = buildSyntheticBloom([]);
    const f = new BloomFilter({ ...empty, n_inserted: 0 });
    expect(f.has("anything.example")).toBe(false);
    expect(f.has("fake-cathaybk.click")).toBe(false);
  });

  it("rejects malformed hash family", () => {
    expect(() => new BloomFilter({ ...spec, hash_family: "bogus" }))
      .toThrow(/unsupported bloom hash_family/);
  });
});

describe("Stage 1 bloom-filter integration", () => {
  const PHISH_DOMAINS = [
    "fake-cathaybk.click",
    "ntbsa-refund-2025.com",
  ];

  it("a domain in the runtime bloom short-circuits to DANGEROUS", () => {
    setRuntimeBloom(buildSyntheticBloom(PHISH_DOMAINS));
    try {
      const r = runStage1("https://fake-cathaybk.click/login");
      expect(r.shortCircuit).toBe(true);
      expect(r.verdict).toBe("dangerous");
      expect(r.signals.some((s) => s.id === "url.bloomfilter_blacklist_hit")).toBe(true);
      expect(r.rawScore).toBeGreaterThanOrEqual(85);
    } finally {
      setRuntimeBloom(null); // restore bundled (empty) blob
    }
  });

  it("a clean-but-suspicious typosquat does NOT trigger the bloom", () => {
    setRuntimeBloom(buildSyntheticBloom(PHISH_DOMAINS));
    try {
      const r = runStage1("https://paypa1-secure-login.tk/account");
      // bloom must NOT fire (typosquat is suspicious but NOT in our feed)
      expect(r.signals.every((s) => s.id !== "url.bloomfilter_blacklist_hit")).toBe(true);
    } finally {
      setRuntimeBloom(null);
    }
  });

  it("a .gov.tw page still short-circuits via institutional TLD ahead of bloom", () => {
    // Even if the bloom were polluted, .gov.tw must always win first.
    setRuntimeBloom(buildSyntheticBloom(["ntbsa.gov.tw"]));
    try {
      const r = runStage1("https://www.nhi.gov.tw/Content_List.aspx?id=ABC123");
      expect(r.verdict).toBe("safe");
      expect(r.signals.some((s) => s.id === "url.tw_institutional_tld")).toBe(true);
      expect(r.signals.every((s) => s.id !== "url.bloomfilter_blacklist_hit")).toBe(true);
    } finally {
      setRuntimeBloom(null);
    }
  });
});

// ---- Cross-tab inference queue (Stage 3) ------------------------------

describe("InferenceQueue", () => {
  /** Build a fake Stage 3 caller whose latency we control per-call so we
   *  can deterministically test ordering. */
  function makeFakeCaller(latencyMs = 5) {
    const calls: Array<{ url: string; ts: number }> = [];
    let counter = 0;
    const caller = async (input: Stage3Input) => {
      const myIdx = counter++;
      calls.push({ url: input.url, ts: Date.now() });
      await new Promise((r) => setTimeout(r, latencyMs));
      const out: Stage3Output = {
        riskScore: 50 + myIdx,
        verdict: "suspicious",
        category: ["test"],
        reasons: [],
        needVisual: false,
      };
      return { result: out, backend: "rules-only" as LLMBackend, latencyMs };
    };
    return { caller, calls };
  }

  function mkInput(url: string): Stage3Input {
    return { url, etld1: "", title: "", textSample: "", ruleSignals: [] };
  }

  it("serializes inferences (one at a time)", async () => {
    const { caller, calls } = makeFakeCaller(20);
    const q = new InferenceQueue(caller);
    const p1 = q.enqueue(1, mkInput("https://a.example/"));
    const p2 = q.enqueue(2, mkInput("https://b.example/"));
    const p3 = q.enqueue(3, mkInput("https://c.example/"));
    await Promise.all([p1, p2, p3]);
    expect(calls).toHaveLength(3);
    // Each call's timestamp must be ≥ prior + 20 ms (serialized).
    for (let i = 1; i < calls.length; i++) {
      expect(calls[i].ts - calls[i - 1].ts).toBeGreaterThanOrEqual(15);
    }
  });

  it("coalesces same-tab requests — only the latest seq returns a non-cancelled result", async () => {
    const { caller, calls } = makeFakeCaller(10);
    const q = new InferenceQueue(caller);
    // Three rapid requests on the same tab. The first one starts running
    // immediately (queue picks it up before subsequent enqueues land), so
    // we cannot stop its caller from being invoked. But ALL three earlier
    // requests must come back as cancelled and only the latest seq returns
    // the real verdict. WebLLM can't be killed mid-generation; we drop
    // stale results on arrival via the seq check.
    const p1 = q.enqueue(1, mkInput("https://stale-1.example/"));
    const p2 = q.enqueue(1, mkInput("https://stale-2.example/"));
    const p3 = q.enqueue(1, mkInput("https://fresh.example/"));
    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    expect(r1.cancelled).toBe(true);
    expect(r2.cancelled).toBe(true);
    expect(r3.cancelled).toBeFalsy();
    // At most TWO calls actually reach the caller (the already-running
    // first one + the eventual fresh one). The two coalesced enqueues
    // never reach the caller because they were dropped from `pending`.
    expect(calls.length).toBeLessThanOrEqual(2);
    expect(calls.map((c) => c.url)).toContain("https://fresh.example/");
    expect(calls.map((c) => c.url)).not.toContain("https://stale-2.example/");
  });

  it("active-tab requests jump ahead of background-tab requests", async () => {
    const { caller, calls } = makeFakeCaller(15);
    const q = new InferenceQueue(caller);
    // Two background-tab requests queue up first.
    const bg1 = q.enqueue(2, mkInput("https://bg1.example/"));
    const bg2 = q.enqueue(3, mkInput("https://bg2.example/"));
    // Then the user switches to tab 1 and that tab needs a classify.
    q.setActiveTab(1);
    const fg = q.enqueue(1, mkInput("https://fg.example/"));
    await Promise.all([bg1, bg2, fg]);
    // bg1 is already running (first call). bg2 and fg are pending.
    // setActiveTab(1) reorders, so fg jumps ahead of bg2. The first call
    // is bg1, then fg, then bg2.
    const urls = calls.map((c) => c.url);
    expect(urls[0]).toBe("https://bg1.example/");
    // Tolerant: fg should run before bg2.
    const fgIdx = urls.indexOf("https://fg.example/");
    const bg2Idx = urls.indexOf("https://bg2.example/");
    expect(fgIdx).toBeGreaterThan(-1);
    expect(bg2Idx).toBeGreaterThan(fgIdx);
  });

  it("cancelTab drops queued requests + bumps seq so in-flight results are discarded", async () => {
    const { caller, calls } = makeFakeCaller(15);
    const q = new InferenceQueue(caller);
    const p1 = q.enqueue(7, mkInput("https://running.example/"));
    const p2 = q.enqueue(7, mkInput("https://queued-stale.example/"));
    // Cancel everything for tab 7 immediately — running call stays on the
    // GPU but its result will be discarded; queued call is dropped now.
    q.cancelTab(7);
    const [r1, r2] = await Promise.all([p1, p2]);
    // Both should report cancelled (p1 because seq was bumped after start,
    // p2 because it was still in queue).
    expect(r1.cancelled || r1.result === null).toBe(true);
    expect(r2.cancelled).toBe(true);
    expect(calls.length).toBeLessThanOrEqual(1);
  });
});

// ---- Taiwan PII combo (Stage 2) -----------------------------------------

describe("Taiwan PII combo Stage 2 detector", () => {
  it("fires when 身分證字號 + 卡號 + OTP are collected on a non-trusted host", () => {
    const r = runStage2(
      emptyPageFeatures({
        url: "https://refund-tax-2026.click/verify",
        etld1: "refund-tax-2026.click",
        hasTwNationalIdField: true,
        hasCreditCardField: true,
        hasOtpField: true,
        hasPasswordField: false,
        formActions: ["https://exfil.attacker.click/post"]
      }),
      "refund-tax-2026.click"
    );
    expect(r.signals.some((s) => s.id === "dom.tw_pii_combo")).toBe(true);
    expect(r.signals.some((s) => s.id === "dom.tw_national_id_cross_etld1_post")).toBe(true);
  });

  it("does NOT fire the combo when only 身分證字號 is present (just the cross-eTLD+1 signal)", () => {
    const r = runStage2(
      emptyPageFeatures({
        url: "https://refund-tax-2026.click/verify",
        etld1: "refund-tax-2026.click",
        hasTwNationalIdField: true,
        formActions: ["https://exfil.attacker.click/post"]
      }),
      "refund-tax-2026.click"
    );
    expect(r.signals.some((s) => s.id === "dom.tw_pii_combo")).toBe(false);
    expect(r.signals.some((s) => s.id === "dom.tw_national_id_cross_etld1_post")).toBe(true);
  });

  it("does NOT fire on a page without the national-ID field", () => {
    const r = runStage2(
      emptyPageFeatures({
        url: "https://refund-tax-2026.click/verify",
        etld1: "refund-tax-2026.click",
        hasTwNationalIdField: false,
        hasCreditCardField: true,
        hasOtpField: true
      }),
      "refund-tax-2026.click"
    );
    expect(r.signals.every((s) => s.id !== "dom.tw_pii_combo")).toBe(true);
    expect(r.signals.every((s) => s.id !== "dom.tw_national_id_cross_etld1_post")).toBe(true);
  });
});
