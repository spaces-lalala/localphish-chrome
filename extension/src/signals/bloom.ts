// On-device bloom-filter decoder + lookup.
//
// The blob lives at extension/src/data/tw-scam-bloom.json and is rebuilt by
// `eval/build_bloom_filter.py` from the 165 反詐騙 / 警政署 phish-URL feed
// (data.gov.tw dataset 176455, CC BY 4.0 compatible).
//
// Hard privacy invariant: this module reads a bundled blob ONLY. There is no
// per-page network lookup, no fetch(), no remote hash check. Daily refresh
// happens via chrome.alarms downloading the SAME blob URL in one batch (see
// background/bloom-refresh.ts), then writing to chrome.storage.local.
//
// Hash family must match build_bloom_filter.py exactly:
//   - 32-bit FNV-1a
//   - two independent seeds (FNV_OFFSET_A, FNV_OFFSET_B)
//   - k positions derived via h1 + i*h2  (mod m)
//   - bits packed MSB-first inside each byte
//   - base64-encoded for JSON transport

import bundledBloomRaw from "@/data/tw-scam-bloom.json";

export interface BloomSpec {
  version: number;
  hash_family: string;
  fnv_offset_a: number;
  fnv_offset_b: number;
  fnv_prime: number;
  m_bits: number;
  k_hashes: number;
  n_inserted: number;
  planned_capacity: number;
  target_fpr: number;
  empirical_fpr: number;
  /** base64 of the packed bit array, MSB-first inside each byte */
  bits_b64: string;
}

const FNV_PRIME = 0x01000193;

function fnv1a(s: string, seed: number): number {
  let h = seed >>> 0;
  // Encode as UTF-8 — same as build_bloom_filter.py's `.encode("utf-8")`.
  const bytes = new TextEncoder().encode(s);
  for (let i = 0; i < bytes.length; i++) {
    h = (h ^ bytes[i]) >>> 0;
    // Math.imul is the safe 32-bit multiply in JS — avoids precision loss
    // above 2^31 that would otherwise corrupt the hash.
    h = Math.imul(h, FNV_PRIME) >>> 0;
  }
  return h >>> 0;
}

export class BloomFilter {
  readonly version: number;
  readonly mBits: number;
  readonly kHashes: number;
  readonly nInserted: number;
  readonly empiricalFpr: number;
  private readonly bits: Uint8Array;
  private readonly seedA: number;
  private readonly seedB: number;

  constructor(spec: BloomSpec) {
    if (spec.hash_family !== "double-fnv1a-32") {
      throw new Error(`unsupported bloom hash_family ${spec.hash_family}`);
    }
    if (spec.fnv_prime !== FNV_PRIME) {
      throw new Error(`unsupported bloom FNV_PRIME ${spec.fnv_prime}`);
    }
    this.version = spec.version;
    this.mBits = spec.m_bits;
    this.kHashes = spec.k_hashes;
    this.nInserted = spec.n_inserted;
    this.empiricalFpr = spec.empirical_fpr;
    this.seedA = spec.fnv_offset_a >>> 0;
    this.seedB = spec.fnv_offset_b >>> 0;
    this.bits = decodeBase64(spec.bits_b64);

    const expectedBytes = Math.ceil(this.mBits / 8);
    if (this.bits.length !== expectedBytes) {
      throw new Error(
        `bloom bit array length mismatch: got ${this.bits.length}, expected ${expectedBytes}`
      );
    }
  }

  /** True only when ALL k hashed positions are set. An empty filter (n=0)
   *  will return false for every input. */
  has(domain: string): boolean {
    if (this.nInserted === 0 || this.mBits === 0) return false;
    const m = this.mBits;
    const h1 = fnv1a(domain, this.seedA);
    // Force h2 odd so the synthetic-hash step stays useful even when m has
    // small prime factors. Matches build_bloom_filter.py.
    const h2 = fnv1a(domain, this.seedB) | 1;
    for (let i = 0; i < this.kHashes; i++) {
      const pos = (((h1 + Math.imul(i, h2)) >>> 0) % m) >>> 0;
      const byteIdx = (pos >>> 3) >>> 0;
      const bitInByte = pos % 8;
      const mask = 1 << (7 - bitInByte);  // MSB-first
      if ((this.bits[byteIdx] & mask) === 0) return false;
    }
    return true;
  }

  /** Useful for diagnostics + the toolbar status panel. */
  describe(): { nInserted: number; mBits: number; kHashes: number; emp_fpr: number } {
    return {
      nInserted: this.nInserted,
      mBits: this.mBits,
      kHashes: this.kHashes,
      emp_fpr: this.empiricalFpr,
    };
  }
}

function decodeBase64(b64: string): Uint8Array {
  // atob is available in both SW + content-script + offscreen contexts.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- Module singletons ----------------------------------------------------
//
// The extension ships with the bundled blob baked into the bundle. Daily
// refresh writes a newer blob into chrome.storage.local; the SW reads it on
// boot (see background/bloom-refresh.ts) and calls setRuntimeBloom() to swap
// in the fresher version. Lookup always uses the freshest filter available.

let runtimeBloom: BloomFilter | null = null;
const bundledBloom: BloomFilter = new BloomFilter(bundledBloomRaw as unknown as BloomSpec);

export function setRuntimeBloom(spec: BloomSpec | null): void {
  runtimeBloom = spec ? new BloomFilter(spec) : null;
}

export function getActiveBloom(): BloomFilter {
  return runtimeBloom ?? bundledBloom;
}

/** Cheap top-level lookup used by Stage 1. Domain must be the eTLD+1 (or
 *  full host); both forms are checked. */
export function bloomHas(domain: string): boolean {
  if (!domain) return false;
  const lower = domain.toLowerCase();
  const f = getActiveBloom();
  if (f.has(lower)) return true;
  // Tolerate a leading "www." — feed entries are normalized without it.
  if (lower.startsWith("www.")) {
    return f.has(lower.slice(4));
  }
  return false;
}
