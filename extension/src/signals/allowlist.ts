// Stage 1 — Tranco allow-list check.
//
// If a page's eTLD+1 is on the Tranco list we built into the bundle, we can
// short-circuit the rest of the cascade. This is plan §3 Stage 1 "Tranco
// Top 100k 白名單命中 → 直接通過".
//
// Today's bundle is a 150-entry starter sample (see src/data/tranco-sample.json);
// eval/fetch_tranco.py will replace it with the real Top-100k.

export class AllowList {
  private readonly set: Set<string>;

  constructor(domains: string[]) {
    this.set = new Set(domains.map((d) => d.toLowerCase()));
  }

  has(etld1: string | null): boolean {
    if (!etld1) return false;
    return this.set.has(etld1.toLowerCase());
  }

  get size(): number {
    return this.set.size;
  }
}
