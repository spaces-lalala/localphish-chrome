// Stage 2 — Favicon CDN hot-link / brand-mismatch detection.
//
// Threat model. Phishing kits routinely hot-link the real brand's favicon
// from the brand's CDN (paypalobjects.com, microsoft.com) so the browser
// tab icon matches what victims expect. The kit author is rarely careful
// enough to host a re-encoded copy locally. This produces a tell:
//
//   page eTLD+1:   signin-paypal-com.attacker.tk
//   favicon eTLD+1: paypal.com OR paypalobjects.com   ← brand canonical / CDN
//
// If the favicon resolves to a known brand's canonical domain OR one of
// its known CDN domains, but the page itself is NOT on that brand, that's
// a strong cross-brand impersonation signal.
//
// Why this works:
//   - We never need to fetch or hash the image — just match URLs.
//   - Far cheaper than CLIP / pHash (plan §6.4) and orthogonal to it.
//   - Falls back gracefully: pages without a `<link rel="icon">` simply
//     produce no faviconHostEtld1 and no signal fires.

import { getDomain } from "tldts";

import type { PageFeatures, Signal } from "@/types";
import type { BrandIndex } from "./typosquat";

import brandCdnsRaw from "@/data/brand-favicon-cdns.json";
import { weight as W } from "./weights";

interface BrandCdnEntry {
  brand: string;
  /** brand canonical eTLD+1 — must match an entry in brand-list.json */
  domain: string;
  /** additional CDN eTLD+1s the brand serves favicons from */
  cdns: string[];
}

const BRAND_CDNS: BrandCdnEntry[] = (brandCdnsRaw as { brands: BrandCdnEntry[] }).brands;

/** etld+1 (favicon host) -> brand canonical etld+1 (for diagnostic message). */
const FAVICON_HOST_TO_BRAND: Map<string, { brand: string; brandDomain: string }> = (() => {
  const m = new Map<string, { brand: string; brandDomain: string }>();
  for (const e of BRAND_CDNS) {
    m.set(e.domain.toLowerCase(), { brand: e.brand, brandDomain: e.domain });
    for (const cdn of e.cdns) {
      m.set(cdn.toLowerCase(), { brand: e.brand, brandDomain: e.domain });
    }
  }
  return m;
})();

export function faviconMismatchSignals(
  features: PageFeatures,
  pageEtld1: string | null,
  idx: BrandIndex
): Signal[] {
  const out: Signal[] = [];
  if (!features.faviconUrl || !pageEtld1) return out;

  let faviconHost: string;
  try {
    faviconHost = new URL(features.faviconUrl, features.url).hostname;
  } catch {
    return out;
  }
  const faviconEtld1 = getDomain(faviconHost);
  if (!faviconEtld1) return out;
  if (faviconEtld1.toLowerCase() === pageEtld1.toLowerCase()) return out; // same-origin favicon, fine

  const lowerFavEtld1 = faviconEtld1.toLowerCase();

  // Case 1: favicon host belongs to a known brand CDN list entry.
  const cdnMatch = FAVICON_HOST_TO_BRAND.get(lowerFavEtld1);
  if (cdnMatch && cdnMatch.brandDomain.toLowerCase() !== pageEtld1.toLowerCase()) {
    out.push({
      id: "dom.favicon_brand_cdn_mismatch",
      stage: "stage2",
      weight: W("dom.favicon_brand_cdn_mismatch"),
      detail: `favicon hot-linked from "${faviconEtld1}" (${cdnMatch.brand} CDN) but page is on "${pageEtld1}" — cross-brand impersonation`
    });
    return out;
  }

  // Case 2: favicon host equals a brand canonical eTLD+1 in our index,
  // even if not in the dedicated CDN list (covers brands without a CDN
  // entry). E.g. favicon directly off "microsoft.com" while page is on
  // some attacker host.
  if (idx.canonicalDomains.has(lowerFavEtld1)) {
    out.push({
      id: "dom.favicon_brand_canonical_mismatch",
      stage: "stage2",
      weight: W("dom.favicon_brand_canonical_mismatch"),
      detail: `favicon loaded from brand domain "${faviconEtld1}" but page is on "${pageEtld1}"`
    });
  }

  return out;
}
