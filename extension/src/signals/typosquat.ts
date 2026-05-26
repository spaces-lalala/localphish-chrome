// Stage 1 — typosquat + subdomain brand-abuse detection.
//
// Two patterns we catch here:
//   1. Lookalike eTLD+1:  "g00gle.com", "paypa1.com", "microsft.com"
//      -> domain label is within Levenshtein 1-2 of a known brand label,
//         BUT eTLD+1 is not the canonical brand domain.
//   2. Subdomain brand abuse:  "paypal.com.evil.tk", "google.login-update.tk"
//      -> brand alias appears in subdomain or path, but eTLD+1 is unrelated.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import { levenshtein } from "./levenshtein";

const TYPOSQUAT_WEIGHT = 40;
const SUBDOMAIN_BRAND_ABUSE_WEIGHT = 35;
const PATH_BRAND_ABUSE_WEIGHT = 10;

export interface Brand {
  name: string;
  domain: string;       // canonical eTLD+1
  aliases: string[];    // lowercased
}

interface BrandIndex {
  brands: Brand[];
  /** domainLabel (e.g. "paypal" from "paypal.com") for quick Levenshtein loop. */
  labels: { label: string; brand: Brand }[];
  /** alias → brand for substring lookups. */
  aliasMap: Map<string, Brand>;
  /** Set of canonical eTLD+1s for fast "is this brand's real domain" check. */
  canonicalDomains: Set<string>;
}

export function buildBrandIndex(brands: Brand[]): BrandIndex {
  const labels: { label: string; brand: Brand }[] = [];
  const aliasMap = new Map<string, Brand>();
  const canonicalDomains = new Set<string>();

  for (const b of brands) {
    const lbl = b.domain.split(".")[0];
    labels.push({ label: lbl, brand: b });
    canonicalDomains.add(b.domain);
    for (const a of b.aliases) {
      aliasMap.set(a.toLowerCase(), b);
    }
  }
  return { brands, labels, aliasMap, canonicalDomains };
}

export function typosquatSignals(p: ParsedUrl, idx: BrandIndex): Signal[] {
  const out: Signal[] = [];
  if (!p.etld1 || !p.domainLabel) return out;

  const lowerLabel = p.domainLabel.toLowerCase();
  const isCanonical = idx.canonicalDomains.has(p.etld1.toLowerCase());

  // 1. eTLD+1 lookalike — skip if we ARE the canonical brand domain.
  if (!isCanonical) {
    for (const { label, brand } of idx.labels) {
      // Skip if length difference is so large that Levenshtein can't be small.
      if (Math.abs(label.length - lowerLabel.length) > 2) continue;
      // Skip if labels are identical (covered by canonical check above).
      if (label === lowerLabel) continue;
      // Skip very short labels — Levenshtein 1 is too weak (e.g. "x.com" vs "y.com").
      if (label.length < 4) continue;

      const d = levenshtein(label, lowerLabel);
      if (d > 0 && d <= 2) {
        out.push({
          id: "url.typosquat_brand",
          stage: "stage1",
          weight: TYPOSQUAT_WEIGHT,
          detail: `domain label "${lowerLabel}" is edit-distance ${d} from brand "${brand.name}" (${brand.domain})`
        });
        break; // one strong hit is enough; further matches are likely false positives
      }
    }
  }

  // 2. Subdomain brand abuse — alias appears in subdomain labels but the
  // eTLD+1 itself is not that brand's canonical domain.
  if (p.subdomain && !isCanonical) {
    const subLabels = p.subdomain.toLowerCase().split(".");
    for (const subLabel of subLabels) {
      const brand = idx.aliasMap.get(subLabel);
      if (brand && brand.domain !== p.etld1.toLowerCase()) {
        out.push({
          id: "url.subdomain_brand_abuse",
          stage: "stage1",
          weight: SUBDOMAIN_BRAND_ABUSE_WEIGHT,
          detail: `subdomain contains brand "${brand.name}" but eTLD+1 is "${p.etld1}", not "${brand.domain}"`
        });
        break;
      }
    }
  }

  // 3. Path brand abuse — brand alias in URL path, not in our domain.
  // Weaker signal; we just nudge the score and let later stages confirm.
  if (!isCanonical && p.pathname.length > 1) {
    const lowerPath = p.pathname.toLowerCase();
    for (const [alias, brand] of idx.aliasMap) {
      if (alias.length < 4) continue;
      // Match as a path-segment-ish token to avoid "ad" matching "adobe" inside "lemonade".
      const re = new RegExp(`(^|[/\\-_])${alias}([/\\-_]|$)`);
      if (re.test(lowerPath) && brand.domain !== p.etld1.toLowerCase()) {
        out.push({
          id: "url.path_brand_abuse",
          stage: "stage1",
          weight: PATH_BRAND_ABUSE_WEIGHT,
          detail: `URL path mentions brand "${brand.name}" but eTLD+1 is "${p.etld1}"`
        });
        break;
      }
    }
  }

  return out;
}
