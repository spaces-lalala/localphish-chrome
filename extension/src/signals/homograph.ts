// Stage 1 — IDN / Punycode / mixed-script homograph detection.
//
// Threat model: attackers register internationalized domains whose visible
// label looks like a famous brand using Unicode characters that render
// identically to Latin (Cyrillic а U+0430 looks like Latin a U+0061), so a
// browser shows `аpple.com` (Punycode `xn--pple-43d.com`) but routes elsewhere.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import { weight as W } from "./weights";

// Quick script bucket — enough to flag Latin/Cyrillic/Greek mixing without
// pulling a full ICU table. We treat Latin as the baseline; anything else
// in the *same label* alongside Latin is suspicious.
function scriptOf(cp: number): "latin" | "cyrillic" | "greek" | "han" | "kana" | "hangul" | "other" {
  if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) return "latin";
  if (cp >= 0x0400 && cp <= 0x04ff) return "cyrillic";
  if (cp >= 0x0370 && cp <= 0x03ff) return "greek";
  if (cp >= 0x4e00 && cp <= 0x9fff) return "han";
  if ((cp >= 0x3040 && cp <= 0x309f) || (cp >= 0x30a0 && cp <= 0x30ff)) return "kana";
  if (cp >= 0xac00 && cp <= 0xd7a3) return "hangul";
  return "other";
}

function hasMixedConfusableScript(label: string): boolean {
  // ASCII-only labels never trigger.
  if (/^[\x00-\x7f]*$/.test(label)) return false;
  const scripts = new Set<string>();
  for (const ch of label) {
    const s = scriptOf(ch.codePointAt(0)!);
    if (s !== "other") scripts.add(s);
  }
  // Confusables: Latin alongside Cyrillic or Greek is the classic homograph
  // attack. Latin+Han/Kana/Hangul is common in legit multilingual domains.
  if (scripts.has("latin") && (scripts.has("cyrillic") || scripts.has("greek"))) {
    return true;
  }
  // Cyrillic+Greek without Latin is also unusual.
  if (scripts.has("cyrillic") && scripts.has("greek")) return true;
  return false;
}

export function homographSignals(p: ParsedUrl, brandDomainLabels: Set<string>): Signal[] {
  const out: Signal[] = [];
  const labels = p.hostname.split(".");

  for (const label of labels) {
    if (label.startsWith("xn--")) {
      // Decode using built-in URL parser side-effect: `new URL` already gives us
      // Punycode in .hostname for IDNs, so decode back via decodeURI is unreliable.
      // Easiest path: decode with built-in. Modern browsers expose
      // URL.parse(...).hostname unchanged; we decode the label ourselves.
      let decoded = label;
      try {
        // hack: build a fake URL whose host is the label, then read .hostname
        // — Chrome's URL parser does NOT auto-decode Punycode, so we use
        // the global URL constructor with a path that forces it.
        decoded = decodePunycodeLabel(label);
      } catch {
        // fall through with decoded = label
      }

      out.push({
        id: "url.punycode_label",
        stage: "stage1",
        weight: W("url.punycode_label"),
        detail: `IDN label "${label}" decodes to "${decoded}"`
      });

      // If the decoded label looks like a famous brand by raw character match,
      // raise the weight sharply — this is the classic Cyrillic-a "аpple" attack.
      const normalized = decoded.toLowerCase().normalize("NFKC");
      for (const brandLabel of brandDomainLabels) {
        if (
          normalized !== brandLabel &&
          stripsToBrand(normalized, brandLabel)
        ) {
          out.push({
            id: "url.punycode_brand_lookalike",
            stage: "stage1",
            weight: W("url.punycode_brand_lookalike"),
            detail: `IDN label decodes to "${decoded}", visually similar to brand "${brandLabel}"`
          });
          break;
        }
      }
    }

    if (hasMixedConfusableScript(label)) {
      out.push({
        id: "url.mixed_script_label",
        stage: "stage1",
        weight: W("url.mixed_script_label"),
        detail: `label "${label}" mixes Latin with Cyrillic/Greek script`
      });
    }
  }

  return out;
}

// Map common confusables to their Latin counterpart and check brand match.
const CONFUSABLE_TO_LATIN: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
  "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
  "ı": "i", "ﬁ": "fi", "ﬂ": "fl"
};

function stripsToBrand(label: string, brand: string): boolean {
  let s = "";
  for (const ch of label) {
    s += CONFUSABLE_TO_LATIN[ch] ?? ch;
  }
  return s.toLowerCase() === brand.toLowerCase();
}

// Minimal RFC 3492 Punycode decoder for a single label including the `xn--` prefix.
// Adapted from the reference implementation; small enough to inline.
function decodePunycodeLabel(label: string): string {
  if (!label.startsWith("xn--")) return label;
  const input = label.slice(4);
  const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;

  // Find the last delimiter (`-`); everything before is literal ASCII.
  let basicEnd = input.lastIndexOf("-");
  const output: number[] = [];
  if (basicEnd > 0) {
    for (let i = 0; i < basicEnd; i++) {
      output.push(input.charCodeAt(i));
    }
  } else {
    basicEnd = -1;
  }

  let n = initialN, bias = initialBias, i = 0;
  let pos = basicEnd + 1;

  const digit = (c: number): number => {
    if (c >= 0x30 && c <= 0x39) return c - 0x30 + 26; // 0-9 -> 26-35
    if (c >= 0x41 && c <= 0x5a) return c - 0x41;      // A-Z -> 0-25
    if (c >= 0x61 && c <= 0x7a) return c - 0x61;      // a-z -> 0-25
    return base;
  };

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
  };

  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (pos >= input.length) return label; // malformed; bail
      const d = digit(input.charCodeAt(pos++));
      if (d >= base) return label;
      i += d * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i++, 0, n);
  }

  return String.fromCodePoint(...output);
}
