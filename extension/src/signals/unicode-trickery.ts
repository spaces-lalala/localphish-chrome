// Stage 1 (hostname + URL) and Stage 2 (page title + visible text) —
// Unicode "trickery" character detection.
//
// homograph.ts already handles Cyrillic / Greek confusables. This file
// covers the orthogonal attack surface:
//
//   - Zero-width characters (U+200B-D, U+2060, U+FEFF, U+180E) splice into
//     hostnames or visible text to make two strings *look* identical while
//     comparing unequal. Used in URL hand-off attacks ("you typed paypal,
//     we routed you to pay​pal with a zero-width joiner") and in copy-paste
//     attacks that bypass naive token matching.
//
//   - Bidi override (U+202A-E, U+2066-9) flips display order — the file
//     name `receipt-pdf‮.exe` *renders* as `receipt-exe.pdf` because U+202E
//     reverses everything after it. Attackers use these to mask extension
//     or to invert URL paths.
//
//   - Tag characters (U+E0000-E007F) are invisible by design; the entire
//     ASCII Latin block is mirrored in the Tag Unicode block. Used in
//     "instruction smuggling" payloads against LLMs, and increasingly to
//     hide tracking codes in URLs that scanners normalize before matching.
//
// All three categories are *very* rare in legitimate content. We fire a
// hard signal when any of them appear in the hostname or URL, and a
// medium signal when they appear in the page title or first 2 KB of body
// text.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import { weight as W } from "./weights";

// --- Character set definitions --------------------------------------------

// Zero-width / invisible whitespace:
//   U+200B  ZERO WIDTH SPACE
//   U+200C  ZERO WIDTH NON-JOINER
//   U+200D  ZERO WIDTH JOINER
//   U+2060  WORD JOINER
//   U+FEFF  ZERO WIDTH NO-BREAK SPACE (BOM)
//   U+180E  MONGOLIAN VOWEL SEPARATOR
// U+00A0 (nbsp) intentionally NOT in this set — it's everywhere in legit content.
const ZERO_WIDTH_RE = /[​-‍⁠﻿᠎]/;

// Bidi formatting + isolate controls.
//   U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO
//   U+2066 LRI, U+2067 RLI, U+2068 FSI, U+2069 PDI
// We intentionally exclude U+200E/F (LRM/RLM) — those are common in
// legitimate Arabic/Hebrew + Latin mixed content.
const BIDI_OVERRIDE_RE = /[‪-‮⁦-⁩]/;

// Tag characters (U+E0000-U+E007F).
const TAG_CHAR_RE = /[\u{E0000}-\u{E007F}]/u;

// --- Weights ---------------------------------------------------------------
// All weights live in extension/src/data/signal-spec.json so the Python eval
// port and the TS extension cannot drift. The URL-tucked-into-path / query
// variants (`url.zero_width_in_url`, `url.bidi_override_in_url`) use slightly
// gentler weights than their hostname counterparts because path/query
// trickery occasionally appears in legitimate URLs (analytics tokens, deep
// links). Spec values 21 / 28 mirror the historical Math.round(35*0.6) /
// Math.round(40*0.7) factors that lived in this file.

// --- Stage 1: URL-level ----------------------------------------------------

function safeDecode(s: string): string {
  // decodeURIComponent throws on malformed sequences (single %, etc.). We
  // never want to throw inside a signal detector; fall back to the raw
  // input on error so the regex still scans for literal characters.
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/**
 * Scan the *entire* URL (href) for trickery codepoints. Hostname is the
 * highest-impact location but path and query are also worth checking —
 * phishing kits use bidi marks in path to mask file extensions.
 *
 * We test both the parser-normalized form AND the percent-decoded form so
 * `%E2%80%AE` (URL-encoded U+202E) is caught even though the URL.* getters
 * keep it escaped.
 */
export function unicodeTrickeryUrlSignals(p: ParsedUrl): Signal[] {
  const out: Signal[] = [];
  const href = p.href + " " + safeDecode(p.href);
  const host = p.hostname + " " + safeDecode(p.hostname);

  if (ZERO_WIDTH_RE.test(host)) {
    out.push({
      id: "url.zero_width_in_host",
      stage: "stage1",
      weight: W("url.zero_width_in_host"),
      detail: "hostname contains invisible zero-width character(s) — visual hostname-confusion attack"
    });
  } else if (ZERO_WIDTH_RE.test(href)) {
    out.push({
      id: "url.zero_width_in_url",
      stage: "stage1",
      weight: W("url.zero_width_in_url"),
      detail: "URL path or query contains invisible zero-width character(s)"
    });
  }

  if (BIDI_OVERRIDE_RE.test(host)) {
    out.push({
      id: "url.bidi_override_in_host",
      stage: "stage1",
      weight: W("url.bidi_override_in_host"),
      detail: "hostname contains bidi-override character (U+202A-E / U+2066-9) — visual reversal attack"
    });
  } else if (BIDI_OVERRIDE_RE.test(href)) {
    out.push({
      id: "url.bidi_override_in_url",
      stage: "stage1",
      weight: W("url.bidi_override_in_url"),
      detail: "URL path or query contains bidi-override character — likely extension/path masking"
    });
  }

  if (TAG_CHAR_RE.test(href)) {
    out.push({
      id: "url.tag_char_in_url",
      stage: "stage1",
      weight: W("url.tag_char_in_url"),
      detail: "URL contains invisible Unicode tag character (U+E00xx) — instruction-smuggling pattern"
    });
  }

  return out;
}

// --- Stage 2: title + visible text ----------------------------------------

/**
 * Scan the page title and first 2 KB of visible text for trickery codepoints.
 * Caller supplies pre-extracted strings (no DOM access here).
 */
export function unicodeTrickeryTextSignals(title: string, visibleTextSample: string): Signal[] {
  const out: Signal[] = [];
  // Concatenate so a single regex test covers both, but report which one
  // matched so the badge UI can point at the right culprit.
  const titleHasZw = ZERO_WIDTH_RE.test(title);
  const textHasZw = ZERO_WIDTH_RE.test(visibleTextSample);
  if (titleHasZw || textHasZw) {
    out.push({
      id: "dom.zero_width_in_text",
      stage: "stage2",
      weight: W("dom.zero_width_in_text"),
      detail: `zero-width character(s) present in page ${titleHasZw ? "title" : "body text"}`
    });
  }

  const titleHasBidi = BIDI_OVERRIDE_RE.test(title);
  const textHasBidi = BIDI_OVERRIDE_RE.test(visibleTextSample);
  if (titleHasBidi || textHasBidi) {
    out.push({
      id: "dom.bidi_override_in_text",
      stage: "stage2",
      weight: W("dom.bidi_override_in_text"),
      detail: `bidi-override character present in page ${titleHasBidi ? "title" : "body text"}`
    });
  }

  const titleHasTag = TAG_CHAR_RE.test(title);
  const textHasTag = TAG_CHAR_RE.test(visibleTextSample);
  if (titleHasTag || textHasTag) {
    out.push({
      id: "dom.tag_char_in_text",
      stage: "stage2",
      weight: W("dom.tag_char_in_text"),
      detail: `Unicode tag character present in page ${titleHasTag ? "title" : "body text"}`
    });
  }

  return out;
}
