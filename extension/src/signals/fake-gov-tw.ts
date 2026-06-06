// Stage 1 — fake Taiwan government domain detection.
//
// Threat model: 165 反詐騙網 publishes the recurring warning「請認明 gov.tw 結尾
// 的官方網站」because attackers register lookalike domains such as
// `govtw.com`, `.gov-tw.com`, `gov.tw.xyz`, or stuff "gov.tw" inside a
// subdomain of an unrelated eTLD+1. Real ROC government sites always land on
// the `.gov.tw` public suffix; anything else claiming to be 健保署 / 國稅局 /
// 監理服務網 is a textbook 假冒公務機關詐騙.
//
// This detector is URL-only and runs alongside the other Stage 1 modules.
// The complementary "page text claims to be a TW gov agency BUT eTLD+1 is
// not .gov.tw" check happens in Stage 2 (it needs visibleTextSample).

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import { weight as W } from "./weights";

/** Real `.gov.tw` registrations always have ≥3 labels (e.g. `npa.gov.tw`,
 *  `nhi.gov.tw`); the public suffix is the literal two-label `gov.tw`. */
function isLegitGovTw(etld1: string | null): boolean {
  if (!etld1) return false;
  return etld1.toLowerCase().endsWith(".gov.tw");
}

export function fakeGovTwSignals(p: ParsedUrl): Signal[] {
  const out: Signal[] = [];
  const host = p.hostname.toLowerCase();

  // If the page genuinely sits on .gov.tw, none of these checks apply.
  if (isLegitGovTw(p.etld1)) return out;

  // 1) "gov.tw" substring buried in a non-.gov.tw hostname.
  //    Examples that trigger: tax.gov.tw.evil-claim.xyz, login.gov-tw.com,
  //    secure.govtw.support.
  if (/(?:^|\.)gov\.tw\./.test(host)) {
    // eTLD+1 is not .gov.tw (checked above) but hostname includes "gov.tw."
    // mid-string — strongest tell.
    out.push({
      id: "url.gov_tw_substring_abuse",
      stage: "stage1",
      weight: W("url.gov_tw_substring_abuse"),
      detail: `hostname "${host}" contains "gov.tw." segment but eTLD+1 is "${p.etld1 ?? "?"}", not a real .gov.tw site`
    });
  }

  // 2) Top-level domain abuse: attacker registers a brand-new TLD that just
  //    happens to start with "gov.tw" -- e.g. someone registers gov.tw.xyz
  //    or similar via a permissive registrar. eTLD+1 ends with .gov.tw.xyz.
  if (p.etld1 && /\bgov\.tw\.[a-z]{2,}$/.test(p.etld1.toLowerCase())) {
    out.push({
      id: "url.gov_tw_pseudo_tld",
      stage: "stage1",
      weight: W("url.gov_tw_pseudo_tld"),
      detail: `eTLD+1 "${p.etld1}" uses "gov.tw" as a fake prefix on a non-Taiwan registry`
    });
  }

  // 3) Hyphenated and run-on variants: `gov-tw.something`, `govtw.something`,
  //    `tw-gov.something`. Attackers favour these because users glance at
  //    the start of the URL.
  if (p.domainLabel) {
    const lbl = p.domainLabel.toLowerCase();
    if (lbl === "gov-tw" || lbl === "govtw" || lbl === "tw-gov" || lbl === "twgov") {
      out.push({
        id: "url.gov_tw_hyphen_variant",
        stage: "stage1",
        weight: W("url.gov_tw_hyphen_variant"),
        detail: `domain label "${lbl}" mimics a Taiwan gov site without using the .gov.tw suffix`
      });
    }
  }

  return out;
}
