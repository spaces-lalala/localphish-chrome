// Stage 1 — reverse-proxy phishing hostname-pattern detection.
//
// Threat model. Evilginx / EvilProxy / Modlishka register hostnames that
// embed a real brand FQDN as a subdomain prefix so the victim's eye stops at
// the brand name:
//
//   login-microsoftonline-com.evil.xyz
//   login.microsoftonline.com.attacker.tld
//   signin-paypal-com.zz
//
// The page itself is a reverse proxy serving real Microsoft / PayPal HTML,
// so every Stage 2 signal (password_no_tls, cross-eTLD+1 form action) goes
// silent — the form posts to the attacker's host, TLS is valid, the visible
// text is genuine. Only Stage 1 can catch this, and only by matching the
// full brand FQDN inside the attacker's subdomain.
//
// typosquat.ts already catches single-label brand aliases in a subdomain
// (e.g. "paypal" in "paypal.attacker.tk"). What's missing is the *multi-
// label* match — the entire brand canonical domain "microsoftonline.com"
// or its hyphen-flattened variant "microsoftonline-com" appearing inside
// the attacker hostname.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import type { BrandIndex } from "./typosquat";
import { weight as W } from "./weights";

// Well-known authentication / sign-in FQDNs that brands publish. These are
// the *exact* hostnames victims expect to see when logging in, so a reverse-
// proxy phishlet embeds them as a subdomain prefix. brand-list.json only
// holds canonical brand eTLD+1s (microsoft.com, google.com, …) — the auth
// FQDNs (login.microsoftonline.com, accounts.google.com, …) are layered on
// top here. Curated, not auto-generated; keep tight to avoid FPs.
const AUTH_FQDNS: ReadonlySet<string> = new Set([
  // Microsoft
  "login.microsoftonline.com",
  "login.microsoft.com",
  "login.live.com",
  "account.live.com",
  "login.windows.net",
  // Google
  "accounts.google.com",
  // Apple
  "appleid.apple.com",
  "idmsa.apple.com",
  // Amazon
  "signin.aws.amazon.com",
  "signin.amazon.com",
  // Yahoo
  "login.yahoo.com",
  // Meta / Facebook
  "login.facebook.com",
  "m.facebook.com",
  // Adobe
  "auth.services.adobe.com",
  // Coinbase / Binance
  "login.coinbase.com",
  "accounts.binance.com",
  // Okta / Auth0 default tenants
  "login.okta.com",
  // Dropbox / GitHub / LinkedIn
  "www.dropbox.com",
  "github.com",
  "www.linkedin.com",
  // Taiwan banks / gov
  "ibank.cathaybk.com.tw",
  "netbank.esunbank.com.tw",
  "ebank.megabank.com.tw",
  "ebank.firstbank.com.tw",
  "www.post.gov.tw"
]);

/** All brand FQDNs we'll search for inside attacker hostnames: brand canonical
 *  eTLD+1s (from brand-list.json) plus the explicit auth FQDNs. Built lazily
 *  to combine the data sources without leaking the BrandIndex internals. */
function buildBrandFqdnNeedles(idx: BrandIndex): string[] {
  const set = new Set<string>();
  for (const d of idx.canonicalDomains) {
    if (d.includes(".")) set.add(d);
  }
  for (const f of AUTH_FQDNS) set.add(f);
  return Array.from(set);
}

export function reverseProxySignals(p: ParsedUrl, idx: BrandIndex): Signal[] {
  const out: Signal[] = [];
  if (!p.etld1 || !p.hostname) return out;

  const lowerHost = p.hostname.toLowerCase();
  const lowerEtld1 = p.etld1.toLowerCase();

  // If the page lives on the canonical brand eTLD+1 (e.g.
  // login.microsoftonline.com on microsoftonline.com — but we don't have
  // microsoftonline.com in canonicalDomains, so this guard targets the
  // *real* brand pages like microsoft.com itself).
  if (idx.canonicalDomains.has(lowerEtld1)) return out;
  // Same idea for AUTH_FQDNS: if the host *is* the auth FQDN (we landed on
  // the real login.microsoftonline.com) we already short-circuit.
  if (AUTH_FQDNS.has(lowerHost)) return out;

  const needles = buildBrandFqdnNeedles(idx);

  // 1. Brand FQDN as dot-bounded substring inside the attacker's hostname.
  const padded = `.${lowerHost}.`;
  for (const brandDomain of needles) {
    if (lowerHost === brandDomain) continue;
    const needle = `.${brandDomain}.`;
    const at = padded.indexOf(needle);
    if (at < 0) continue;
    // Skip the canonical-edge case (brand at the right of the hostname —
    // i.e. we're a real subdomain of the brand, not an attacker host).
    if (at + needle.length === padded.length) continue;

    out.push({
      id: "url.reverse_proxy_fqdn",
      stage: "stage1",
      weight: W("url.reverse_proxy_fqdn"),
      detail: `hostname embeds brand FQDN "${brandDomain}" as a subdomain — Evilginx / EvilProxy pattern (page eTLD+1 is "${lowerEtld1}", not "${brandDomain}")`
    });
    return out; // one strong hit is enough
  }

  // 2. Hyphen-flattened variant: "login-microsoftonline-com.evil.xyz".
  // Replace "-" with "." in each hostname label, then re-test as a suffix
  // of any brand FQDN needle.
  for (const label of lowerHost.split(".")) {
    if (!label.includes("-")) continue;
    if (label.length < 10) continue;
    const unfolded = label.replace(/-/g, ".");
    for (const brandDomain of needles) {
      if (unfolded === brandDomain || unfolded.endsWith(`.${brandDomain}`)) {
        out.push({
          id: "url.reverse_proxy_hyphen_fqdn",
          stage: "stage1",
          weight: W("url.reverse_proxy_hyphen_fqdn"),
          detail: `hostname label "${label}" decodes to "${unfolded}", embedding brand FQDN "${brandDomain}" — hyphen-flattened Evilginx pattern`
        });
        return out;
      }
    }
  }

  return out;
}
