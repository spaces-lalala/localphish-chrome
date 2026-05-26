// Common URL parse + eTLD+1 extraction used by every Stage 1 signal.
// Wraps tldts so the rest of the code never needs to import it directly.

import { parse } from "tldts";

export interface ParsedUrl {
  href: string;
  protocol: string;
  hostname: string;
  pathname: string;
  port: string;
  /** Public Suffix List eTLD+1 (e.g. `mail.google.com` → `google.com`). */
  etld1: string | null;
  /** Domain label without the public suffix (`google.com` → `google`). */
  domainLabel: string | null;
  /** Subdomain portion (`mail.google.com` → `mail`); empty string if none. */
  subdomain: string;
  /** True iff hostname is an IPv4/IPv6 literal. */
  isIp: boolean;
  /** True iff hostname's public suffix is on the ICANN list (filters `.local`, intranet). */
  isIcann: boolean;
}

export function parseUrl(raw: string): ParsedUrl | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }

  const t = parse(u.hostname);

  return {
    href: u.href,
    protocol: u.protocol,
    hostname: u.hostname,
    pathname: u.pathname,
    port: u.port,
    etld1: t.domain ?? null,
    domainLabel: t.domainWithoutSuffix ?? null,
    subdomain: t.subdomain ?? "",
    isIp: t.isIp ?? false,
    isIcann: t.isIcann ?? false
  };
}
