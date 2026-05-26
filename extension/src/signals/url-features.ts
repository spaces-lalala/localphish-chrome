// Stage 1 — pure URL structural features.
// All checks here are O(|url|); the orchestrator can run them per page-load.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";

const NONSTANDARD_PORT_WEIGHT = 8;
const IP_HOST_WEIGHT = 30;
const AT_SIGN_WEIGHT = 25;
const LONG_URL_WEIGHT = 6;
const MANY_HYPHENS_WEIGHT = 4;
const MANY_SUBDOMAINS_WEIGHT = 7;
const HIGH_ENTROPY_WEIGHT = 10;
const DOUBLE_ENCODING_WEIGHT = 12;

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const len = s.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export function urlFeatureSignals(p: ParsedUrl): Signal[] {
  const out: Signal[] = [];

  // IP-as-host: a literal IP for a non-internal page is a strong phishing tell.
  if (p.isIp) {
    out.push({
      id: "url.ip_as_host",
      stage: "stage1",
      weight: IP_HOST_WEIGHT,
      detail: `hostname is an IP literal: ${p.hostname}`
    });
  }

  // userinfo (`@`) — original URL spec allows `https://user@target/`, attackers
  // exploit this to display a familiar prefix and redirect to `target`.
  // Re-derive from href because URL parser strips the `@` from .hostname.
  const beforeHost = p.href.split("://")[1]?.split("/")[0] ?? "";
  if (beforeHost.includes("@")) {
    out.push({
      id: "url.userinfo_at",
      stage: "stage1",
      weight: AT_SIGN_WEIGHT,
      detail: "URL contains '@' before the host — possible deceptive userinfo"
    });
  }

  // Non-standard port for an http(s) URL.
  if (p.port && p.port !== "80" && p.port !== "443") {
    out.push({
      id: "url.nonstandard_port",
      stage: "stage1",
      weight: NONSTANDARD_PORT_WEIGHT,
      detail: `non-standard port :${p.port}`
    });
  }

  // Excessive length — phishing kits often append a long fake path/query to
  // bury the real host below the visible address-bar viewport.
  if (p.href.length > 100) {
    out.push({
      id: "url.long",
      stage: "stage1",
      weight: LONG_URL_WEIGHT,
      detail: `URL is ${p.href.length} chars`
    });
  }

  // Many hyphens in hostname — "secure-paypal-login-update.example.tk" pattern.
  const hyphens = (p.hostname.match(/-/g) ?? []).length;
  if (hyphens >= 4) {
    out.push({
      id: "url.many_hyphens",
      stage: "stage1",
      weight: MANY_HYPHENS_WEIGHT,
      detail: `${hyphens} hyphens in hostname`
    });
  }

  // Deep subdomain chain — "paypal.com.evil.tk.something.host" pattern, but
  // also common for legit CDNs. Only flag at 4+ labels in subdomain.
  const subLabels = p.subdomain ? p.subdomain.split(".").length : 0;
  if (subLabels >= 4) {
    out.push({
      id: "url.many_subdomains",
      stage: "stage1",
      weight: MANY_SUBDOMAINS_WEIGHT,
      detail: `${subLabels} subdomain labels`
    });
  }

  // High Shannon entropy in the path — algorithmically generated phishing URLs
  // (e.g. /a3f9c2e1b8d7/login) have entropy >4.0 in path body. Skip empty paths
  // and very short ones to avoid false positives on short legit paths.
  const pathBody = p.pathname.replace(/[/.\-_]/g, "");
  if (pathBody.length >= 16 && shannonEntropy(pathBody) > 4.0) {
    out.push({
      id: "url.high_entropy_path",
      stage: "stage1",
      weight: HIGH_ENTROPY_WEIGHT,
      detail: `path body length=${pathBody.length} entropy>${4.0}`
    });
  }

  // Double percent-encoding — `%25` after decoding becomes `%`, so a URL with
  // `%2525` got encoded twice. Legitimate sites rarely do this; obfuscation kits do.
  if (/%25[0-9a-fA-F]{2}/.test(p.href)) {
    out.push({
      id: "url.double_encoded",
      stage: "stage1",
      weight: DOUBLE_ENCODING_WEIGHT,
      detail: "URL contains double percent-encoding (%25XX)"
    });
  }

  return out;
}
