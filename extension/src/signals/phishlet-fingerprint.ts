// Stage 1 — phishlet URL endpoint fingerprint.
//
// Threat model. Evilginx, EvilProxy, Caffeine, Modlishka all ship with
// default phishlet configurations that route victim traffic through
// signature URL paths. Even when the attacker hosts on a "clean" hostname
// (newly registered, no brand string), the URL path often leaks the
// phishlet by way of an OAuth-style endpoint, OpenID discovery doc, or
// keep-alive callback that has no business being on a non-IDP host.
//
// Patterns below are sourced from:
//   - Evilginx 2 default phishlet config (login_data, sso_login)
//   - Microsoft's own login flow paths repurposed on attacker hosts
//   - Google OAuth flow paths repurposed on attacker hosts
//   - OpenID Connect discovery URL on non-IDP domains
//
// Each pattern is regex-tested against the URL pathname; a hit pushes a
// medium-strong signal. We gate every pattern on "page is NOT on the
// canonical IDP host" — otherwise we'd flag the real login.microsoftonline.com.

import type { Signal } from "@/types";
import type { ParsedUrl } from "./parse-url";
import { weight as W } from "./weights";

interface PhishletPattern {
  /** Regex against the URL pathname (lowercased). */
  re: RegExp;
  /** Set of canonical eTLD+1s where this path is legitimate; skip the match if page is on one. */
  legitOnEtld1s: ReadonlySet<string>;
  /** Human description for the signal detail. */
  description: string;
}

const PATTERNS: PhishletPattern[] = [
  // Microsoft OAuth/login endpoints on non-Microsoft hosts. The real domain
  // is `login.microsoftonline.com` / `login.live.com` / `account.live.com`.
  {
    re: /\/(?:common|organizations|consumers)?\/?oauth2\/(?:v2\.0\/)?authorize/i,
    legitOnEtld1s: new Set([
      "microsoftonline.com",
      "live.com",
      "microsoft.com",
      "office.com",
      "azure.com",
      "windows.net"
    ]),
    description: "Microsoft-style OAuth /oauth2/authorize endpoint on a non-Microsoft host"
  },
  // Google OAuth endpoints. Real domain: `accounts.google.com`.
  {
    re: /\/o\/oauth2\/(?:v2\/)?auth(?:\b|\/)/i,
    legitOnEtld1s: new Set(["google.com", "googleapis.com"]),
    description: "Google-style OAuth /o/oauth2/auth endpoint on a non-Google host"
  },
  // OpenID Connect discovery doc on a non-IDP host. Real IDPs publish this,
  // but a SaaS phishing host has no reason to.
  {
    re: /\/\.well-known\/openid-configuration\b/i,
    legitOnEtld1s: new Set([
      "microsoftonline.com",
      "google.com",
      "googleapis.com",
      "apple.com",
      "okta.com",
      "auth0.com",
      "amazoncognito.com"
    ]),
    description: "OIDC discovery endpoint /.well-known/openid-configuration on a non-IDP host"
  },
  // Evilginx default login_data callback (collects victim cookies).
  {
    re: /\/login[_-]?data(?:\?|$|\/)/i,
    legitOnEtld1s: new Set(),
    description: "Evilginx default /login_data endpoint — credential collection callback"
  },
  // Evilginx default sso_login path.
  {
    re: /\/sso[_-]?login(?:\?|$|\/)/i,
    legitOnEtld1s: new Set([
      "okta.com",
      "auth0.com",
      "duosecurity.com",
      "onelogin.com",
      "pingidentity.com"
    ]),
    description: "Phishlet-style /sso_login endpoint on a non-IDP host"
  },
  // Microsoft "kmsi" (keep me signed in) flow ID — phishlets pre-populate.
  {
    re: /\/kmsi(?:\?|$|\/)/i,
    legitOnEtld1s: new Set(["microsoftonline.com", "live.com", "microsoft.com"]),
    description: "Microsoft KMSI endpoint replayed on a non-Microsoft host"
  }
];

export function phishletSignals(p: ParsedUrl): Signal[] {
  const out: Signal[] = [];
  if (!p.etld1) return out;

  const lowerEtld1 = p.etld1.toLowerCase();
  const path = (p.pathname || "/").toLowerCase();

  for (const pat of PATTERNS) {
    if (pat.legitOnEtld1s.has(lowerEtld1)) continue;
    if (pat.re.test(path)) {
      out.push({
        id: "url.phishlet_endpoint",
        stage: "stage1",
        weight: W("url.phishlet_endpoint"),
        detail: pat.description
      });
      // Only one phishlet signal per URL; multiple hits would double-count.
      return out;
    }
  }

  return out;
}
