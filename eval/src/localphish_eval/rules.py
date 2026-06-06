"""Python port of the extension's Stage 1 + Stage 2-lite detectors.

The browser extension is TypeScript; for offline batch evaluation we re-
implement the rules in Python with identical weights so Tier A numbers are
the rule-layer baseline that Tier B (Playwright loading the real extension)
will eventually be compared against.

If a future refactor changes a weight in the extension, the corresponding
constant here must move in lockstep — there's a regression test idea for
Week 15 (run the extension Stage 1 over a small URL set, diff results
against this module).
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import tldextract


# ---------------------------------------------------------------- weights ---
#
# Single source of truth: extension/src/data/signal-spec.json. Both this
# Python eval port and the TS extension read weights from the same file —
# previously every weight tweak had to be mirrored manually, and drift was
# caught only via Tier B parity checks after-the-fact (Week 16 §10 條 23).
# Stage 0 of Week 16 v3 resolves this.

_SPEC_PATH = (
    Path(__file__).resolve().parents[3]
    / "extension" / "src" / "data" / "signal-spec.json"
)


def _load_spec() -> dict:
    return json.loads(_SPEC_PATH.read_text(encoding="utf-8"))


_SPEC = _load_spec()
_SIGNALS = _SPEC["signals"]
_CAPS = _SPEC.get("_caps", {})


def signal_weight(signal_id: str) -> int:
    sig = _SIGNALS.get(signal_id)
    if sig is None:
        raise KeyError(f"signal-spec: unknown signal id {signal_id!r}")
    return int(sig["weight"])


def signal_cap(cap_id: str) -> int:
    c = _CAPS.get(cap_id)
    if c is None:
        raise KeyError(f"signal-spec: unknown cap id {cap_id!r}")
    return int(c)


# Legacy W_* names kept as module-level constants populated from the spec so
# existing detector functions continue to work without per-line refactor.
# DO NOT add new W_* constants here — emit signals with literal IDs and call
# signal_weight() at the call site.
W_NONSTANDARD_PORT          = signal_weight("url.nonstandard_port")
W_IP_HOST                   = signal_weight("url.ip_as_host")
W_AT_SIGN                   = signal_weight("url.userinfo_at")
W_LONG_URL                  = signal_weight("url.long")
W_MANY_HYPHENS              = signal_weight("url.many_hyphens")
W_MANY_SUBDOMAINS           = signal_weight("url.many_subdomains")
W_HIGH_ENTROPY_PATH         = signal_weight("url.high_entropy_path")
W_DOUBLE_ENCODING           = signal_weight("url.double_encoded")
W_TYPOSQUAT                 = signal_weight("url.typosquat_brand")
W_SUBDOMAIN_BRAND_ABUSE     = signal_weight("url.subdomain_brand_abuse")
W_PATH_BRAND_ABUSE          = signal_weight("url.path_brand_abuse")
W_GOV_TW_SUBSTRING          = signal_weight("url.gov_tw_substring_abuse")
W_GOV_TW_PSEUDO_TLD         = signal_weight("url.gov_tw_pseudo_tld")
W_GOV_TW_HYPHEN_VARIANT     = signal_weight("url.gov_tw_hyphen_variant")
W_REVERSE_PROXY_FQDN        = signal_weight("url.reverse_proxy_fqdn")
W_REVERSE_PROXY_HYPHEN_FQDN = signal_weight("url.reverse_proxy_hyphen_fqdn")
W_PHISHLET                  = signal_weight("url.phishlet_endpoint")
W_URL_ZERO_WIDTH            = signal_weight("url.zero_width_in_host")
W_URL_BIDI_OVERRIDE         = signal_weight("url.bidi_override_in_host")
W_URL_TAG_CHAR              = signal_weight("url.tag_char_in_url")

W_PASSWORD_NO_TLS           = signal_weight("dom.password_no_tls")
W_PASSWORD_CROSS_ETLD1      = signal_weight("dom.password_cross_etld1_post")
W_OTP_CROSS_ETLD1           = signal_weight("dom.otp_cross_etld1_post")
W_CARD_CROSS_ETLD1          = signal_weight("dom.card_cross_etld1_post")
W_CARD_AND_PASSWORD         = signal_weight("dom.card_and_password")
W_SEED_PHRASE               = signal_weight("dom.seed_phrase_grid")
W_CROSS_STRAIT              = signal_weight("dom.cross_strait_terms")
W_CROSS_STRAIT_STRONG       = signal_weight("dom.cross_strait_terms_strong")
W_ANTI_DEBUG                = signal_weight("dom.anti_debug")

# Verdict thresholds (mirror cascade.ts)
DANGER_FLOOR = 85
SAFE_CEILING = 15


# ----------------------------------------------------------- data loaders ---


@dataclass
class Brand:
    name: str
    domain: str
    aliases: list[str]
    label: str = ""  # domain-without-suffix; filled at load time


@dataclass
class BloomFilter:
    """Read-only bloom filter mirroring extension/src/signals/bloom.ts. Same
    hash family (double FNV-1a 32-bit + Kirsch–Mitzenmacher synthesis), same
    bit packing (MSB-first), so a row that hits in Python also hits in TS.
    """
    m_bits: int
    k_hashes: int
    n_inserted: int
    seed_a: int
    seed_b: int
    bits: bytes

    def has(self, domain: str) -> bool:
        if self.n_inserted == 0 or self.m_bits == 0 or not domain:
            return False
        d = domain.lower()
        encoded = d.encode("utf-8")
        # Match the TS strip-www behaviour (feed entries are pre-stripped).
        candidates = [encoded]
        if d.startswith("www."):
            candidates.append(d[4:].encode("utf-8"))
        for b in candidates:
            if self._has_bytes(b):
                return True
        return False

    def _has_bytes(self, b: bytes) -> bool:
        h1 = _fnv1a(b, self.seed_a)
        h2 = _fnv1a(b, self.seed_b) | 1
        m = self.m_bits
        for i in range(self.k_hashes):
            pos = ((h1 + i * h2) & 0xFFFFFFFF) % m
            byte_idx = pos // 8
            mask = 1 << (7 - (pos % 8))
            if not (self.bits[byte_idx] & mask):
                return False
        return True


_FNV_PRIME = 0x01000193


def _fnv1a(data: bytes, seed: int) -> int:
    h = seed & 0xFFFFFFFF
    for byte in data:
        h ^= byte
        h = (h * _FNV_PRIME) & 0xFFFFFFFF
    return h


def _empty_bloom() -> BloomFilter:
    return BloomFilter(
        m_bits=0,
        k_hashes=0,
        n_inserted=0,
        seed_a=0x811C9DC5,
        seed_b=0xCBF29CE4,
        bits=b"",
    )


@dataclass
class RuleData:
    allowlist: set[str]
    brands: list[Brand]
    brand_canonical_domains: set[str]
    brand_labels_by_canonical: list[Brand] = field(default_factory=list)
    brand_alias_index: dict[str, Brand] = field(default_factory=dict)
    tld_table: dict[str, tuple[int, set[str]]] = field(default_factory=dict)  # tier → (weight, tlds)
    idp_allowlist: set[str] = field(default_factory=set)
    tw_allowlist: set[str] = field(default_factory=set)
    bloom: BloomFilter = field(default_factory=_empty_bloom)


def load_rule_data(data_dir: Path) -> RuleData:
    """Load all reference JSONs from extension/src/data/."""
    tranco = json.loads((data_dir / "tranco-sample.json").read_text(encoding="utf-8"))
    brands_raw = json.loads((data_dir / "brand-list.json").read_text(encoding="utf-8"))
    tlds_raw = json.loads((data_dir / "suspicious-tlds.json").read_text(encoding="utf-8"))
    idp_path = data_dir / "known-idp-allowlist.json"
    idp_raw = (
        json.loads(idp_path.read_text(encoding="utf-8"))
        if idp_path.exists()
        else {"etld1s": []}
    )
    tw_path = data_dir / "taiwan-allowlist.json"
    tw_raw = (
        json.loads(tw_path.read_text(encoding="utf-8"))
        if tw_path.exists()
        else {"domains": []}
    )
    bloom_path = data_dir / "tw-scam-bloom.json"
    if bloom_path.exists():
        bspec = json.loads(bloom_path.read_text(encoding="utf-8"))
        import base64
        bloom = BloomFilter(
            m_bits=int(bspec["m_bits"]),
            k_hashes=int(bspec["k_hashes"]),
            n_inserted=int(bspec["n_inserted"]),
            seed_a=int(bspec["fnv_offset_a"]),
            seed_b=int(bspec["fnv_offset_b"]),
            bits=base64.b64decode(bspec["bits_b64"]),
        )
    else:
        bloom = _empty_bloom()

    brands: list[Brand] = []
    canonical: set[str] = set()
    alias_idx: dict[str, Brand] = {}
    for b in brands_raw["brands"]:
        label = b["domain"].split(".")[0]
        brand = Brand(
            name=b["name"],
            domain=b["domain"].lower(),
            aliases=[a.lower() for a in b.get("aliases", [])],
            label=label
        )
        brands.append(brand)
        canonical.add(brand.domain)
        for a in brand.aliases:
            alias_idx.setdefault(a, brand)

    tld_table: dict[str, tuple[int, set[str]]] = {}
    for tier in ("high", "medium", "low"):
        section = tlds_raw[tier]
        tld_table[tier] = (
            int(section["_weight"]),
            {t.lower() for t in section["tlds"]}
        )

    return RuleData(
        allowlist={d.lower() for d in tranco["domains"]},
        brands=brands,
        brand_canonical_domains=canonical,
        brand_alias_index=alias_idx,
        tld_table=tld_table,
        idp_allowlist={d.lower() for d in idp_raw.get("etld1s", [])},
        tw_allowlist={d.lower() for d in tw_raw.get("domains", [])},
        bloom=bloom,
    )


# ------------------------------------------------------------- URL parse ---


@dataclass
class ParsedUrl:
    href: str
    protocol: str
    hostname: str
    pathname: str
    port: str
    etld1: str | None
    domain_label: str | None
    subdomain: str
    is_ip: bool


def parse_url(raw: str) -> ParsedUrl | None:
    try:
        u = urlparse(raw)
    except ValueError:
        return None
    if not u.scheme or not u.hostname:
        return None
    ext = tldextract.extract(u.hostname)
    return ParsedUrl(
        href=raw,
        protocol=u.scheme + ":",
        hostname=u.hostname,
        pathname=u.path or "/",
        port=str(u.port) if u.port else "",
        etld1=f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None,
        domain_label=ext.domain or None,
        subdomain=ext.subdomain or "",
        is_ip=bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", u.hostname))
                or u.hostname.startswith("[")
    )


# ----------------------------------------------------------- signal type ---


@dataclass
class Signal:
    id: str
    stage: str
    weight: int
    detail: str = ""


# ---------------------------------------------------- URL feature signals ---


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def url_feature_signals(p: ParsedUrl) -> list[Signal]:
    out: list[Signal] = []
    if p.is_ip:
        out.append(Signal("url.ip_as_host", "stage1", W_IP_HOST, f"IP literal: {p.hostname}"))
    # @-sign userinfo
    before_host = p.href.split("://", 1)[1].split("/", 1)[0] if "://" in p.href else ""
    if "@" in before_host:
        out.append(Signal("url.userinfo_at", "stage1", W_AT_SIGN, "URL contains '@' before host"))
    if p.port and p.port not in ("80", "443"):
        out.append(Signal("url.nonstandard_port", "stage1", W_NONSTANDARD_PORT, f":{p.port}"))
    if len(p.href) > 100:
        out.append(Signal("url.long", "stage1", W_LONG_URL, f"{len(p.href)} chars"))
    hyphens = p.hostname.count("-")
    if hyphens >= 4:
        out.append(Signal("url.many_hyphens", "stage1", W_MANY_HYPHENS, f"{hyphens} hyphens"))
    sub_labels = len(p.subdomain.split(".")) if p.subdomain else 0
    if sub_labels >= 4:
        out.append(Signal("url.many_subdomains", "stage1", W_MANY_SUBDOMAINS, f"{sub_labels} labels"))
    path_body = re.sub(r"[/.\-_]", "", p.pathname)
    if len(path_body) >= 16 and _shannon_entropy(path_body) > 4.0:
        out.append(Signal("url.high_entropy_path", "stage1", W_HIGH_ENTROPY_PATH,
                          f"path body length={len(path_body)}"))
    if re.search(r"%25[0-9a-fA-F]{2}", p.href):
        out.append(Signal("url.double_encoded", "stage1", W_DOUBLE_ENCODING, "double percent-encoded"))
    return out


# -------------------------------------------------------- typosquat signals -


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def typosquat_signals(p: ParsedUrl, data: RuleData) -> list[Signal]:
    out: list[Signal] = []
    if not p.etld1 or not p.domain_label:
        return out
    lower_label = p.domain_label.lower()
    is_canonical = p.etld1.lower() in data.brand_canonical_domains

    if not is_canonical:
        for brand in data.brands:
            if abs(len(brand.label) - len(lower_label)) > 2:
                continue
            if brand.label == lower_label:
                continue
            if len(brand.label) < 4:
                continue
            d = _levenshtein(brand.label, lower_label)
            if 0 < d <= 2:
                out.append(Signal("url.typosquat_brand", "stage1", W_TYPOSQUAT,
                                  f"label '{lower_label}' is edit-distance {d} from brand '{brand.name}'"))
                break

    if p.subdomain and not is_canonical:
        for sub_label in p.subdomain.lower().split("."):
            brand = data.brand_alias_index.get(sub_label)
            if brand and brand.domain != p.etld1.lower():
                out.append(Signal("url.subdomain_brand_abuse", "stage1", W_SUBDOMAIN_BRAND_ABUSE,
                                  f"subdomain contains brand '{brand.name}' but eTLD+1 is '{p.etld1}'"))
                break

    if not is_canonical and len(p.pathname) > 1:
        lower_path = p.pathname.lower()
        for alias, brand in data.brand_alias_index.items():
            if len(alias) < 4:
                continue
            if not re.search(rf"(^|[/\-_]){re.escape(alias)}([/\-_]|$)", lower_path):
                continue
            if brand.domain == (p.etld1 or "").lower():
                continue
            out.append(Signal("url.path_brand_abuse", "stage1", W_PATH_BRAND_ABUSE,
                              f"path mentions brand '{brand.name}' but eTLD+1 is '{p.etld1}'"))
            break

    return out


# ----------------------------------------------------- suspicious-tld signals


def suspicious_tld_signals(p: ParsedUrl, data: RuleData) -> list[Signal]:
    if not p.etld1:
        return []
    tld = p.etld1.split(".")[-1].lower()
    for tier in ("high", "medium", "low"):
        weight, tlds = data.tld_table[tier]
        if tld in tlds:
            return [Signal(f"url.tld_{tier}_risk", "stage1", weight, f"'.{tld}' is on {tier}-risk list")]
    return []


# ----------------------------------------------------- reverse-proxy fingerprint


# Mirror of AUTH_FQDNS in extension/src/signals/reverse-proxy.ts. Keep in sync
# when adding a brand. These are the well-known auth FQDNs phishlets embed.
_AUTH_FQDNS: set[str] = {
    "login.microsoftonline.com", "login.microsoft.com", "login.live.com",
    "account.live.com", "login.windows.net",
    "accounts.google.com",
    "appleid.apple.com", "idmsa.apple.com",
    "signin.aws.amazon.com", "signin.amazon.com",
    "login.yahoo.com",
    "login.facebook.com", "m.facebook.com",
    "auth.services.adobe.com",
    "login.coinbase.com", "accounts.binance.com",
    "login.okta.com",
    "www.dropbox.com", "github.com", "www.linkedin.com",
    "ibank.cathaybk.com.tw", "netbank.esunbank.com.tw",
    "ebank.megabank.com.tw", "ebank.firstbank.com.tw",
    "www.post.gov.tw",
}


def reverse_proxy_signals(p: ParsedUrl, data: RuleData) -> list[Signal]:
    """Port of extension/src/signals/reverse-proxy.ts."""
    out: list[Signal] = []
    if not p.etld1 or not p.hostname:
        return out
    lower_host = p.hostname.lower()
    lower_etld1 = p.etld1.lower()
    if lower_etld1 in data.brand_canonical_domains:
        return out
    if lower_host in _AUTH_FQDNS:
        return out

    needles: set[str] = set()
    for d in data.brand_canonical_domains:
        if "." in d:
            needles.add(d)
    needles.update(_AUTH_FQDNS)

    # 1. Brand FQDN as label-bounded substring in attacker hostname.
    padded = f".{lower_host}."
    for brand_domain in needles:
        if lower_host == brand_domain:
            continue
        needle = f".{brand_domain}."
        at = padded.find(needle)
        if at < 0:
            continue
        if at + len(needle) == len(padded):
            continue  # canonical edge
        out.append(Signal(
            "url.reverse_proxy_fqdn", "stage1", W_REVERSE_PROXY_FQDN,
            f"hostname embeds brand FQDN '{brand_domain}' (page eTLD+1 '{lower_etld1}')"
        ))
        return out

    # 2. Hyphen-flattened variant.
    for label in lower_host.split("."):
        if "-" not in label or len(label) < 10:
            continue
        unfolded = label.replace("-", ".")
        for brand_domain in needles:
            if unfolded == brand_domain or unfolded.endswith("." + brand_domain):
                out.append(Signal(
                    "url.reverse_proxy_hyphen_fqdn", "stage1", W_REVERSE_PROXY_HYPHEN_FQDN,
                    f"label '{label}' decodes to '{unfolded}' embedding brand FQDN '{brand_domain}'"
                ))
                return out
    return out


# ------------------------------------------------------- phishlet fingerprint


_PHISHLET_PATTERNS: list[tuple[re.Pattern[str], set[str], str]] = [
    (re.compile(r"/(?:common|organizations|consumers)?/?oauth2/(?:v2\.0/)?authorize", re.IGNORECASE),
     {"microsoftonline.com", "live.com", "microsoft.com", "office.com", "azure.com", "windows.net"},
     "Microsoft-style /oauth2/authorize endpoint on non-Microsoft host"),
    (re.compile(r"/o/oauth2/(?:v2/)?auth(?:\b|/)", re.IGNORECASE),
     {"google.com", "googleapis.com"},
     "Google-style /o/oauth2/auth endpoint on non-Google host"),
    (re.compile(r"/\.well-known/openid-configuration\b", re.IGNORECASE),
     {"microsoftonline.com", "google.com", "googleapis.com", "apple.com",
      "okta.com", "auth0.com", "amazoncognito.com"},
     "OIDC discovery endpoint on non-IDP host"),
    (re.compile(r"/login[_-]?data(?:\?|$|/)", re.IGNORECASE),
     set(),
     "Evilginx default /login_data callback"),
    (re.compile(r"/sso[_-]?login(?:\?|$|/)", re.IGNORECASE),
     {"okta.com", "auth0.com", "duosecurity.com", "onelogin.com", "pingidentity.com"},
     "Phishlet-style /sso_login on non-IDP host"),
    (re.compile(r"/kmsi(?:\?|$|/)", re.IGNORECASE),
     {"microsoftonline.com", "live.com", "microsoft.com"},
     "Microsoft KMSI endpoint replayed on non-Microsoft host"),
]


def phishlet_signals(p: ParsedUrl) -> list[Signal]:
    out: list[Signal] = []
    if not p.etld1:
        return out
    lower_etld1 = p.etld1.lower()
    path = (p.pathname or "/").lower()
    for pat, legit, desc in _PHISHLET_PATTERNS:
        if lower_etld1 in legit:
            continue
        if pat.search(path):
            out.append(Signal("url.phishlet_endpoint", "stage1", W_PHISHLET, desc))
            return out
    return out


# ------------------------------------------------------- unicode trickery (URL)


_ZERO_WIDTH_RE = re.compile(r"[​-‍⁠﻿᠎]")
_BIDI_OVERRIDE_RE = re.compile(r"[‪-‮⁦-⁩]")
_TAG_CHAR_RE = re.compile(r"[\U000E0000-\U000E007F]")


def _safe_unquote(s: str) -> str:
    """urllib.unquote always succeeds, but it leaves invalid sequences alone — same effective behavior as JS safeDecode wrapping decodeURIComponent."""
    from urllib.parse import unquote
    try:
        return unquote(s)
    except Exception:
        return s


def unicode_trickery_url_signals(p: ParsedUrl) -> list[Signal]:
    out: list[Signal] = []
    # Test both the parser-normalized form and the percent-decoded form so
    # %E2%80%AE etc. are caught even though urllib keeps it escaped.
    host = p.hostname + " " + _safe_unquote(p.hostname)
    href = p.href + " " + _safe_unquote(p.href)
    if _ZERO_WIDTH_RE.search(host):
        out.append(Signal("url.zero_width_in_host", "stage1", W_URL_ZERO_WIDTH,
                          "hostname contains zero-width character(s)"))
    elif _ZERO_WIDTH_RE.search(href):
        out.append(Signal("url.zero_width_in_url", "stage1", round(W_URL_ZERO_WIDTH * 0.6),
                          "URL path/query contains zero-width character(s)"))
    if _BIDI_OVERRIDE_RE.search(host):
        out.append(Signal("url.bidi_override_in_host", "stage1", W_URL_BIDI_OVERRIDE,
                          "hostname contains bidi-override character"))
    elif _BIDI_OVERRIDE_RE.search(href):
        out.append(Signal("url.bidi_override_in_url", "stage1", round(W_URL_BIDI_OVERRIDE * 0.7),
                          "URL contains bidi-override character"))
    if _TAG_CHAR_RE.search(href):
        out.append(Signal("url.tag_char_in_url", "stage1", W_URL_TAG_CHAR,
                          "URL contains invisible tag character"))
    return out


# ---------------------------------------------------------- fake-gov-tw -----


def fake_gov_tw_signals(p: ParsedUrl) -> list[Signal]:
    out: list[Signal] = []
    if (p.etld1 or "").lower().endswith(".gov.tw"):
        return out
    host = p.hostname.lower()
    if re.search(r"(^|\.)gov\.tw\.", host):
        out.append(Signal("url.gov_tw_substring_abuse", "stage1", W_GOV_TW_SUBSTRING,
                          f"hostname '{host}' contains 'gov.tw.' segment"))
    if p.etld1 and re.search(r"\bgov\.tw\.[a-z]{2,}$", p.etld1.lower()):
        out.append(Signal("url.gov_tw_pseudo_tld", "stage1", W_GOV_TW_PSEUDO_TLD,
                          f"eTLD+1 '{p.etld1}' uses 'gov.tw' as a fake prefix"))
    if p.domain_label and p.domain_label.lower() in {"gov-tw", "govtw", "tw-gov", "twgov"}:
        out.append(Signal("url.gov_tw_hyphen_variant", "stage1", W_GOV_TW_HYPHEN_VARIANT,
                          f"domain label '{p.domain_label}' mimics .gov.tw"))
    return out


# ------------------------------------------------------- stage 1 orchestrator


def run_stage1(url: str, data: RuleData) -> dict:
    p = parse_url(url)
    if p is None:
        return {"rawScore": 0, "signals": [Signal("url.parse_failed", "stage1", 0, url[:80])],
                "shortCircuit": True, "parsed": None}
    if p.protocol not in ("http:", "https:"):
        return {"rawScore": 0, "signals": [], "shortCircuit": True, "parsed": p}
    if p.etld1 and p.etld1.lower() in data.allowlist:
        return {
            "rawScore": 0,
            "signals": [Signal("url.allowlist_hit", "stage1", 0, f"'{p.etld1}' on Tranco allow-list")],
            "shortCircuit": True,
            "parsed": p
        }
    # TWNIC institutional-TLD short-circuit (mirror of stage1.ts logic).
    # Must come BEFORE the TW allowlist + bloom so a poisoned bloom can
    # never burn a legit .gov.tw / .edu.tw site.
    if p.etld1:
        lower = p.etld1.lower()
        if lower.endswith(".edu.tw") or lower.endswith(".gov.tw"):
            return {
                "rawScore": 0,
                "signals": [Signal(
                    "url.tw_institutional_tld", "stage1", 0,
                    f"'{p.etld1}' is a TWNIC-verified institutional TLD")],
                "shortCircuit": True,
                "parsed": p
            }

    # Taiwan first-class allowlist (mirror of stage1.ts logic).
    if p.etld1 and p.etld1.lower() in data.tw_allowlist:
        return {
            "rawScore": 0,
            "signals": [Signal(
                "url.tw_allowlist_hit", "stage1", 0,
                f"'{p.etld1}' on the Taiwan-curated institution allow-list")],
            "shortCircuit": True,
            "parsed": p
        }

    # On-device 165 / 警政署 bloom-filter check (mirror of stage1.ts logic).
    # Runs AFTER all allowlist short-circuits.
    host_for_bloom = (p.hostname or "").lower()
    etld1_for_bloom = (p.etld1 or "").lower()
    if data.bloom.has(host_for_bloom) or (etld1_for_bloom and data.bloom.has(etld1_for_bloom)):
        bw = signal_weight("url.bloomfilter_blacklist_hit")
        return {
            "rawScore": bw,
            "signals": [Signal(
                "url.bloomfilter_blacklist_hit", "stage1", bw,
                f"hostname matches the on-device 165 反詐騙 phishing-domain feed (eTLD+1 '{p.etld1}')")],
            "shortCircuit": True,
            "parsed": p,
        }

    sigs: list[Signal] = []
    sigs.extend(url_feature_signals(p))
    sigs.extend(typosquat_signals(p, data))
    sigs.extend(suspicious_tld_signals(p, data))
    sigs.extend(fake_gov_tw_signals(p))
    sigs.extend(reverse_proxy_signals(p, data))
    sigs.extend(phishlet_signals(p))
    sigs.extend(unicode_trickery_url_signals(p))
    score = min(100, sum(s.weight for s in sigs))
    return {"rawScore": score, "signals": sigs, "shortCircuit": score >= DANGER_FLOOR, "parsed": p}
