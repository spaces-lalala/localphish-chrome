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

# URL-level
W_NONSTANDARD_PORT = 8
W_IP_HOST = 30
W_AT_SIGN = 25
W_LONG_URL = 6
W_MANY_HYPHENS = 4
W_MANY_SUBDOMAINS = 7
W_HIGH_ENTROPY_PATH = 10
W_DOUBLE_ENCODING = 12

# Homograph (Punycode skipped in Python port — tldextract gives us the decoded
# form already; mixed-script detection would need a Unicode confusables table
# we don't yet ship. Leave a stub.)

# Typosquat — weights tuned against Tier A first run (TIER_A_FIRST_RUN.md).
# url.typosquat_brand precision 0.222 → +40 → +25.
# url.path_brand_abuse precision 0.200 → +10 → +5.
# subdomain_brand_abuse kept at +35 (too rare on PhreshPhish to recalibrate,
# but it's the load-bearing signal for the TW post-customs / 國稅 / ETC fixtures).
W_TYPOSQUAT = 25
W_SUBDOMAIN_BRAND_ABUSE = 35
W_PATH_BRAND_ABUSE = 5

# Suspicious TLD (read from JSON table — three tiers).

# fake-gov-tw (台灣本土)
W_GOV_TW_SUBSTRING = 40
W_GOV_TW_PSEUDO_TLD = 35
W_GOV_TW_HYPHEN_VARIANT = 30

# DOM
W_PASSWORD_NO_TLS = 25
W_PASSWORD_CROSS_ETLD1 = 35
W_OTP_CROSS_ETLD1 = 25
W_CARD_CROSS_ETLD1 = 30
W_CARD_AND_PASSWORD = 12
W_SEED_PHRASE = 45

# Cross-strait language
W_CROSS_STRAIT = 25
W_CROSS_STRAIT_STRONG = 35

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
class RuleData:
    allowlist: set[str]
    brands: list[Brand]
    brand_canonical_domains: set[str]
    brand_labels_by_canonical: list[Brand] = field(default_factory=list)
    brand_alias_index: dict[str, Brand] = field(default_factory=dict)
    tld_table: dict[str, tuple[int, set[str]]] = field(default_factory=dict)  # tier → (weight, tlds)


def load_rule_data(data_dir: Path) -> RuleData:
    """Load all reference JSONs from extension/src/data/."""
    tranco = json.loads((data_dir / "tranco-sample.json").read_text(encoding="utf-8"))
    brands_raw = json.loads((data_dir / "brand-list.json").read_text(encoding="utf-8"))
    tlds_raw = json.loads((data_dir / "suspicious-tlds.json").read_text(encoding="utf-8"))

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
        tld_table=tld_table
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

    sigs: list[Signal] = []
    sigs.extend(url_feature_signals(p))
    sigs.extend(typosquat_signals(p, data))
    sigs.extend(suspicious_tld_signals(p, data))
    sigs.extend(fake_gov_tw_signals(p))
    score = min(100, sum(s.weight for s in sigs))
    return {"rawScore": score, "signals": sigs, "shortCircuit": score >= DANGER_FLOOR, "parsed": p}
