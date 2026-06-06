"""Python port of the extension's Stage 2 DOM-feature scoring.

Reads an HTML excerpt with BeautifulSoup and emits the same Signal[] shape
as the extension's content script + SW combined. Weights mirror
extension/src/signals/stage2.ts so Tier A is a faithful rule-layer baseline.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from bs4 import BeautifulSoup
import tldextract

from .rules import (
    RuleData,
    Signal,
    W_ANTI_DEBUG,
    W_CARD_AND_PASSWORD,
    W_CARD_CROSS_ETLD1,
    W_CROSS_STRAIT,
    W_CROSS_STRAIT_STRONG,
    W_OTP_CROSS_ETLD1,
    W_PASSWORD_CROSS_ETLD1,
    W_PASSWORD_NO_TLS,
    W_SEED_PHRASE,
    signal_weight,
    signal_cap,
)

# All weights live in extension/src/data/signal-spec.json. Stage 2 weights
# previously inlined here are now derived from the same spec the TS extension
# reads; see rules.py header for the rationale.
W_VERIFY_WALL                = signal_weight("dom.cloaking_verify_wall")
W_VERIFY_WALL_STRONG         = signal_weight("dom.cloaking_verify_wall_strong")
W_FAVICON_BRAND_MISMATCH     = signal_weight("dom.favicon_brand_cdn_mismatch")
W_TEXT_ZERO_WIDTH            = signal_weight("dom.zero_width_in_text")
W_TEXT_BIDI_OVERRIDE         = signal_weight("dom.bidi_override_in_text")
W_TEXT_TAG_CHAR              = signal_weight("dom.tag_char_in_text")
W_TW_PII_COMBO               = signal_weight("dom.tw_pii_combo")
W_TW_NATIONAL_ID_CROSS_ETLD1 = signal_weight("dom.tw_national_id_cross_etld1_post")

# Stage 2 detectors that the original Python port skipped because BS4 has no
# layout engine. We port lossy versions that catch *inline style / attribute*
# hints — these still fire on cheap phishing kits which set display:none
# directly on the iframe, and miss the kits that use CSS-class-driven hides
# (only Tier B with a real DOM can catch those). Loss-of-coverage is
# documented in TIER_A_FOURTH_RUN.md.
W_HIDDEN_IFRAME              = signal_weight("dom.hidden_iframes")
W_HIDDEN_IFRAME_CAP          = signal_cap("dom.hidden_iframes_cap")
W_MANY_FOREIGN_SCRIPTS       = signal_weight("dom.many_foreign_scripts")
W_TINY_ELEMENT               = signal_weight("dom.tiny_interactive")  # not reachable from BS4 without layout — kept for parity

VERIFY_WALL_TEXT_THRESHOLD = 300

_ZERO_WIDTH_RE = re.compile(r"[​-‍⁠﻿᠎]")
_BIDI_OVERRIDE_RE = re.compile(r"[‪-‮⁦-⁩]")
_TAG_CHAR_RE = re.compile(r"[\U000E0000-\U000E007F]")


def _load_favicon_cdn_map(data_dir: Path) -> dict[str, tuple[str, str]]:
    """Return {favicon-host eTLD+1 -> (brand-name, canonical-domain)}."""
    p = data_dir / "brand-favicon-cdns.json"
    if not p.exists():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, tuple[str, str]] = {}
    for e in raw.get("brands", []):
        canonical = e["domain"].lower()
        out[canonical] = (e["brand"], canonical)
        for cdn in e.get("cdns", []):
            out[cdn.lower()] = (e["brand"], canonical)
    return out


_FAVICON_MAP_CACHE: dict[str, tuple[str, str]] | None = None


def _favicon_map(data_dir: Path | None) -> dict[str, tuple[str, str]]:
    global _FAVICON_MAP_CACHE
    if _FAVICON_MAP_CACHE is None and data_dir is not None:
        _FAVICON_MAP_CACHE = _load_favicon_cdn_map(data_dir)
    return _FAVICON_MAP_CACHE or {}


_ANTI_DEBUG_SCRIPT_PATTERNS = [
    re.compile(r"\bkeyCode\s*===?\s*123\b"),
    re.compile(r"\be\.key(?:Code)?\s*===?\s*['\"]?F12['\"]?"),
    re.compile(r"\bctrlKey[^;]*shiftKey[^;]*(?:73|74)\b"),
    re.compile(r"\bdebugger\s*;[\s\S]{0,80}\bsetInterval"),
    re.compile(r"window\.outerHeight\s*-\s*window\.innerHeight\s*>\s*\d{2,3}"),
    re.compile(r"\bdisableContextMenu\b", re.IGNORECASE),
    re.compile(r"\bnoDevTools?\b", re.IGNORECASE),
]
_BLOCKING_ATTRS = ("oncontextmenu", "onkeydown", "onkeyup", "onkeypress")


def _detect_anti_debug(soup) -> bool:
    """Port of dom-extract.ts detectAntiDebug()."""
    for tag_name in ("body", "html"):
        tag = soup.find(tag_name)
        if not tag:
            continue
        for attr in _BLOCKING_ATTRS:
            v = tag.get(attr) or ""
            if not v:
                continue
            if re.search(r"return\s+false", v, re.IGNORECASE):
                return True
            if "preventDefault(" in v:
                return True
    # Inline <script> blocks
    for s in soup.find_all("script", src=False)[:30]:
        text = (s.string or s.get_text() or "")[:4096]
        if not text:
            continue
        if any(p.search(text) for p in _ANTI_DEBUG_SCRIPT_PATTERNS):
            return True
    return False


_CARD_HINTS = (
    "card", "cardnumber", "card-number", "creditcard", "cc-number", "ccnumber",
    "cvv", "cvc", "csc", "securitycode", "security-code"
)


def _input_is_card(inp) -> bool:
    ac = (inp.get("autocomplete") or "").lower()
    if "cc-number" in ac or ac in ("cc-csc", "cc-exp"):
        return True
    name = (inp.get("name") or "").lower().replace("_", "-").replace(" ", "-")
    if any(h in name for h in _CARD_HINTS):
        return True
    placeholder = (inp.get("placeholder") or "").lower()
    if re.search(r"\bcvv\b|\bcvc\b|card number|信用卡|卡號", placeholder):
        return True
    return False


def _input_is_otp(inp) -> bool:
    ac = (inp.get("autocomplete") or "").lower()
    if "one-time-code" in ac:
        return True
    name = (inp.get("name") or "").lower()
    if re.match(r"^(otp|otpcode|otp-code|one[-_]?time|2fa|tfa|verifycode|verification[-_]?code)$", name):
        return True
    if re.search(r"(^|[-_])otp([-_]|$)", name):
        return True
    return False


_TW_NATIONAL_ID_NAME_HINTS = (
    "idno", "idnum", "id-number", "nationalid", "national-id",
    "twid", "tw-id", "personid", "person-id",
    "身分證", "身份證", "統一編號", "統編"
)
_TW_NATIONAL_ID_PATTERN = re.compile(r"\b[A-Z][12]\d{8}\b")


def _input_is_tw_national_id(inp) -> bool:
    name = (inp.get("name") or "").lower().replace("_", "-").replace(" ", "-")
    if any(h.lower() in name for h in _TW_NATIONAL_ID_NAME_HINTS):
        return True
    placeholder = inp.get("placeholder") or ""
    if "身分證" in placeholder or "身份證" in placeholder or \
       "統一編號" in placeholder or "統編" in placeholder:
        return True
    if _TW_NATIONAL_ID_PATTERN.search(placeholder):
        return True
    pat = inp.get("pattern") or ""
    if "[A-Z]" in pat and "[0-9]" in pat:
        return True
    return False


def _form_has_seed_phrase_grid(form) -> bool:
    pwd = form.find("input", {"type": "password"})
    if not pwd:
        return False
    texts = form.find_all("input", {"type": ["text", None]})
    if len(texts) < 8:
        return False
    roots: Counter[str] = Counter()
    for t in texts:
        nm = (t.get("name") or t.get("placeholder") or "").lower()
        root = re.sub(r"\d+$", "", nm).strip()
        if root:
            roots[root] += 1
    return any(c >= 8 for c in roots.values())


_MAINLAND_TERMS = ("短信", "激活", "信息", "賬號", "視頻", "屏幕", "軟件", "默認", "客戶端", "網絡", "服務器")
_TW_INSTITUTION_HINTS = (
    "政府", "衛福部", "健保署", "健保卡", "國稅局", "財政部", "內政部", "勞動部",
    "經濟部", "監理服務網", "監理站", "戶政事務所", "警政署", "165",
    "中華郵政", "中華電信", "台灣大哥大", "遠傳", "悠遊卡", "悠遊付",
    "遠通電收", "ETC", "蝦皮", "momo購物", "PChome",
    "國泰世華", "中國信託", "中信銀行", "玉山銀行", "兆豐", "第一銀行",
    "台新銀行", "富邦銀行", "合作金庫", "台灣銀行"
)


def _has_turnstile(soup) -> bool:
    if soup.select_one('div.cf-turnstile, div[data-sitekey][class*="turnstile"]'):
        return True
    if soup.select_one('script[src*="challenges.cloudflare.com/turnstile"]'):
        return True
    return False


def _has_hcaptcha(soup) -> bool:
    if soup.select_one('div.h-captcha, div[data-sitekey][class*="h-captcha"]'):
        return True
    if soup.select_one('script[src*="hcaptcha.com/1/api.js"], iframe[src*="hcaptcha.com"]'):
        return True
    return False


def _find_favicon_url(soup) -> str | None:
    link = soup.find(
        "link",
        rel=lambda v: v is not None and (
            "icon" in (v if isinstance(v, list) else v.lower().split())
            or "apple-touch-icon" in (v if isinstance(v, list) else v.lower().split())
            or (isinstance(v, str) and v.lower() == "shortcut icon")
        )
    )
    if link and link.get("href"):
        return link["href"]
    return None


def analyze_dom(
    html: str,
    page_url: str,
    data: RuleData | None = None,
    data_dir: Path | None = None,
) -> list[Signal]:
    """Parse a (possibly truncated) HTML excerpt and emit Stage 2 signals.

    `data` is optional only for backwards compatibility with the first Tier A
    run — callers should pass it so the IDP allowlist filters out legitimate
    OAuth/SSO cross-eTLD+1 form actions.

    `data_dir` enables the favicon-CDN-mismatch lookup (loads brand-favicon-
    cdns.json on first call). Without it, that signal silently no-ops.
    """
    out: list[Signal] = []
    if not html:
        return out

    # BS4 is tolerant of half-broken HTML which excerpts often are.
    soup = BeautifulSoup(html, "lxml")

    # Page-level
    try:
        from urllib.parse import urlparse as _urlparse
        page_proto = (_urlparse(page_url).scheme + ":") if page_url else ""
        page_ext = tldextract.extract(_urlparse(page_url).hostname or "")
        page_etld1 = (
            f"{page_ext.domain}.{page_ext.suffix}".lower()
            if page_ext.domain and page_ext.suffix else None
        )
    except Exception:
        page_proto = ""
        page_etld1 = None

    visible_text = soup.get_text(" ", strip=True)
    visible_text = re.sub(r"\s+", " ", visible_text)[:2000]

    inputs = soup.find_all("input")
    has_password = any(i.get("type") == "password" for i in inputs)
    has_otp = any(_input_is_otp(i) for i in inputs)
    has_card = any(_input_is_card(i) for i in inputs)
    has_tw_id = any(_input_is_tw_national_id(i) for i in inputs)

    forms = soup.find_all("form")
    form_actions = [(f.get("action") or "") for f in forms if f.get("action")]
    seed_phrase = any(_form_has_seed_phrase_grid(f) for f in forms)

    # ---- Signals -----------------------------------------------------------
    if has_password and page_proto == "http:":
        out.append(Signal("dom.password_no_tls", "stage2", W_PASSWORD_NO_TLS,
                          "password collected over plain http://"))

    # Cross-eTLD+1 form action checks
    action_etld1s: list[str | None] = []
    for action in form_actions:
        try:
            from urllib.parse import urljoin, urlparse as _urlparse
            abs_url = urljoin(page_url, action)
            host = _urlparse(abs_url).hostname or ""
            ext = tldextract.extract(host)
            d = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else None
            action_etld1s.append(d)
        except Exception:
            action_etld1s.append(None)

    # Filter out known IDPs — OAuth/SSO targets like accounts.google.com,
    # login.microsoftonline.com etc. are legitimate cross-eTLD+1 destinations.
    idp_allow = data.idp_allowlist if data else set()
    suspicious_cross = [
        d for d in action_etld1s
        if d is not None and d != page_etld1 and d not in idp_allow
    ]
    all_cross_idp = (
        page_etld1 is not None
        and any(d is not None and d != page_etld1 for d in action_etld1s)
        and not suspicious_cross
    )
    cross = page_etld1 is not None and bool(suspicious_cross)

    if all_cross_idp:
        out.append(Signal("dom.oauth_idp_allowlisted", "stage2", 0,
                          "cross-eTLD+1 form actions all target known OAuth/SSO IDPs — not flagging"))

    if cross:
        if has_password:
            out.append(Signal("dom.password_cross_etld1_post", "stage2", W_PASSWORD_CROSS_ETLD1,
                              "password posts cross-eTLD+1"))
        if has_otp:
            out.append(Signal("dom.otp_cross_etld1_post", "stage2", W_OTP_CROSS_ETLD1,
                              "OTP posts cross-eTLD+1"))
        if has_card:
            out.append(Signal("dom.card_cross_etld1_post", "stage2", W_CARD_CROSS_ETLD1,
                              "credit-card posts cross-eTLD+1"))

    if has_card and has_password:
        out.append(Signal("dom.card_and_password", "stage2", W_CARD_AND_PASSWORD,
                          "card + password collected together"))

    # Taiwan PII combo (mirror of stage2.ts). Triggers on pages outside the
    # Stage 1 trusted lists (.gov.tw / .edu.tw / Taiwan first-class allowlist
    # short-circuit before this code runs) — so any 身分證字號 collection here
    # is by construction off the trusted host set.
    if has_tw_id:
        if has_card and has_otp:
            out.append(Signal("dom.tw_pii_combo", "stage2", W_TW_PII_COMBO,
                              "page collects 身分證字號 + 卡號 + OTP off the Taiwan trusted list"))
        if cross:
            out.append(Signal("dom.tw_national_id_cross_etld1_post", "stage2",
                              W_TW_NATIONAL_ID_CROSS_ETLD1,
                              "身分證字號 field posts cross-eTLD+1"))

    # ---- Hidden iframes (lossy: inline style / attribute only) -----------
    hidden_iframe_count = 0
    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").lower()
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
            hidden_iframe_count += 1
            continue
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()
        if width in ("0", "1") and height in ("0", "1"):
            hidden_iframe_count += 1
    if hidden_iframe_count > 0:
        w = min(W_HIDDEN_IFRAME_CAP, W_HIDDEN_IFRAME * hidden_iframe_count)
        out.append(Signal("dom.hidden_iframes", "stage2", w,
                          f"{hidden_iframe_count} hidden iframe(s) (inline style/attr)"))

    # ---- Many foreign-eTLD+1 scripts -------------------------------------
    if page_etld1:
        foreign_etld1s: set[str] = set()
        for s in soup.find_all("script", src=True):
            try:
                from urllib.parse import urljoin as _urljoin, urlparse as _urlparse2
                abs_url = _urljoin(page_url, s["src"])
                host = _urlparse2(abs_url).hostname or ""
                ext = tldextract.extract(host)
                if ext.domain and ext.suffix:
                    d = f"{ext.domain}.{ext.suffix}".lower()
                    if d != page_etld1:
                        foreign_etld1s.add(d)
            except Exception:
                pass
        if len(foreign_etld1s) > 5:
            out.append(Signal("dom.many_foreign_scripts", "stage2", W_MANY_FOREIGN_SCRIPTS,
                              f"loads scripts from {len(foreign_etld1s)} distinct foreign eTLD+1s"))

    if _detect_anti_debug(soup):
        out.append(Signal("dom.anti_debug", "stage2", W_ANTI_DEBUG,
                          "page disables right-click / F12 / DevTools — common phishing-kit anti-inspection"))

    if seed_phrase:
        out.append(Signal("dom.seed_phrase_grid", "stage2", W_SEED_PHRASE,
                          "seed-phrase grid pattern"))

    # Cross-strait language anomaly (gated on TW-institution claim or .tw host)
    claims_tw_inst = any(h in visible_text for h in _TW_INSTITUTION_HINTS)
    on_tw_host = (page_etld1 or "").endswith(".tw") or (page_etld1 or "").endswith(".com.tw")
    if claims_tw_inst or on_tw_host:
        hits = [t for t in _MAINLAND_TERMS if t in visible_text]
        if hits:
            strong = len(set(hits)) >= 3
            out.append(Signal(
                "dom.cross_strait_terms_strong" if strong else "dom.cross_strait_terms",
                "stage2",
                W_CROSS_STRAIT_STRONG if strong else W_CROSS_STRAIT,
                f"mainland terms detected: {','.join(hits)}"
            ))

    # ---- Cloaking / verify-wall (2024+ PhaaS standard) --------------------
    has_turnstile = _has_turnstile(soup)
    has_hcaptcha = _has_hcaptcha(soup)
    if has_turnstile or has_hcaptcha:
        widget = "Cloudflare Turnstile" if has_turnstile else "hCaptcha"
        body_len = len(visible_text)
        form_count = len(forms)
        if body_len < VERIFY_WALL_TEXT_THRESHOLD:
            if form_count == 0 and not has_password:
                out.append(Signal(
                    "dom.cloaking_verify_wall_strong", "stage2", W_VERIFY_WALL_STRONG,
                    f"{widget} widget present + body {body_len} chars + no form — likely cloaking gate"
                ))
            else:
                out.append(Signal(
                    "dom.cloaking_verify_wall", "stage2", W_VERIFY_WALL,
                    f"{widget} widget present with thin body ({body_len} chars) — possible verify-wall"
                ))

    # ---- Favicon CDN hot-link mismatch ------------------------------------
    favicon_href = _find_favicon_url(soup)
    if favicon_href and page_etld1:
        try:
            from urllib.parse import urljoin, urlparse as _urlparse
            fav_abs = urljoin(page_url, favicon_href)
            fav_host = _urlparse(fav_abs).hostname or ""
            fav_ext = tldextract.extract(fav_host)
            fav_etld1 = (
                f"{fav_ext.domain}.{fav_ext.suffix}".lower()
                if fav_ext.domain and fav_ext.suffix else None
            )
        except Exception:
            fav_etld1 = None

        if fav_etld1 and fav_etld1 != page_etld1:
            cdn_map = _favicon_map(data_dir)
            cdn_hit = cdn_map.get(fav_etld1)
            if cdn_hit and cdn_hit[1] != page_etld1:
                out.append(Signal(
                    "dom.favicon_brand_cdn_mismatch", "stage2", W_FAVICON_BRAND_MISMATCH,
                    f"favicon hot-linked from '{fav_etld1}' ({cdn_hit[0]} CDN) but page is on '{page_etld1}'"
                ))
            elif data and fav_etld1 in data.brand_canonical_domains:
                out.append(Signal(
                    "dom.favicon_brand_canonical_mismatch", "stage2", W_FAVICON_BRAND_MISMATCH,
                    f"favicon loaded from brand domain '{fav_etld1}' but page is on '{page_etld1}'"
                ))

    # ---- Unicode trickery in title + body text ----------------------------
    title_text = (soup.title.get_text() if soup.title else "")
    if _ZERO_WIDTH_RE.search(title_text) or _ZERO_WIDTH_RE.search(visible_text):
        out.append(Signal(
            "dom.zero_width_in_text", "stage2", W_TEXT_ZERO_WIDTH,
            "zero-width character(s) present in page text"
        ))
    if _BIDI_OVERRIDE_RE.search(title_text) or _BIDI_OVERRIDE_RE.search(visible_text):
        out.append(Signal(
            "dom.bidi_override_in_text", "stage2", W_TEXT_BIDI_OVERRIDE,
            "bidi-override character present in page text"
        ))
    if _TAG_CHAR_RE.search(title_text) or _TAG_CHAR_RE.search(visible_text):
        out.append(Signal(
            "dom.tag_char_in_text", "stage2", W_TEXT_TAG_CHAR,
            "Unicode tag character present in page text"
        ))

    return out
