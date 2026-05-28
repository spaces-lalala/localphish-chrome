"""Python port of the extension's Stage 2 DOM-feature scoring.

Reads an HTML excerpt with BeautifulSoup and emits the same Signal[] shape
as the extension's content script + SW combined. Weights mirror
extension/src/signals/stage2.ts so Tier A is a faithful rule-layer baseline.
"""

from __future__ import annotations

import re
from collections import Counter

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
)


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


def analyze_dom(html: str, page_url: str, data: RuleData | None = None) -> list[Signal]:
    """Parse a (possibly truncated) HTML excerpt and emit Stage 2 signals.

    `data` is optional only for backwards compatibility with the first Tier A
    run — callers should pass it so the IDP allowlist filters out legitimate
    OAuth/SSO cross-eTLD+1 form actions.
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

    return out
