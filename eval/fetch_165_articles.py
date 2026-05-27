"""Fetch articles from 165.npa.gov.tw (台灣警政署 165 反詐騙網).

The 165 site's HTML is an Angular SPA, but exposes a JSON API at /api/article/.
We pull three category lists and their per-article detail; the result is a
local corpus of Taiwan-context phishing descriptions used as grounding for
the Stage 3 prompt v2 (Taiwan-localized) in Week 15.

Category codes (discovered from the bundle):
    A — 詐騙手法 / phishing patterns
    C — 最新案例 / recent cases
    1 — 警政公告 / police bulletins

Usage:
    uv run python eval/fetch_165_articles.py
    uv run python eval/fetch_165_articles.py --max-per-category 30
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx


BASE = "https://165.npa.gov.tw"
DEFAULT_UA = "LocalPhish-Eval/0.1 (academic phishing research; contact via 111703009@g.nccu.edu.tw)"
CATEGORIES = {"A": "詐騙手法", "C": "最新案例", "1": "警政公告"}
DEFAULT_OUT = Path(__file__).parent / "datasets/tw_165_articles.json"
RATE_LIMIT_SECONDS = 1.0  # polite — one request per second


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(s: str | None) -> str:
    if not s:
        return ""
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", s)).strip()


def fetch_list(client: httpx.Client, category: str) -> list[dict]:
    url = f"{BASE}/api/article/list/{category}"
    r = client.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_detail(client: httpx.Client, article_id: int) -> dict:
    url = f"{BASE}/api/article/detail/{article_id}"
    r = client.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-per-category",
        type=int,
        default=40,
        help="cap articles fetched per category"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--no-detail",
        action="store_true",
        help="skip per-article detail fetch (titles only)"
    )
    args = parser.parse_args()

    out: dict = {
        "_source": BASE,
        "_fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "_categories": CATEGORIES,
        "articles": []
    }

    with httpx.Client(headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"}) as client:
        for code, label in CATEGORIES.items():
            print(f"[165] fetching list /api/article/list/{code} ({label})", file=sys.stderr)
            try:
                items = fetch_list(client, code)
            except httpx.HTTPError as e:
                print(f"  -> failed: {e}", file=sys.stderr)
                continue
            print(f"  -> {len(items)} entries, taking first {args.max_per_category}", file=sys.stderr)
            items = items[: args.max_per_category]

            for it in items:
                aid = it.get("id")
                title = it.get("title", "")
                pub = it.get("publishDate", "")
                content = ""
                if not args.no_detail and aid is not None:
                    time.sleep(RATE_LIMIT_SECONDS)
                    try:
                        detail = fetch_detail(client, aid)
                        content = strip_html(detail.get("content") or detail.get("articleContent"))
                    except httpx.HTTPError as e:
                        print(f"  -> detail {aid} failed: {e}", file=sys.stderr)
                out["articles"].append({
                    "id": aid,
                    "category": code,
                    "category_label": label,
                    "title": title,
                    "publish_date": pub,
                    "content": content[:6000]  # cap per-article body to keep file size sane
                })
            time.sleep(RATE_LIMIT_SECONDS)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(out, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    size_kb = args.out.stat().st_size / 1024
    print(
        f"[165] wrote {len(out['articles'])} articles -> {args.out} ({size_kb:.1f} KB)",
        file=sys.stderr
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
