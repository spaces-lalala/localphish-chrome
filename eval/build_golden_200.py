"""Build a golden 200-sample subset for Tier B rendering.

Strategy:
  - 100 phish from PhreshPhish (stratify across URL feature buckets so
    we don't end up with 100 .tk samples)
  - 50 benign from Tranco Top 5000 (sample uniformly)
  - 50 easy-misclassify candidates (Vercel staging, SPA hashes, SSO
    redirect pages, password manager origins, *.gov.tw legit)

Output:
  datasets/golden_200.jsonl    fields: url, label, html_excerpt (where avail), source, bucket

This is the dataset tier_b_rendered.py renders. Random seed is fixed so
the same subset comes back every run, which keeps Tier A vs Tier B
comparisons reproducible across re-runs.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console


# Hand-curated easy-misclassify URLs. These don't need to be live — they
# represent the *shapes* of legit URLs that have historically tripped
# naive phishing detectors. Each one is a URL pattern we expect Tier B to
# correctly classify as benign.
EASY_MISCLASSIFY_PATTERNS = [
    # Vercel / Netlify staging
    ("https://my-project-abc123.vercel.app/", "vercel-staging"),
    ("https://stage-app.vercel.app/login", "vercel-staging"),
    ("https://staging.netlify.app/auth", "netlify-staging"),
    # SPA hash routes
    ("https://app.notion.so/workspace/abc123", "spa-hash"),
    ("https://www.figma.com/file/xyz/", "spa-hash"),
    ("https://twitter.com/i/account", "spa-hash"),
    # SSO redirect chains
    ("https://accounts.google.com/o/oauth2/v2/auth?client_id=...", "sso-legit"),
    ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "sso-legit"),
    ("https://appleid.apple.com/auth/authorize", "sso-legit"),
    # Password manager extension origins (chrome-extension://) — skipped, not
    # web URLs.
    # Legit .gov.tw — these MUST be SAFE
    ("https://www.post.gov.tw/post/internet/Postal/index.jsp", "gov-tw-legit"),
    ("https://www.nhi.gov.tw/Content_List.aspx?n=4915F4E97DB4DA70&topn=23C660CAACAA159D", "gov-tw-legit"),
    ("https://www.etax.nat.gov.tw/etwmain/web/ETW118W/CON/410/8051506122210316061", "gov-tw-legit"),
    ("https://www.fetc.net.tw/", "gov-tw-legit"),
    # Legit TW banks
    ("https://www.cathaybk.com.tw/cathaybk/personal/", "tw-bank-legit"),
    ("https://www.esunbank.com/zh-tw/personal", "tw-bank-legit"),
    ("https://www.ctbcbank.com/twrbo/zh_tw/index.html", "tw-bank-legit"),
    # Legit popular sites with funky URLs
    ("https://github.com/anthropics/claude-code/pulls", "popular-legit"),
    ("https://stackoverflow.com/questions/tagged/python", "popular-legit"),
    ("https://chatgpt.com/c/abc123", "popular-legit"),
]


def url_bucket(url: str) -> str:
    """Coarse bucket so we can stratify the phish samples."""
    try:
        h = urlparse(url).hostname or ""
    except ValueError:
        h = ""
    if not h:
        return "(unparseable)"
    if h.replace(".", "").isdigit():
        return "ip-host"
    suffix = h.rsplit(".", 1)[-1]
    if suffix in ("tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "mov", "quest"):
        return f"susp-tld-{suffix}"
    if any(brand in h for brand in ("paypal", "microsoft", "apple", "google", "amazon")):
        return "brand-in-host"
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phreshphish", type=Path,
                        default=Path(__file__).parent / "datasets/phreshphish_subset.jsonl")
    parser.add_argument("--tranco", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data/tranco-sample.json")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "datasets/golden_200.jsonl")
    parser.add_argument("--seed", type=int, default=20260603)
    parser.add_argument("--n-phish", type=int, default=100)
    parser.add_argument("--n-benign", type=int, default=50)
    args = parser.parse_args()
    console = Console()

    rng = random.Random(args.seed)

    # ---- Phish: stratified sample from PhreshPhish ----
    if not args.phreshphish.exists():
        console.print(f"[red]missing[/red] {args.phreshphish}")
        return 2

    phish_pool: dict[str, list[dict]] = defaultdict(list)
    with args.phreshphish.open("r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("_meta") or int(obj.get("label", 0)) != 1:
                continue
            phish_pool[url_bucket(obj["url"])].append(obj)

    n_buckets = len(phish_pool)
    per_bucket = max(1, args.n_phish // n_buckets)
    phish_pick: list[dict] = []
    for b, rows in phish_pool.items():
        rng.shuffle(rows)
        for r in rows[:per_bucket]:
            r2 = dict(r)
            r2["_source"] = "phreshphish"
            r2["_bucket"] = b
            phish_pick.append(r2)
    rng.shuffle(phish_pick)
    phish_pick = phish_pick[:args.n_phish]
    console.print(f"phish: picked {len(phish_pick)} across {n_buckets} buckets")

    # ---- Benign: Tranco sample (URL only — no HTML excerpt) ----
    benign_pick: list[dict] = []
    if args.tranco.exists():
        tranco = json.loads(args.tranco.read_text(encoding="utf-8"))
        domains = tranco.get("domains", [])
        rng.shuffle(domains)
        for d in domains[: args.n_benign]:
            benign_pick.append({
                "url": f"https://www.{d}/",
                "label": 0,
                "html_excerpt": "",
                "_source": "tranco",
                "_bucket": "tranco-top"
            })
        console.print(f"benign: picked {len(benign_pick)} from Tranco")
    else:
        console.print(f"[yellow]warn[/yellow] missing {args.tranco}, skipping benign sampling")

    # ---- Easy misclassify: hand-curated ----
    easy_pick: list[dict] = []
    for url, bucket in EASY_MISCLASSIFY_PATTERNS:
        easy_pick.append({
            "url": url,
            "label": 0,
            "html_excerpt": "",
            "_source": "easy-misclassify",
            "_bucket": bucket
        })
    console.print(f"easy-misclassify: {len(easy_pick)} curated entries")

    # ---- Write ----
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        f.write(json.dumps({
            "_meta": True,
            "_seed": args.seed,
            "_n_phish": len(phish_pick),
            "_n_benign": len(benign_pick),
            "_n_easy": len(easy_pick),
            "_total": len(phish_pick) + len(benign_pick) + len(easy_pick)
        }, ensure_ascii=False) + "\n")
        for r in phish_pick + benign_pick + easy_pick:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    console.print(f"[green]wrote[/green] {args.out} "
                  f"({len(phish_pick) + len(benign_pick) + len(easy_pick)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
