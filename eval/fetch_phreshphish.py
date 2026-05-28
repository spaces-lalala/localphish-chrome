"""Fetch a PhreshPhish subset for Tier A evaluation.

PhreshPhish (arXiv 2507.10854, CC-BY-4.0) is a 666k-sample HTML+URL dataset
of real-world phishing and benign pages. The full archive is ~1.5 TB; for
prompt iteration we only need a few thousand labelled rows.

This script downloads the smallest test shard (~55 MB on the wire), samples
N rows per class, and writes a compact JSONL of {url, label, html_excerpt}.

Usage:
    uv run python eval/fetch_phreshphish.py                  # 2000 phish + 2000 benign
    uv run python eval/fetch_phreshphish.py --per-class 500  # smaller
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import polars as pl


REPO = "phreshphish/phreshphish"
SHARD = "data/test-000.parquet"  # smallest shard, ~55 MB on the wire
HF_RESOLVE = f"https://huggingface.co/datasets/{REPO}/resolve/main/{SHARD}"
DEFAULT_UA = "LocalPhish-Eval/0.1 (academic research; 111703009@g.nccu.edu.tw)"
HTML_EXCERPT_CHARS = 50_000  # earlier 4000 sat inside <head>, missed every form


def download_shard(url: str, dest: Path) -> None:
    if dest.exists():
        size_mb = dest.stat().st_size / 1024 / 1024
        print(f"[phreshphish] cached shard at {dest} ({size_mb:.1f} MB) — skipping download",
              file=sys.stderr)
        return
    print(f"[phreshphish] downloading {url}", file=sys.stderr)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, headers={"User-Agent": DEFAULT_UA},
                      timeout=600, follow_redirects=True) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        seen = 0
        with dest.open("wb") as f:
            for chunk in r.iter_bytes(chunk_size=1 << 16):
                f.write(chunk)
                seen += len(chunk)
                if total:
                    pct = 100 * seen / total
                    print(f"\r  {seen / 1024 / 1024:6.1f} / {total / 1024 / 1024:.1f} MB "
                          f"({pct:5.1f}%)", end="", file=sys.stderr)
        print("", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--per-class",
        type=int,
        default=2000,
        help="how many rows of each class (phish, benign) to keep"
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(__file__).parent / "datasets/cache"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "datasets/phreshphish_subset.jsonl"
    )
    args = parser.parse_args()

    shard_path = args.cache_dir / "test-000.parquet"
    download_shard(HF_RESOLVE, shard_path)

    print(f"[phreshphish] reading {shard_path}", file=sys.stderr)
    df = pl.read_parquet(shard_path)
    print(f"  -> {len(df):,} rows, columns: {df.columns}", file=sys.stderr)

    # Schema discovery — PhreshPhish v1.0.1 uses (url, html, label) but we
    # accept any reasonable spelling.
    url_col = _pick(df.columns, ["url", "URL", "page_url"])
    label_col = _pick(df.columns, ["label", "Label", "is_phish", "phishing"])
    html_col = _pick(df.columns, ["html", "raw_html", "page_html", "content"])
    if url_col is None or label_col is None:
        print(f"[phreshphish] cannot find url/label columns in {df.columns}", file=sys.stderr)
        return 2

    df = df.select([
        pl.col(url_col).alias("url"),
        pl.col(label_col).alias("label"),
        pl.col(html_col).str.slice(0, HTML_EXCERPT_CHARS).alias("html_excerpt")
        if html_col else pl.lit("").alias("html_excerpt")
    ])

    # Normalize label to 0/1 — PhreshPhish uses {0: benign, 1: phish} or strings.
    df = df.with_columns(
        pl.when(pl.col("label").cast(pl.Utf8).is_in(["1", "phish", "phishing", "True", "true"]))
        .then(pl.lit(1))
        .otherwise(pl.lit(0))
        .alias("label_int")
    )

    phish = df.filter(pl.col("label_int") == 1).sample(
        n=min(args.per_class, df.filter(pl.col("label_int") == 1).height),
        seed=42
    )
    benign = df.filter(pl.col("label_int") == 0).sample(
        n=min(args.per_class, df.filter(pl.col("label_int") == 0).height),
        seed=42
    )
    print(f"[phreshphish] sampled {len(phish)} phish + {len(benign)} benign",
          file=sys.stderr)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        meta = {
            "_meta": True,
            "_source": REPO,
            "_shard": SHARD,
            "_fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "_per_class": args.per_class,
            "_html_excerpt_chars": HTML_EXCERPT_CHARS
        }
        f.write(json.dumps(meta, ensure_ascii=False) + "\n")
        for row in pl.concat([phish, benign]).iter_rows(named=True):
            f.write(json.dumps({
                "url": row["url"],
                "label": int(row["label_int"]),
                "html_excerpt": row["html_excerpt"] or ""
            }, ensure_ascii=False) + "\n")
    size_mb = args.out.stat().st_size / 1024 / 1024
    print(f"[phreshphish] wrote {len(phish) + len(benign)} rows -> {args.out} ({size_mb:.1f} MB)",
          file=sys.stderr)
    return 0


def _pick(columns: list[str], candidates: list[str]) -> str | None:
    for c in candidates:
        if c in columns:
            return c
    return None


if __name__ == "__main__":
    raise SystemExit(main())
