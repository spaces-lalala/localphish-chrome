"""Offline pipeline — fetch the 165 反詐騙 / 警政署 published "DNS-suspended
phishing domains" feed from data.gov.tw and normalize it for downstream
bloom-filter building.

Source: data.gov.tw dataset 176455 「165反詐騙諮詢專線_遭停止解析涉詐網站」
License: 政府資料開放授權條款 第1版 (≡ CC BY 4.0) — modification, derivative
         works, redistribution all permitted with attribution. Allows us to
         ship a derived bloom-filter blob inside the extension.

Privacy invariant: this script runs OFFLINE on the maintainer's machine; the
extension never makes per-page lookups to any external service (Stage 0 hard
rule). The output is a static bundled blob refreshed by chrome.alarms.

Output:
    eval/datasets/tw_scam_domains.jsonl   one JSON object per row:
        { "domain": "...", "month": "11311", "category": "...", "source": "..." }

Run:
    uv run python fetch_tw_scam_domains.py
    uv run python fetch_tw_scam_domains.py --csv path/to/local.csv  # offline
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import httpx
from rich.console import Console


# Public dataset 176455. The opdadm.moi.gov.tw redirect is stable; the
# resource UUID may change when the publisher rotates the file, in which
# case re-fetch the resource ID from https://data.gov.tw/dataset/176455.
DATASET_URL = (
    "https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/"
    "29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/"
    "A73E7D73-B7B5-4B12-A50E-87404FB43693/download"
)

# Documented column order (rare reorder is possible — we normalize defensively).
EXPECTED_FIELDS = ("民國年月", "網域", "網站性質", "法律依據", "聲請單位")


def normalize_domain(raw: str) -> str | None:
    """Normalize a domain to lowercase eTLD-suffix host. Returns None if the
    cell is not a plausible domain (empty, contains spaces, is an IP, etc.).

    We DO NOT keep the path/query — the bloom filter checks eTLD+host
    membership, not full URLs. Phishing kits rotate paths every reboot but
    keep the same hostname for hours / days.
    """
    if not raw:
        return None
    s = raw.strip().strip(".").lower()
    if not s:
        return None
    # Strip scheme if present (some publishers include http://).
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = parsed.hostname or ""
        except Exception:
            return None
    # Strip leading www.
    if s.startswith("www."):
        s = s[4:]
    # Reject IPs and obvious non-hostnames.
    if not s or " " in s or "/" in s or "@" in s or "?" in s:
        return None
    # Must contain at least one dot.
    if "." not in s:
        return None
    # ASCII / IDN-encoded — leave xn-- as-is, leave UTF-8 domains as-is
    # (Stage 1 normalizes with tldts at lookup time).
    return s


def parse_csv_bytes(blob: bytes) -> list[dict[str, str]]:
    """Parse the CSV defensively. data.gov.tw publishes UTF-8 with BOM."""
    text = blob.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, str]] = []
    for row in reader:
        if not row:
            continue
        # csv.DictReader keys may carry surrounding whitespace if the header
        # cell had any; strip them.
        rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
    return rows


def fetch(url: str, timeout: float = 30.0) -> bytes:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.content


def iter_rows(rows: Iterable[dict[str, str]]) -> Iterable[dict[str, str]]:
    """Map publisher columns -> our canonical schema. Tolerates header
    variations (`網域` vs `網址` vs `domain`)."""
    for r in rows:
        # The publisher sometimes uses different header capitalization /
        # punctuation. Try the documented header first, then variants.
        domain_raw = (
            r.get("網域")
            or r.get("網址")
            or r.get("Domain")
            or r.get("domain")
            or ""
        )
        domain = normalize_domain(domain_raw)
        if not domain:
            continue
        yield {
            "domain": domain,
            "month": r.get("民國年月", "") or r.get("month", ""),
            "category": r.get("網站性質", "") or r.get("category", ""),
            "source_basis": r.get("法律依據", ""),
            "source_org": r.get("聲請單位", ""),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=None,
                        help="Use a local CSV instead of fetching data.gov.tw")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "datasets/tw_scam_domains.jsonl")
    parser.add_argument("--url", default=DATASET_URL)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    console = Console()

    if args.csv:
        console.print(f"[cyan]Reading local CSV[/cyan] {args.csv}")
        blob = args.csv.read_bytes()
    else:
        console.print(f"[cyan]Fetching[/cyan] {args.url}")
        try:
            blob = fetch(args.url, args.timeout)
        except Exception as e:
            console.print(f"[red]fetch failed[/red]: {e}")
            console.print(
                "[yellow]Hint:[/yellow] if data.gov.tw is unreachable from your "
                "network, download the CSV manually from "
                "https://data.gov.tw/dataset/176455 and re-run with --csv <path>"
            )
            return 1

    console.print(f"  got {len(blob)} bytes")

    try:
        rows = parse_csv_bytes(blob)
    except Exception as e:
        console.print(f"[red]CSV parse failed[/red]: {e}")
        return 1
    console.print(f"  parsed {len(rows)} raw rows; headers={list(rows[0].keys()) if rows else []}")

    canonical = list(iter_rows(rows))
    # Dedup by domain (publisher includes the same domain across months).
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for r in canonical:
        if r["domain"] in seen:
            continue
        seen.add(r["domain"])
        deduped.append(r)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for r in deduped:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    console.print(
        f"[green]wrote[/green] {args.out}  "
        f"({len(deduped)} unique domains, {len(canonical) - len(deduped)} duplicates dropped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
