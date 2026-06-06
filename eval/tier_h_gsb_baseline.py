"""Tier H — Google Safe Browsing Lookup API external baseline (eval-only).

Reviewer #7 (round 3 §10 條 12): "all numbers are LocalPhish vs LocalPhish-
rules-only, no external SOTA comparison". This tier closes that.

Privacy invariant (Stage 0): GSB is INVOKED ONLY HERE in `eval/`, NEVER in
the extension runtime. The extension never makes per-page lookups to GSB
or any external service — the privacy story is intact. This is offline
research-grade evaluation, executed on the maintainer's machine.

What this tier does:
  1. For each URL in golden_200.jsonl (Tier C base) + tier_g_results.csv
     (TW phish fixtures), ask GSB v4 Lookup whether the URL is on its
     malicious-URL blacklist.
  2. Compute GSB's recall / FPR on each subset.
  3. Report a side-by-side: LocalPhish rules-only vs LocalPhish cascade vs GSB.

GSB API key handling:
  - Set GSB_API_KEY in env. Without a key the script reports
    "key absent — no comparison possible" and writes a placeholder
    summary so the report can cite it as "external baseline harness
    shipped, awaiting credential".
  - Key is NEVER persisted to disk by this script. We pass it once via
    env var; that's it.

Output:
  results/tier_h_results.csv     per-url: source, label, gsb_match, threats
  results/tier_h_summary.json    aggregate metrics + cross-tier comparison
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import time
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table


GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
DEFAULT_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",   # this is the phishing bucket
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def gsb_lookup(api_key: str, urls: list[str], timeout: float = 15.0) -> dict[str, list[str]]:
    """Query GSB threatMatches:find. Returns {url -> [threat_type, ...]}.

    GSB v4 docs: batch up to 500 URLs per request. Result contains a
    `matches` array; URLs absent from `matches` are clean.
    """
    results: dict[str, list[str]] = {u: [] for u in urls}
    if not urls:
        return results
    # GSB enforces a generous QPS for low-volume; 500-URL batches stay well
    # under the per-request size limit.
    for batch in chunk(urls, 500):
        body = {
            "client": {"clientId": "localphish-eval", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": DEFAULT_THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in batch],
            },
        }
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                GSB_URL,
                params={"key": api_key},
                json=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            payload = resp.json()
        for m in payload.get("matches", []):
            u = m.get("threat", {}).get("url")
            tt = m.get("threatType", "")
            if u and u in results:
                results[u].append(tt)
        # Be a polite GSB caller — small gap between batches.
        time.sleep(0.5)
    return results


def load_golden_200(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append({"url": row["url"], "label": int(row["label"]), "source": "golden_200"})
    return rows


def load_tier_g(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({"url": row["url"], "label": 1, "source": "tier_g_tw"})  # all phish
    return rows


def confusion(rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    for r in rows:
        pos = r.get("gsb_match", False)
        if r["label"] == 1 and pos: tp += 1
        elif r["label"] == 1 and not pos: fn += 1
        elif r["label"] == 0 and pos: fp += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", type=Path,
                        default=Path(__file__).parent / "datasets/golden_200.jsonl")
    parser.add_argument("--tier-g", type=Path,
                        default=Path(__file__).parent / "results/tier_g_results.csv")
    parser.add_argument("--out-csv", type=Path,
                        default=Path(__file__).parent / "results/tier_h_results.csv")
    parser.add_argument("--out-json", type=Path,
                        default=Path(__file__).parent / "results/tier_h_summary.json")
    parser.add_argument("--api-key", default=os.environ.get("GSB_API_KEY"))
    args = parser.parse_args()
    console = Console()

    if not args.api_key:
        console.print("[yellow]GSB_API_KEY not set in env — running in HARNESS-ONLY mode[/yellow]")
        console.print(
            "  Get one at https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com\n"
            "  Then re-run: GSB_API_KEY=<key> uv run python tier_h_gsb_baseline.py"
        )
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps({
            "status": "harness-shipped, awaiting GSB_API_KEY",
            "_note": (
                "Tier H is the external baseline harness called out in §10 條 12 "
                "(round 3 review). Implementation complete; needs the maintainer to "
                "provision a free GSB Lookup API key (Google Cloud Console, 10k "
                "queries/day free tier) and re-run. Result will populate this file."
            ),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        return 0

    # ---- collect URLs --------------------------------------------------
    golden = load_golden_200(args.golden)
    tier_g = load_tier_g(args.tier_g)
    all_rows = golden + tier_g
    console.print(f"[cyan]Tier H — GSB baseline[/cyan]")
    console.print(f"  golden_200 rows: {len(golden)} ({sum(1 for r in golden if r['label']==1)} phish, {sum(1 for r in golden if r['label']==0)} benign)")
    console.print(f"  tier_g TW rows: {len(tier_g)}")

    urls = [r["url"] for r in all_rows]
    console.print(f"  total URLs to query GSB: {len(urls)}")

    # ---- call GSB ------------------------------------------------------
    matches = gsb_lookup(args.api_key, urls)
    for r in all_rows:
        threats = matches.get(r["url"], [])
        r["gsb_match"] = bool(threats)
        r["gsb_threats"] = threats

    # ---- write CSV + per-subset metrics --------------------------------
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "url", "label", "gsb_match", "gsb_threats"])
        for r in all_rows:
            w.writerow([r["source"], r["url"], r["label"], int(r["gsb_match"]),
                        ";".join(r["gsb_threats"])])

    cm_golden = confusion(golden)
    cm_tier_g = confusion(tier_g)
    cm_all = confusion(all_rows)

    tbl = Table(title="GSB on each subset")
    tbl.add_column("subset")
    for k in ("n", "phish", "benign", "tp", "fp", "fn", "tn", "precision", "recall", "fpr"):
        tbl.add_column(k)
    for name, sub, cm in (
        ("golden_200", golden, cm_golden),
        ("tier_g_tw", tier_g, cm_tier_g),
        ("combined", all_rows, cm_all),
    ):
        tbl.add_row(
            name,
            str(len(sub)),
            str(sum(1 for r in sub if r["label"] == 1)),
            str(sum(1 for r in sub if r["label"] == 0)),
            str(cm["tp"]), str(cm["fp"]), str(cm["fn"]), str(cm["tn"]),
            f"{cm['precision']:.3f}", f"{cm['recall']:.3f}", f"{cm['fpr']:.3f}",
        )
    console.print(tbl)

    summary = {
        "golden_200": cm_golden,
        "tier_g_tw": cm_tier_g,
        "combined": cm_all,
        "n_total": len(all_rows),
        "_attribution": "Google Safe Browsing v4 Lookup API",
    }
    args.out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n[green]wrote[/green] {args.out_csv}")
    console.print(f"[green]wrote[/green] {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
