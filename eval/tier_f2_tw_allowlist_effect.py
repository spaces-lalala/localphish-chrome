"""Tier F2 — Re-evaluate Tier F with the Week 16 v2 Taiwan first-class
allow-list applied as a post-process short-circuit.

Tier F (rendered rules + Ollama LLM) found FPR = 52.2% on 117 matched rows.
Reviewer #7 (round 3) pointed out the root cause: the allowlist is global
Tranco Top-5000, which misses cathaybk / esun / momoshop / linepay.tw etc.

Week 16 v2 ships `extension/src/data/taiwan-allowlist.json` (88 hand-curated
Taiwan institution eTLD+1s). This script applies it post-hoc on Tier F
results: any row whose eTLD+1 is on the new list becomes Stage-1 SAFE
(rules_score=0, LLM not called, final verdict safe), simulating what the
Week 16 v2 cascade would have done.

This is a CONSERVATIVE measurement — the new TW PII combo Stage 2 detector
is not modeled here (would require re-running the Playwright rendered
extractor on every row). It only measures the allow-list effect.

Outputs:
  - results/tier_f2_results.csv     per-row (url, label, was_short_circuited, final_score, final_verdict)
  - results/tier_f2_summary.json    Before/after metrics
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse

import tldextract
from rich.console import Console
from rich.table import Table


def etld1(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ""


def confusion(rows: list[dict], pred_field: str = "final_score", thr: int = 50) -> dict:
    tp = fp = fn = tn = 0
    for r in rows:
        label = int(r["label"])
        try:
            pred_score = int(r[pred_field])
        except (TypeError, ValueError):
            pred_score = 0
        pred_pos = pred_score >= thr
        if label == 1 and pred_pos:
            tp += 1
        elif label == 1 and not pred_pos:
            fn += 1
        elif label == 0 and pred_pos:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 3),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier-f-csv", type=Path,
                        default=Path(__file__).parent / "results/tier_f_results.csv")
    parser.add_argument("--tw-allowlist", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data/taiwan-allowlist.json")
    parser.add_argument("--out-dir", type=Path,
                        default=Path(__file__).parent / "results")
    parser.add_argument("--thr", type=int, default=50)
    args = parser.parse_args()
    console = Console()

    tw = json.loads(args.tw_allowlist.read_text(encoding="utf-8"))
    tw_set = {d.lower() for d in tw["domains"]}
    console.print(f"[cyan]Loaded Taiwan first-class allowlist: {len(tw_set)} entries[/cyan]")

    rows_before: list[dict] = []
    rows_after: list[dict] = []
    short_circuited: list[str] = []

    with args.tier_f_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows_before.append(dict(row))
            new_row = dict(row)
            host_etld1 = etld1(row["url"])
            if host_etld1 in tw_set:
                # Short-circuit safe — pretend Stage 1 caught it.
                new_row["was_short_circuited"] = "Y"
                new_row["final_score"] = "0"
                new_row["final_verdict"] = "safe"
                new_row["llm_called"] = "N"
                short_circuited.append(row["url"])
            else:
                new_row["was_short_circuited"] = "N"
            rows_after.append(new_row)

    cm_before = confusion(rows_before, "final_score", args.thr)
    cm_after = confusion(rows_after, "final_score", args.thr)

    # n_benign for FPR rate
    n_benign = sum(1 for r in rows_before if int(r["label"]) == 0)

    tbl = Table(title=f"Tier F2 — TW allowlist post-hoc effect on Tier F (n={len(rows_before)}, n_benign={n_benign}, thr={args.thr})")
    tbl.add_column("metric")
    tbl.add_column("Tier F (before)")
    tbl.add_column("Tier F2 (after TW allowlist)")
    tbl.add_column("delta")

    for k in ("precision", "recall", "f1", "fpr"):
        b = cm_before[k]
        a = cm_after[k]
        d = round(a - b, 3)
        tbl.add_row(k.upper(), f"{b:.3f}", f"{a:.3f}", f"{d:+.3f}")
    for k in ("tp", "fp", "fn", "tn"):
        b = cm_before[k]
        a = cm_after[k]
        tbl.add_row(k.upper(), str(b), str(a), f"{a - b:+d}")
    console.print(tbl)

    console.print(f"\n[green]Short-circuited by new TW allowlist:[/green] {len(short_circuited)} row(s)")
    for u in short_circuited:
        console.print(f"  - {u}")

    # ----------------- Write CSV + summary -----------------
    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "tier_f2_results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = list(rows_after[0].keys()) if rows_after else []
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_after)

    summary = {
        "n": len(rows_before),
        "n_benign": n_benign,
        "threshold": args.thr,
        "before": cm_before,
        "after": cm_after,
        "short_circuited_count": len(short_circuited),
        "short_circuited_urls": short_circuited,
        "tw_allowlist_size": len(tw_set),
    }
    summary_path = args.out_dir / "tier_f2_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    console.print(f"\n[green]wrote[/green] {csv_path}")
    console.print(f"[green]wrote[/green] {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
