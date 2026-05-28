"""Tier A — static rule-layer evaluation on PhreshPhish subset.

Loads the JSONL produced by fetch_phreshphish.py, runs the Python-ported
Stage 1 + Stage 2-lite detectors over each {url, html_excerpt, label} row,
and emits:

  results/tier_a_results.csv     per-row detection + signals + verdict
  results/tier_a_summary.json    F1 / Precision / Recall / FPR / per-signal hit rates
  stdout: rich-table summary

The threshold used to derive a binary decision is configurable via --threshold
(default 50 — matches the cascade's 'suspicious' floor). Tier A reports the
sweep across thresholds 5–95 so the Week 15 report can show a P-R curve.

Usage:
    uv run python eval/tier_a_static.py
    uv run python eval/tier_a_static.py --threshold 30
    uv run python eval/tier_a_static.py --input eval/datasets/phreshphish_subset.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from localphish_eval.rules import (
    DANGER_FLOOR,
    SAFE_CEILING,
    Signal,
    load_rule_data,
    run_stage1,
)
from localphish_eval.dom_features import analyze_dom


def cascade_score(url: str, html: str, data) -> tuple[int, list[Signal]]:
    s1 = run_stage1(url, data)
    sigs: list[Signal] = list(s1["signals"])
    if s1["shortCircuit"]:
        return s1["rawScore"], sigs
    s2 = analyze_dom(html, url, data)
    sigs.extend(s2)
    total = min(100, s1["rawScore"] + sum(s.weight for s in s2))
    return total, sigs


def verdict_from_score(score: int) -> str:
    if score >= DANGER_FLOOR:
        return "dangerous"
    if score < SAFE_CEILING:
        return "safe"
    if score >= 50:
        return "suspicious"
    return "caution"


def confusion(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    n_pos = tp + fn
    n_neg = fp + tn
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / n_pos if n_pos else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
        "fpr": fp / n_neg if n_neg else 0.0,
        "accuracy": (tp + tn) / max(1, tp + tn + fp + fn)
    }


def bootstrap_ci(
    y_true: list[int],
    scores: list[int],
    threshold: int,
    n_bootstrap: int = 1000,
    seed: int = 42
) -> dict:
    """Bootstrap 95% CI for F1 / Precision / Recall / FPR at a given threshold.

    We can't easily afford to re-download more PhreshPhish shards each run, so
    we use the standard non-parametric bootstrap (sampling with replacement
    from the existing N rows) to estimate how much each metric would move if
    we'd drawn a slightly different N rows from the same distribution. The
    resulting CI is a lower bound on true population variance — it doesn't
    capture between-shard variance — but it's the right metric for reporting
    "given this dataset, how stable are our numbers".
    """
    import random
    rng = random.Random(seed)
    n = len(y_true)
    f1s, ps, rs, fprs = [], [], [], []
    for _ in range(n_bootstrap):
        idxs = [rng.randrange(n) for _ in range(n)]
        yt = [y_true[i] for i in idxs]
        yp = [1 if scores[i] >= threshold else 0 for i in idxs]
        m = confusion(yt, yp)
        f1s.append(m["f1"]); ps.append(m["precision"])
        rs.append(m["recall"]); fprs.append(m["fpr"])

    def pct(xs, p):
        xs = sorted(xs)
        k = int(round((p / 100) * (len(xs) - 1)))
        return xs[k]

    return {
        "f1_ci": [pct(f1s, 2.5), pct(f1s, 97.5)],
        "precision_ci": [pct(ps, 2.5), pct(ps, 97.5)],
        "recall_ci": [pct(rs, 2.5), pct(rs, 97.5)],
        "fpr_ci": [pct(fprs, 2.5), pct(fprs, 97.5)]
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "datasets/phreshphish_subset.jsonl")
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data")
    parser.add_argument("--results-dir", type=Path, default=Path(__file__).parent / "results")
    parser.add_argument("--threshold", type=int, default=50,
                        help="score threshold for binary decision (default 50)")
    parser.add_argument("--limit", type=int, default=0,
                        help="cap rows scored (0 = all)")
    args = parser.parse_args()

    console = Console()
    console.print(f"[bold cyan]Tier A — static rule-layer evaluation[/bold cyan]")
    console.print(f"  data dir: {args.data_dir}")
    data = load_rule_data(args.data_dir)
    console.print(f"  loaded: {len(data.allowlist)} allow-list, "
                  f"{len(data.brands)} brands, "
                  f"{sum(len(t[1]) for t in data.tld_table.values())} TLD entries")

    if not args.input.exists():
        console.print(f"[red]missing input {args.input}[/red] — run "
                      "`uv run python eval/fetch_phreshphish.py` first")
        return 2

    args.results_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.results_dir / "tier_a_results.csv"
    summary_path = args.results_dir / "tier_a_summary.json"

    rows = []
    with args.input.open("r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("_meta"):
                continue
            rows.append(obj)
    if args.limit:
        rows = rows[: args.limit]
    console.print(f"  rows: {len(rows)}")

    t0 = time.time()
    scored = []
    per_signal: Counter[str] = Counter()
    per_signal_by_label: dict[str, dict[int, int]] = defaultdict(lambda: {0: 0, 1: 0})

    for row in rows:
        url = row["url"]
        html = row.get("html_excerpt") or ""
        label = int(row["label"])
        score, sigs = cascade_score(url, html, data)
        scored.append((url, label, score, sigs))
        for s in sigs:
            if s.weight > 0:
                per_signal[s.id] += 1
                per_signal_by_label[s.id][label] += 1

    elapsed = time.time() - t0

    # Confusion matrix at the user-specified threshold
    y_true = [r[1] for r in scored]
    y_pred = [1 if r[2] >= args.threshold else 0 for r in scored]
    main_metrics = confusion(y_true, y_pred)

    # Threshold sweep + bootstrap 95% CIs at each threshold.
    sweep = []
    raw_scores = [r[2] for r in scored]
    for thr in range(5, 96, 5):
        y_pred_t = [1 if s >= thr else 0 for s in raw_scores]
        m = confusion(y_true, y_pred_t)
        ci = bootstrap_ci(y_true, raw_scores, thr, n_bootstrap=500)
        sweep.append({"threshold": thr, **m, **ci})

    # Per-signal hit rates restricted to weight-bearing signals
    per_signal_rows = []
    for sid, total in per_signal.most_common():
        on_phish = per_signal_by_label[sid].get(1, 0)
        on_benign = per_signal_by_label[sid].get(0, 0)
        per_signal_rows.append({
            "signal": sid,
            "fires_total": total,
            "fires_on_phish": on_phish,
            "fires_on_benign": on_benign,
            "phish_precision": on_phish / total if total else 0.0
        })

    # --- write CSV ---
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "score", "verdict", "signals"])
        for url, label, score, sigs in scored:
            w.writerow([
                url,
                label,
                score,
                verdict_from_score(score),
                "|".join(f"{s.id}+{s.weight}" for s in sigs if s.weight > 0)
            ])

    # --- write summary JSON ---
    summary = {
        "input_path": str(args.input),
        "n_rows": len(scored),
        "n_phish": sum(1 for _, l, _, _ in scored if l == 1),
        "n_benign": sum(1 for _, l, _, _ in scored if l == 0),
        "elapsed_seconds": round(elapsed, 2),
        "rows_per_second": round(len(scored) / max(0.01, elapsed), 1),
        "primary_threshold": args.threshold,
        "primary_metrics": main_metrics,
        "threshold_sweep": sweep,
        "per_signal": per_signal_rows
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # --- console report ---
    tbl = Table(title=f"Tier A primary metrics (threshold={args.threshold})")
    for col in ("metric", "value"):
        tbl.add_column(col)
    for k in ("precision", "recall", "f1", "fpr", "accuracy"):
        tbl.add_row(k.upper(), f"{main_metrics[k]:.3f}")
    for k in ("tp", "fp", "fn", "tn"):
        tbl.add_row(k.upper(), str(main_metrics[k]))
    console.print(tbl)

    sweep_tbl = Table(title="Threshold sweep (95 % bootstrap CI in brackets)")
    sweep_tbl.add_column("thr")
    sweep_tbl.add_column("F1 [CI]")
    sweep_tbl.add_column("Precision [CI]")
    sweep_tbl.add_column("Recall [CI]")
    sweep_tbl.add_column("FPR [CI]")
    for row in sweep:
        f1lo, f1hi = row["f1_ci"]
        plo, phi = row["precision_ci"]
        rlo, rhi = row["recall_ci"]
        fprlo, fprhi = row["fpr_ci"]
        sweep_tbl.add_row(
            str(row["threshold"]),
            f"{row['f1']:.3f} [{f1lo:.2f}-{f1hi:.2f}]",
            f"{row['precision']:.3f} [{plo:.2f}-{phi:.2f}]",
            f"{row['recall']:.3f} [{rlo:.2f}-{rhi:.2f}]",
            f"{row['fpr']:.3f} [{fprlo:.2f}-{fprhi:.2f}]"
        )
    console.print(sweep_tbl)

    sig_tbl = Table(title="Per-signal hit rates (top 20)")
    sig_tbl.add_column("signal")
    sig_tbl.add_column("total")
    sig_tbl.add_column("on_phish")
    sig_tbl.add_column("on_benign")
    sig_tbl.add_column("precision")
    for r in per_signal_rows[:20]:
        sig_tbl.add_row(r["signal"], str(r["fires_total"]),
                        str(r["fires_on_phish"]), str(r["fires_on_benign"]),
                        f"{r['phish_precision']:.3f}")
    console.print(sig_tbl)

    console.print(f"\nResults written:")
    console.print(f"  {csv_path}")
    console.print(f"  {summary_path}")
    console.print(f"\n[dim]{len(scored)} rows in {elapsed:.1f}s "
                  f"({summary['rows_per_second']} rows/s)[/dim]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
