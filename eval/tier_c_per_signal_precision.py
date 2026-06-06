"""Stage 2a — per-signal precision on the RENDERED base.

Reviewer's complaint (round 3 §10 條 13): §3.2 per-signal precision was
computed against the static BS4 Tier A base, but the central report
argument is that "rendering changes everything". So the weight-tuning
decisions that report cites are anchored in numbers the report itself
calls unreliable. Internal contradiction.

This script rebuilds per-signal precision on the rendered base by:
  1. Loading tier_b_results.csv (rendered_features JSON per row from
     Playwright DOM extraction).
  2. Running the Python Stage 1 + Stage 2 detectors against each row,
     producing per-row firing signals.
  3. Joining against the row labels (phish=1 / benign=0) and computing
     precision = TP / (TP + FP) per signal.

Why the firing rate may differ vs Tier C's official CSV:
  - Tier C ran the actual extension via Playwright. This script re-runs
    the Python port against the same rendered_features. Since Stage 0
    refactored both sides to the same signal-spec.json, weights agree
    by construction; the only drift sources are (a) detectors TS-side
    that Python skipped (homograph confusables), (b) BS4 attribute
    parsing quirks. We document this caveat in the report.

Output: results/tier_c_per_signal_precision.csv + .json
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from localphish_eval.rules import load_rule_data, run_stage1
from localphish_eval.dom_features import analyze_dom


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier-b-csv", type=Path,
                        default=Path(__file__).parent / "results/tier_b_results.csv")
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data")
    parser.add_argument("--out-csv", type=Path,
                        default=Path(__file__).parent / "results/tier_c_per_signal_precision.csv")
    parser.add_argument("--out-json", type=Path,
                        default=Path(__file__).parent / "results/tier_c_per_signal_precision.json")
    args = parser.parse_args()
    console = Console()
    data = load_rule_data(args.data_dir)

    if not args.tier_b_csv.exists():
        console.print(f"[red]missing Tier B csv[/red]: {args.tier_b_csv}")
        return 1

    # ---- per-signal counters -------------------------------------------
    fired_phish: dict[str, int] = {}
    fired_benign: dict[str, int] = {}
    n_phish = 0
    n_benign = 0

    with args.tier_b_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                label = int(row["label"])
            except (ValueError, KeyError):
                continue
            try:
                rendered = json.loads(row["rendered_features"])
            except Exception:
                continue

            url = rendered.get("url") or row.get("url") or ""
            # Some Tier B rows have rendered_features but with the HTML body
            # excerpt stored separately under "_html". The Tier B run wrote
            # the visibleTextSample and we re-derive Stage 2 from the
            # rendered features dict directly via analyze_dom() — for that
            # we need an HTML excerpt. Reconstruct a minimal HTML wrapper
            # from the structured features so analyze_dom can run.
            stage1 = run_stage1(url, data)
            s1_sigs = [s.id for s in stage1["signals"]]

            # We don't have raw HTML here, just structured features. Build a
            # minimal HTML scaffold that exposes the same fields to BS4 so
            # the standard Stage 2 detectors can fire. This is a pragmatic
            # compromise — the alternative (re-running Playwright across
            # all 117 rows) is what Tier C already did.
            html_scaffold = _build_scaffold(rendered)
            s2_sigs = [s.id for s in analyze_dom(
                html_scaffold, url, data,
                data_dir=args.data_dir
            )]

            all_sigs = set(s1_sigs + s2_sigs)
            if label == 1:
                n_phish += 1
                for sid in all_sigs:
                    fired_phish[sid] = fired_phish.get(sid, 0) + 1
            else:
                n_benign += 1
                for sid in all_sigs:
                    fired_benign[sid] = fired_benign.get(sid, 0) + 1

    n_total = n_phish + n_benign
    all_signals = sorted(set(fired_phish.keys()) | set(fired_benign.keys()))

    # ---- per-signal precision -----------------------------------------
    out_rows: list[dict] = []
    for sid in all_signals:
        tp = fired_phish.get(sid, 0)
        fp = fired_benign.get(sid, 0)
        total = tp + fp
        if total == 0:
            continue
        precision = tp / total
        out_rows.append({
            "signal": sid,
            "tp_on_phish": tp,
            "fp_on_benign": fp,
            "total_fires": total,
            "precision": round(precision, 3),
            "hit_rate_phish": round(tp / n_phish, 3) if n_phish else 0.0,
            "hit_rate_benign": round(fp / n_benign, 3) if n_benign else 0.0,
        })

    # ---- ranked output -------------------------------------------------
    out_rows.sort(key=lambda r: (-r["precision"], -r["total_fires"]))

    tbl = Table(title=f"Per-signal precision on RENDERED base (n_phish={n_phish}, n_benign={n_benign}, n_total={n_total})")
    tbl.add_column("signal")
    tbl.add_column("TP/(TP+FP)")
    tbl.add_column("precision")
    tbl.add_column("phish hit-rate")
    tbl.add_column("benign hit-rate")
    for r in out_rows:
        tbl.add_row(
            r["signal"],
            f"{r['tp_on_phish']}/{r['total_fires']}",
            f"{r['precision']:.3f}",
            f"{r['hit_rate_phish']:.3f}",
            f"{r['hit_rate_benign']:.3f}",
        )
    console.print(tbl)

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()) if out_rows else
                           ["signal", "tp_on_phish", "fp_on_benign", "total_fires",
                            "precision", "hit_rate_phish", "hit_rate_benign"])
        w.writeheader()
        w.writerows(out_rows)
    summary = {
        "n_phish": n_phish,
        "n_benign": n_benign,
        "n_total": n_total,
        "per_signal": out_rows,
    }
    args.out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n[green]wrote[/green] {args.out_csv}")
    console.print(f"[green]wrote[/green] {args.out_json}")
    return 0


def _build_scaffold(features: dict) -> str:
    """Reconstruct a minimal HTML excerpt from rendered PageFeatures so the
    BS4-based Stage 2 detectors can run. Drops sub-detectors that need raw
    DOM (favicon-CDN-match runs from features.faviconUrl directly which
    survives this scaffold).

    This is a structural surrogate, NOT a re-render — but for signals like
    `dom.password_cross_etld1_post`, `dom.tw_pii_combo` etc., the structured
    features are all that's needed.
    """
    title = features.get("title", "")
    body_text = features.get("visibleTextSample", "")
    forms_html = []
    for action in features.get("formActions", []) or []:
        inputs = []
        if features.get("hasPasswordField"):
            inputs.append('<input type="password" name="password">')
        if features.get("hasOtpField"):
            inputs.append('<input name="otp" autocomplete="one-time-code">')
        if features.get("hasCreditCardField"):
            inputs.append('<input name="card_number" autocomplete="cc-number">')
        if features.get("hasTwNationalIdField"):
            inputs.append('<input name="idno" placeholder="身分證字號">')
        forms_html.append(f'<form action="{action}" method="post">{"".join(inputs)}</form>')
    if not forms_html and (features.get("hasPasswordField") or features.get("hasCreditCardField")):
        # No declared form action — emit a same-origin form so cross-eTLD+1
        # checks don't fire spuriously.
        inputs = []
        if features.get("hasPasswordField"):
            inputs.append('<input type="password" name="password">')
        forms_html.append(f'<form>{"".join(inputs)}</form>')
    fav = features.get("faviconUrl") or ""
    favicon_link = f'<link rel="icon" href="{fav}">' if fav else ""

    return (
        f'<!doctype html><html><head><title>{title}</title>{favicon_link}</head>'
        f'<body><div>{body_text}</div>{"".join(forms_html)}</body></html>'
    )


if __name__ == "__main__":
    raise SystemExit(main())
