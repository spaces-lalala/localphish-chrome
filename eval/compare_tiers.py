"""Tier A vs Tier B drift report.

Reads:
  results/tier_a_results.csv   (per-row signals + score)
  results/tier_b_results.csv   (per-row static_features / rendered_features / diff)

Joins on URL and emits:
  results/tier_compare.json    machine-readable diff summary
  stdout                       rich-table human report

The thing we actually care about: **which rows would Tier A and Tier B
classify differently?** Tier A only sees static HTML; Tier B sees the
post-JS DOM. If a sample fires `dom.password_no_tls` in Tier B but not Tier
A, that means the password field was JS-injected — Tier A would miss it
in batch eval. This number is the empirical answer to "how badly does Tier
A under-represent real phishing?", which is exactly the question the
Week 16 punchline turns on.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier-a", type=Path,
                        default=Path(__file__).parent / "results/tier_a_results.csv")
    parser.add_argument("--tier-b", type=Path,
                        default=Path(__file__).parent / "results/tier_b_results.csv")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_compare.json")
    args = parser.parse_args()
    console = Console()

    if not args.tier_a.exists():
        console.print(f"[red]missing[/red] {args.tier_a} — run `tier_a_static.py` first")
        return 2
    if not args.tier_b.exists():
        console.print(f"[red]missing[/red] {args.tier_b} — run `tier_b_rendered.py` first")
        return 2

    # Tier A
    tier_a: dict[str, dict] = {}
    with args.tier_a.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            tier_a[row["url"]] = {
                "score": int(row["score"]),
                "verdict": row["verdict"],
                "signals": row["signals"].split("|") if row["signals"] else []
            }

    # Tier B
    tier_b: dict[str, dict] = {}
    with args.tier_b.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try:
                static = json.loads(row["static_features"]) if row["static_features"] else {}
                rendered = json.loads(row["rendered_features"]) if row["rendered_features"] else {}
                diff = json.loads(row["diff"]) if row["diff"] else {}
            except json.JSONDecodeError:
                continue
            tier_b[row["url"]] = {"static": static, "rendered": rendered, "diff": diff,
                                  "label": int(row.get("label", -1))}

    # Join
    joined = sorted(set(tier_a.keys()) & set(tier_b.keys()))
    only_a = sorted(set(tier_a.keys()) - set(tier_b.keys()))
    only_b = sorted(set(tier_b.keys()) - set(tier_a.keys()))

    drift_field_counts: Counter[str] = Counter()
    js_injected_password = 0
    js_injected_form = 0
    cloaking_only_in_static = 0
    cloaking_only_in_rendered = 0

    for url in joined:
        b = tier_b[url]
        diff = b.get("diff", {})
        for k in diff:
            if not k.startswith("_"):
                drift_field_counts[k] += 1
        # JS-injected password: rendered has password but static didn't.
        d_pw = diff.get("hasPasswordField")
        if d_pw and d_pw.get("rendered") and not d_pw.get("static"):
            js_injected_password += 1
        d_form = diff.get("formCount")
        if d_form and d_form.get("rendered", 0) > d_form.get("static", 0):
            js_injected_form += 1
        # Cloaking widget present in one tier but not the other
        d_ts = diff.get("hasTurnstileWidget")
        if d_ts:
            if d_ts.get("static") and not d_ts.get("rendered"):
                cloaking_only_in_static += 1
            elif d_ts.get("rendered") and not d_ts.get("static"):
                cloaking_only_in_rendered += 1

    n = len(joined) or 1
    summary = {
        "joined_rows": n,
        "tier_a_only": len(only_a),
        "tier_b_only": len(only_b),
        "feature_drift_counts": dict(drift_field_counts),
        "js_injected_password": js_injected_password,
        "js_injected_form": js_injected_form,
        "cloaking_in_static_not_rendered": cloaking_only_in_static,
        "cloaking_in_rendered_not_static": cloaking_only_in_rendered,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- Report ----
    tbl = Table(title=f"Tier A vs Tier B drift ({n} joined rows)")
    tbl.add_column("metric"); tbl.add_column("count"); tbl.add_column("pct")
    for k, v in summary.items():
        if k == "feature_drift_counts":
            continue
        if isinstance(v, int):
            tbl.add_row(k, str(v), f"{(v / n) * 100:.1f}%" if k != "joined_rows" else "")
    console.print(tbl)

    if drift_field_counts:
        tbl2 = Table(title="Per-feature disagreement (rendered vs static)")
        tbl2.add_column("feature"); tbl2.add_column("count"); tbl2.add_column("pct")
        for k, c in drift_field_counts.most_common():
            tbl2.add_row(k, str(c), f"{(c / n) * 100:.1f}%")
        console.print(tbl2)

    console.print(f"\n[green]wrote[/green] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
