"""Tier G — Taiwan-specific phishing eval (Stage 1b).

Closes the long-standing gap: every prior tier ran on PhreshPhish (English-
brand-heavy) or on hand-curated *English* fixtures. We never measured how
well the localized detectors (fake-gov-tw / cross-strait-language / TW PII
combo / TW first-class allowlist / 165 bloom filter) actually fire on
**Taiwan-themed phishing pages** at the corpus level.

What this tier IS:
  - 9 static HTML fixtures under `test/fixtures/tw/` (3 from Week 14
    submission + 6 added Week 16 v3: 中華郵政, 國稅局, ETC, LINE Pay,
    健保署, 蝦皮, 中華電信, 勞保, 監理). Each was hand-written by the
    project author from 165 article descriptions; they are best-effort
    reconstructions of *real* TW scam page patterns the author has seen.
  - Measures cascade behaviour with rules-only Stage 1 + Stage 2 against
    these pages, plus an optional "+ bloom filter" run when the user has
    populated extension/src/data/tw-scam-bloom.json from the data.gov.tw
    feed.

What this tier IS NOT:
  - It is NOT in-the-wild crawled samples. The original task plan asked for
    15-30 real samples from 165 / web.archive.org; the 165 JSON API
    (`fetch_165_articles.py`) returns titles + bodies but the bodies are
    empty (165 doesn't republish the verbatim phish URLs / HTML for IP /
    abuse-vector reasons). web.archive.org pulls require WebFetch quota
    that was unavailable when this tier was wired. The harness here is
    structurally complete; the user can drop more `*.html` files into
    `test/fixtures/tw/` and rerun without code changes.
  - Therefore the numbers should be read as "lower-bound on what the
    detectors catch on TW-styled phishing patterns I wrote" — not as
    SOTA-comparable wild-sample recall. The report flags this caveat
    explicitly.

Output:
  results/tier_g_results.csv     per-fixture: filename, url, rules_score, fired_signals, verdict
  results/tier_g_summary.json    counts, per-signal hit rate, bloom-on vs bloom-off comparison
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


# Each fixture is a (filename, synthetic_url) pair. The synthetic URL mirrors
# the attacker host pattern we'd expect for that scam category (lookalike of
# the genuine Taiwan brand / institution). It does NOT match anything real
# and never connects out — fixtures are local file:// reads only.
TW_FIXTURES: list[tuple[str, str, str]] = [
    # filename                              attacker URL                                              scam category
    ("post-customs-fake.html",              "https://post-tw-customs.duty-fee.click/payment",         "中華郵政 包裹補繳關稅"),
    ("ntbsa-tax-refund-fake.html",          "https://ntbsa-refund-2026.gov-tw.click/refund",          "國稅局 退稅通知"),
    ("etc-overdue-fake.html",               "https://etc-payment-tw.fetc-online.top/pay",             "遠通電收 ETC 催繳"),
    ("linepay-binding-fake.html",           "https://linepay-verify.account-renew.click/post",        "LINE Pay 重新綁卡"),
    ("nhi-card-renewal-fake.html",          "https://nhi-care-verify.healthcare-tw.click/submit",     "健保署 IC 卡過期"),
    ("shopee-seller-dispute-fake.html",     "https://shopee-pay-refund.account-tw.click/post",        "蝦皮 解除分期"),
    ("cht-bill-overdue-fake.html",          "https://cht-online-pay.bill-tw.top/submit",              "中華電信 欠費停話"),
    ("labor-insurance-refund-fake.html",    "https://laborgov-refund.tw-portal.click/apply",          "勞保 溢繳退費"),
    ("monitor-traffic-fine-fake.html",      "https://mvdis-pay.gov-tw.click/post",                    "監理服務網 違規繳費"),
]


def run_one(fixture_path: Path, url: str, data) -> dict:
    html = fixture_path.read_text(encoding="utf-8")
    stage1 = run_stage1(url, data)
    s1_sigs = stage1["signals"]
    s1_score = stage1["rawScore"]

    # If Stage 1 short-circuits dangerous (bloom/typosquat-driven), we still
    # run Stage 2 for diagnostic visibility but the cascade verdict is
    # already locked. If it short-circuits safe (institutional-TLD /
    # allowlist), Stage 2 is moot.
    if stage1.get("shortCircuit") and stage1.get("rawScore", 0) == 0:
        s2_sigs = []
    else:
        # data_dir for favicon-CDN lookup (matches Tier A invocation pattern).
        from pathlib import Path as _P
        s2_sigs = analyze_dom(
            html, url, data,
            data_dir=_P(__file__).resolve().parent.parent / "extension" / "src" / "data",
        )

    all_sigs = list(s1_sigs) + list(s2_sigs)
    s2_score = sum(s.weight for s in s2_sigs)
    total = min(100, s1_score + s2_score)

    if total >= 85:
        verdict = "dangerous"
    elif total >= 50:
        verdict = "suspicious"
    elif total >= 15:
        verdict = "caution"
    else:
        verdict = "safe"

    return {
        "filename": fixture_path.name,
        "url": url,
        "stage1_score": s1_score,
        "stage2_score": s2_score,
        "total_score": total,
        "verdict": verdict,
        "fired_signals": [{"id": s.id, "weight": s.weight, "detail": s.detail or ""} for s in all_sigs],
        "short_circuit": bool(stage1.get("shortCircuit", False)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures-dir", type=Path,
                        default=Path(__file__).parent.parent / "test/fixtures/tw")
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).parent.parent / "extension/src/data")
    parser.add_argument("--out-csv", type=Path,
                        default=Path(__file__).parent / "results/tier_g_results.csv")
    parser.add_argument("--out-json", type=Path,
                        default=Path(__file__).parent / "results/tier_g_summary.json")
    args = parser.parse_args()
    console = Console()

    data = load_rule_data(args.data_dir)
    console.print(
        f"[cyan]Tier G — Taiwan-specific phishing eval[/cyan]\n"
        f"  bloom n_inserted={data.bloom.n_inserted}  "
        f"tw_allowlist size={len(data.tw_allowlist)}"
    )

    rows: list[dict] = []
    for fname, url, category in TW_FIXTURES:
        p = args.fixtures_dir / fname
        if not p.exists():
            console.print(f"[red]missing fixture[/red]: {p}")
            continue
        r = run_one(p, url, data)
        r["category"] = category
        rows.append(r)
        sig_ids = [s["id"] for s in r["fired_signals"]]
        console.print(
            f"  [bold]{r['filename']:<38}[/bold] "
            f"score={r['total_score']:>3}  verdict={r['verdict']:<10}  "
            f"signals={','.join(sig_ids[:5])}{'…' if len(sig_ids) > 5 else ''}"
        )

    # ----------- summary --------------------------------------------------
    n = len(rows)
    n_caught = sum(1 for r in rows if r["total_score"] >= 50)
    n_dangerous = sum(1 for r in rows if r["verdict"] == "dangerous")

    sig_hits: dict[str, int] = {}
    for r in rows:
        for s in r["fired_signals"]:
            sig_hits[s["id"]] = sig_hits.get(s["id"], 0) + 1

    tbl = Table(title=f"Tier G Summary (n={n})")
    tbl.add_column("metric")
    tbl.add_column("value")
    tbl.add_row("samples", str(n))
    tbl.add_row("caught at threshold 50 (suspicious+)", f"{n_caught} ({n_caught/n:.0%})")
    tbl.add_row("caught at threshold 85 (dangerous)", f"{n_dangerous} ({n_dangerous/n:.0%})")
    tbl.add_row("bloom n_inserted", str(data.bloom.n_inserted))
    tbl.add_row("bloom-driven short-circuits", str(sig_hits.get("url.bloomfilter_blacklist_hit", 0)))
    console.print(tbl)

    tbl2 = Table(title="Per-signal hit rate (Tier G)")
    tbl2.add_column("signal"); tbl2.add_column("hits"); tbl2.add_column("rate")
    for sid, c in sorted(sig_hits.items(), key=lambda kv: -kv[1]):
        tbl2.add_row(sid, str(c), f"{c/n:.0%}")
    console.print(tbl2)

    # ----------- write artifacts ------------------------------------------
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "category", "url", "stage1_score", "stage2_score",
                         "total_score", "verdict", "fired_signal_ids"])
        for r in rows:
            writer.writerow([
                r["filename"], r["category"], r["url"],
                r["stage1_score"], r["stage2_score"], r["total_score"], r["verdict"],
                ",".join(s["id"] for s in r["fired_signals"]),
            ])

    summary = {
        "n": n,
        "caught_thr50": n_caught,
        "caught_thr85": n_dangerous,
        "bloom_n_inserted": data.bloom.n_inserted,
        "per_signal_hits": sig_hits,
        "rows": rows,
    }
    args.out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    console.print(f"\n[green]wrote[/green] {args.out_csv}")
    console.print(f"[green]wrote[/green] {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
