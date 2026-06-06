"""Tier F — production-proxy: rendered rules + Ollama LLM.

Closes the gap reviewer #6 flagged: every previous tier measures only ONE
side of the production setup —
  - Tier C: rendered rules, no LLM (Nano can't load in Playwright Chromium)
  - Tier D: static BS4 rules + Ollama LLM (not rendered)
  - Tier E.5: 3 adversarial pairs, force_llm on rules=100 already-dangerous

Production setup is "real extension (rendered DOM) + on-device LLM". This
tier joins:
  - Tier C's rendered rules score (from real extension via Playwright)
  - Tier B's rendered text (visibleTextSample from Playwright DOM extraction)
  - Ollama Qwen 2.5-0.5B as LLM stage (proxy for Nano on Lite profile —
    same model family as WebLLM Pro, used because Playwright Chromium
    can't load Nano)

Two modes:
  - `production` (default): grey-band gating (15 <= rules <= 84) like the
    real cascade. LLM only fires when rules layer is uncertain.
  - `force_llm`: bypass gating, call LLM on every row. Used to measure
    LLM's RAW benign-FPR — the kill-metric Week 14 §9.1 self-defined that
    has never actually been quantified.

Caveats (these are real, write them into the report not just here):
  1. Ollama Qwen 0.5B != Nano. Qwen 0.5B is the Pro Profile proxy; default
     Lite profile uses Nano which is bigger and trained differently. The
     LLM-side numbers here are upper-bound conservative for what Nano on
     Lite would produce.
  2. Tier B/C rendered DOM extraction was done with Playwright +
     Chromium-for-Testing, not the user's everyday Chrome. Some pages may
     render slightly differently (font fallbacks, etc.) but text extraction
     should be ~equivalent.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from tier_d_python_llm import (
    build_user_prompt,
    llm_run_ollama,
    verdict_from_score,
    confusion,
    bootstrap_ci,
)


# ----------------------------------------------------------- data loaders


def load_tier_c(path: Path) -> dict[str, dict]:
    """Tier C CSV columns: url, label, verdict, score, meta, latency_s."""
    out: dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                out[row["url"]] = {
                    "label": int(row["label"]),
                    "rendered_rules_score": int(row["score"]),
                    "rendered_verdict": row["verdict"],
                }
            except (ValueError, KeyError):
                continue
    return out


def load_tier_b(path: Path) -> dict[str, dict]:
    """Tier B CSV columns: url, label, static_features, rendered_features, diff."""
    out: dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "")
            rendered_text = ""
            try:
                rf = json.loads(row["rendered_features"]) if row.get("rendered_features") else {}
                rendered_text = rf.get("visibleTextSample", "")
            except json.JSONDecodeError:
                pass
            out[url] = {"rendered_text": rendered_text}
    return out


# ---------------------------------------------------------------- runner


def run(args, console: Console) -> int:
    tier_c = load_tier_c(args.tier_c)
    tier_b = load_tier_b(args.tier_b)
    console.print(f"Tier C rows: {len(tier_c)}, Tier B rows: {len(tier_b)}")
    if not tier_c:
        console.print(f"[red]missing or empty Tier C CSV[/red] {args.tier_c}")
        return 2

    # Probe Ollama
    import httpx
    try:
        with httpx.Client(timeout=5.0) as c:
            r = c.get(f"{args.ollama_url.rstrip('/')}/api/tags")
            if r.status_code != 200:
                console.print(f"[red]Ollama not responding[/red] {args.ollama_url}")
                return 2
    except Exception as e:
        console.print(f"[red]Ollama probe failed[/red]: {e}")
        return 2

    rows = []
    for url, c_data in tier_c.items():
        b_data = tier_b.get(url, {})
        rows.append({
            "url": url,
            "label": c_data["label"],
            "rendered_rules": c_data["rendered_rules_score"],
            "rendered_text": b_data.get("rendered_text", ""),
        })

    console.print(f"[cyan]Tier F — mode={args.mode}, n={len(rows)}[/cyan]")
    console.print(f"  LLM gating: "
                  + ("grey-band (15 <= rules <= 84)" if args.mode == "production"
                     else "FORCE all rows"))

    # Write per-row CSV
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fout = args.out.open("w", encoding="utf-8", newline="")
    writer = csv.writer(fout)
    writer.writerow(["url", "label", "rendered_rules", "llm_called",
                     "llm_score", "llm_verdict", "final_score", "final_verdict"])

    llm_called_count = 0
    llm_succeeded_count = 0
    rendered_rules_scores: list[int] = []
    final_scores: list[int] = []

    for i, r in enumerate(rows):
        rules_score = r["rendered_rules"]
        in_grey_band = 15 <= rules_score <= 84
        call_llm = args.mode == "force_llm" or in_grey_band

        llm_score = None
        llm_verdict = None
        if call_llm:
            llm_called_count += 1
            from urllib.parse import urlparse
            import tldextract
            etld1 = ""
            try:
                host = urlparse(r["url"]).hostname or ""
                ext = tldextract.extract(host)
                if ext.domain and ext.suffix:
                    etld1 = f"{ext.domain}.{ext.suffix}"
            except Exception:
                pass
            # rule_signals for the prompt: empty since we don't have them per-row
            # from Tier C's CSV (it stored verdict + score only). The LLM sees
            # only URL + eTLD+1 + rendered text — same info as the extension
            # gives Nano when no rule signals fired strongly.
            prompt = build_user_prompt(r["url"], etld1, "", r["rendered_text"], [])
            out = llm_run_ollama(args.model, args.ollama_url, prompt, args.timeout_s)
            if out and isinstance(out.get("risk_score"), (int, float)):
                llm_succeeded_count += 1
                llm_score = int(out["risk_score"])
                llm_verdict = str(out.get("verdict", ""))

        final_score = max(rules_score, llm_score or 0)
        final_verdict = verdict_from_score(final_score)

        rendered_rules_scores.append(rules_score)
        final_scores.append(final_score)

        writer.writerow([r["url"], r["label"], rules_score,
                         "Y" if call_llm else "N",
                         llm_score or "", llm_verdict or "",
                         final_score, final_verdict])

        if (i + 1) % 20 == 0 or (i + 1) == len(rows):
            console.print(f"  [{i + 1}/{len(rows)}] rules={rules_score} "
                          f"llm={llm_score} final={final_verdict}/{final_score} "
                          f"(called={llm_called_count}, ok={llm_succeeded_count})")

    fout.close()

    # ---- Metrics
    y_true = [r["label"] for r in rows]
    y_pred_rules_only = [1 if s >= 50 else 0 for s in rendered_rules_scores]
    y_pred_final = [1 if s >= 50 else 0 for s in final_scores]

    m_rules = confusion(y_true, y_pred_rules_only)
    m_final = confusion(y_true, y_pred_final)
    ci_rules = bootstrap_ci(y_true, y_pred_rules_only)
    ci_final = bootstrap_ci(y_true, y_pred_final)

    # Per-class FPR breakdown: how many benigns did the LLM falsely call positive?
    benign_indices = [i for i, r in enumerate(rows) if r["label"] == 0]
    llm_called_on_benign = 0
    llm_fp_on_benign = 0
    final_fp_on_benign = 0
    for i in benign_indices:
        # Re-read: we wrote llm_called/score per row. Compare again from final_scores.
        if call_llm := (args.mode == "force_llm" or
                        (15 <= rendered_rules_scores[i] <= 84)):
            llm_called_on_benign += 1
        # Did final cascade FP on this benign?
        if final_scores[i] >= 50:
            final_fp_on_benign += 1

    # Re-read CSV to count LLM-side FP on benign
    with args.out.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if int(row["label"]) == 0 and row["llm_score"]:
                try:
                    if int(row["llm_score"]) >= 50:
                        llm_fp_on_benign += 1
                except ValueError:
                    pass

    summary = {
        "mode": args.mode,
        "n_rows": len(rows),
        "n_phish": sum(1 for r in rows if r["label"] == 1),
        "n_benign": sum(1 for r in rows if r["label"] == 0),
        "llm_called": llm_called_count,
        "llm_succeeded": llm_succeeded_count,
        "llm_called_on_benign": llm_called_on_benign,
        "llm_fp_on_benign_alone": llm_fp_on_benign,
        "rendered_rules_at_thr50": {**m_rules, **ci_rules},
        "cascade_with_llm_at_thr50": {**m_final, **ci_final},
        "benign_fp_breakdown": {
            "n_benign": len(benign_indices),
            "llm_called_on_benign": llm_called_on_benign,
            "llm_FP_alone (llm_score >= 50)": llm_fp_on_benign,
            "cascade_FP_after_max (final >= 50)": final_fp_on_benign,
        },
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- Report
    tbl = Table(title=f"Tier F production-proxy — mode={args.mode}, n={len(rows)}")
    tbl.add_column("metric")
    tbl.add_column("rendered rules-only")
    tbl.add_column("rendered + Ollama")
    tbl.add_column("delta")
    def fmt(v):
        if isinstance(v, float) and (v != v):
            return "N/A"
        return f"{v:.3f}" if isinstance(v, float) else str(v)
    for k in ("precision", "recall", "f1", "fpr"):
        tbl.add_row(k.upper(), fmt(m_rules[k]), fmt(m_final[k]),
                    fmt(m_final[k] - m_rules[k]) if isinstance(m_rules[k], float) and isinstance(m_final[k], float)
                    and m_rules[k] == m_rules[k] and m_final[k] == m_final[k] else "-")
    for k in ("tp", "fp", "fn", "tn"):
        tbl.add_row(k.upper(), str(m_rules[k]), str(m_final[k]), str(m_final[k] - m_rules[k]))
    console.print(tbl)

    fpr_tbl = Table(title=f"Benign-side FPR breakdown (n_benign={summary['n_benign']})")
    fpr_tbl.add_column("metric")
    fpr_tbl.add_column("count")
    fpr_tbl.add_column("rate vs n_benign")
    for k, v in summary["benign_fp_breakdown"].items():
        if k == "n_benign":
            continue
        rate = v / max(1, summary["n_benign"])
        fpr_tbl.add_row(k, str(v), f"{rate * 100:.1f}%")
    console.print(fpr_tbl)

    console.print(
        f"\n[bold]LLM stage[/bold]: called {llm_called_count}/{len(rows)} rows, "
        f"{llm_succeeded_count} succeeded "
        f"({(llm_called_count - llm_succeeded_count) / max(1, llm_called_count) * 100:.1f}% failure)"
    )
    console.print(f"\n[green]wrote[/green] {args.out}")
    console.print(f"[green]wrote[/green] {args.summary}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tier-c", type=Path,
                        default=Path(__file__).parent / "results/tier_c_results.csv")
    parser.add_argument("--tier-b", type=Path,
                        default=Path(__file__).parent / "results/tier_b_results.csv")
    parser.add_argument("--mode", choices=["production", "force_llm"], default="production",
                        help="production = grey-band gating (real cascade behavior); "
                             "force_llm = call LLM on every row (benign-FPR diagnostic)")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_f_results.csv")
    parser.add_argument("--summary", type=Path,
                        default=Path(__file__).parent / "results/tier_f_summary.json")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:0.5b")
    parser.add_argument("--timeout-s", type=float, default=60.0)
    args = parser.parse_args()
    # Per-mode default output paths
    if args.mode == "force_llm" and str(args.out).endswith("tier_f_results.csv"):
        args.out = args.out.parent / "tier_f_forcellm_results.csv"
        args.summary = args.summary.parent / "tier_f_forcellm_summary.json"
    return run(args, Console())


if __name__ == "__main__":
    raise SystemExit(main())
