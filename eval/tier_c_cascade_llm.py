"""Tier C — full cascade-with-LLM evaluation.

This runs the **real LocalPhish extension** (Stage 1 + Stage 2 + Stage 3
Gemini Nano) over a PhreshPhish subset and computes F1 / precision / recall.
That's the Week 16 punchline tool — the comparison "rules-only F1=0.454 at
threshold 5 vs cascade+LLM F1=?" lives here.

How it works:
  1. Launch Chromium persistent context with the built extension loaded
     (--load-extension=…/dist).
  2. Spin up a local HTTP server that serves each PhreshPhish HTML excerpt
     on a unique path.
  3. For each row:
     - Navigate Chromium to the served URL.
     - Wait up to 60 s for the in-page badge UI to settle (Nano can be
       slow; the popup polls up to 200 s, but for batch eval we cap at 60).
     - Read the badge's aria-label to extract VERDICT + SCORE.
     - Record per-row result.
  4. Aggregate into F1 / precision / recall + bootstrap 95% CI.

What this does NOT do:
  - Does not exercise WebLLM Pro Profile (would need to also script the
    profile toggle, plus Qwen on iGPU is too slow for batch eval — 30-90 s
    per row × 100 rows = hours). Pro/Lite comparison done qualitatively
    in the final report; quantitative Pro eval is future work.
  - Does not measure FPR on benign URLs that the cascade has to actually
    LLM-judge. Allow-list benigns short-circuit at Stage 1, so a Tranco
    benign just returns SAFE at 0 ms. To measure cascade FPR you'd need
    benign samples that fall in the 15-84 grey band — outside our
    PhreshPhish snapshot's content.

Usage:
    cd extension && npm run build         # produces dist/
    cd ../eval
    uv run python tier_c_cascade_llm.py --limit 60
    uv run python tier_c_cascade_llm.py --limit 0     # all rows
    uv run python tier_c_cascade_llm.py --threshold 50

Heads-up: the user's Chrome profile needs Gemini Nano enabled
(chrome://flags + chrome://components Optimization Guide On Device Model
downloaded). Without it the cascade falls through to rules-only and the
result matches Tier A's static numbers.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

# Re-use the in-memory HTTP server harness from Tier B.
from tier_b_rendered import serve_blobs


# ---- Verdict extraction (matches extension/src/content/badge.ts DOM) ------


# Badge structure (from badge.ts buildContent):
#   <div id="localphish-badge-host">
#     <shadow root>
#       <div .badge id="lp-badge" aria-label="LocalPhish DANGEROUS score 95">
#         <span .label>DANGEROUS</span>
#         <span .score>95</span>
#
# For SAFE verdicts the badge is intentionally not rendered (badge.ts:217-222);
# we treat absence of the host element after a long wait as a SAFE classification.
EXTRACT_VERDICT_JS = r"""
() => {
  const host = document.getElementById("localphish-badge-host");
  if (!host) return { state: "no-badge" };
  const root = host.shadowRoot;
  if (!root) return { state: "no-shadow" };
  // Loading pill (no verdict yet)?
  const spinner = root.querySelector(".spinner");
  if (spinner) return { state: "analyzing" };
  const badge = root.getElementById("lp-badge");
  if (!badge) return { state: "no-badge-el" };
  const label = badge.querySelector(".label")?.textContent?.trim() ?? "";
  const score = badge.querySelector(".score")?.textContent?.trim() ?? "";
  const meta = root.querySelector(".panel .meta")?.textContent?.trim() ?? "";
  return {
    state: "verdict",
    verdict: label.toLowerCase(),
    score: parseInt(score, 10),
    meta
  };
}
"""


async def classify_one(page, served_url: str, max_wait_s: float = 60.0):
    """Navigate page to URL and poll for the badge to settle on a verdict."""
    try:
        await page.goto(served_url, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        # Continue: Nano fires on partial loads too, the extension's content
        # script runs at document_idle which doesn't depend on full network idle.
        pass

    deadline = time.monotonic() + max_wait_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            res = await page.evaluate(EXTRACT_VERDICT_JS)
        except Exception:
            await asyncio.sleep(0.5)
            continue
        last_state = res
        if res.get("state") == "verdict":
            return res
        if res.get("state") == "no-badge" and time.monotonic() - (deadline - max_wait_s) > 10:
            # No badge AND no loading pill after 10s suggests cascade
            # short-circuited to SAFE (badge.ts hides the badge on safe).
            return {"state": "verdict", "verdict": "safe", "score": 0, "meta": "(no-badge inferred SAFE)"}
        await asyncio.sleep(0.6)

    return last_state or {"state": "timeout", "verdict": "unknown", "score": 0, "meta": ""}


# ---- Metrics --------------------------------------------------------------


def confusion(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def bootstrap_ci(y_true: list[int], y_pred: list[int], n_boot: int = 500,
                 seed: int = 42) -> dict:
    rng = random.Random(seed)
    n = len(y_true)
    if n == 0:
        return {"f1_ci": [0.0, 0.0], "precision_ci": [0.0, 0.0],
                "recall_ci": [0.0, 0.0], "fpr_ci": [0.0, 0.0]}
    f1s, ps, rs, fprs = [], [], [], []
    for _ in range(n_boot):
        idxs = [rng.randrange(n) for _ in range(n)]
        yt = [y_true[i] for i in idxs]
        yp = [y_pred[i] for i in idxs]
        m = confusion(yt, yp)
        f1s.append(m["f1"])
        # precision can be NaN when no positives; treat as 0 for CI sake
        ps.append(m["precision"] if m["precision"] == m["precision"] else 0.0)
        rs.append(m["recall"]); fprs.append(m["fpr"])

    def pct(xs, p):
        xs = sorted(xs)
        k = int(round((p / 100) * (len(xs) - 1)))
        return xs[k]

    return {
        "f1_ci": [pct(f1s, 2.5), pct(f1s, 97.5)],
        "precision_ci": [pct(ps, 2.5), pct(ps, 97.5)],
        "recall_ci": [pct(rs, 2.5), pct(rs, 97.5)],
        "fpr_ci": [pct(fprs, 2.5), pct(fprs, 97.5)],
    }


# ---- Runner ---------------------------------------------------------------


async def run(args, console: Console) -> int:
    from playwright.async_api import async_playwright

    extension_dist = args.extension.resolve()
    if not extension_dist.exists():
        console.print(f"[red]missing[/red] extension dist {extension_dist} — run "
                      f"`cd ../extension && npm run build` first")
        return 2

    rows: list[dict] = []
    with args.input.open("r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("_meta"):
                continue
            rows.append(obj)
    if args.limit:
        rows = rows[: args.limit]
    n_total = len(rows)
    n_phish = sum(1 for r in rows if int(r.get("label", 0)) == 1)
    console.print(f"[cyan]Tier C — cascade-with-LLM on {n_total} rows[/cyan] "
                  f"({n_phish} phish, {n_total - n_phish} benign)")

    out_csv = args.out
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fout = out_csv.open("w", encoding="utf-8", newline="")
    writer = csv.writer(fout)
    writer.writerow(["url", "label", "verdict", "score", "meta", "latency_s"])

    results: list[tuple[int, str, int]] = []  # (label, verdict, score)
    started = time.monotonic()

    with serve_blobs(args.port) as server:
        base_url = f"http://127.0.0.1:{args.port}"
        user_data_dir = Path(tempfile.mkdtemp(prefix="localphish-tierc-"))
        async with async_playwright() as pw:
            ctx = await pw.chromium.launch_persistent_context(
                str(user_data_dir),
                headless=False,  # MV3 extensions don't run headless
                args=[
                    f"--disable-extensions-except={extension_dist}",
                    f"--load-extension={extension_dist}",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
            )
            # Give the extension a few seconds to register, build its
            # offscreen document, and probe Nano. Without this, the first
            # 1-2 rows tend to time out before Nano is ready.
            page = await ctx.new_page()
            await page.goto("about:blank")
            await asyncio.sleep(args.warmup_s)

            for i, row in enumerate(rows):
                url = row.get("url", "")
                html = row.get("html_excerpt") or "<!doctype html><html><body><h1>placeholder</h1></body></html>"
                label = int(row.get("label", 0))
                blob_key = f"row-{i:04d}.html"
                server.html_blobs[blob_key] = html
                served = f"{base_url}/{blob_key}"
                t0 = time.monotonic()
                res = await classify_one(page, served, max_wait_s=args.timeout_s)
                latency = time.monotonic() - t0

                verdict = res.get("verdict", "unknown")
                score = int(res.get("score") or 0)
                meta = res.get("meta", "")
                writer.writerow([url, label, verdict, score, meta, f"{latency:.2f}"])
                fout.flush()
                results.append((label, verdict, score))

                if (i + 1) % 10 == 0 or (i + 1) == n_total:
                    elapsed = time.monotonic() - started
                    rate = (i + 1) / max(1.0, elapsed)
                    eta = (n_total - i - 1) / max(0.01, rate)
                    console.print(f"  [{i + 1}/{n_total}] last: {verdict}/{score} "
                                  f"({latency:.1f}s) · {rate:.2f} rows/s · ETA {eta / 60:.1f} min")

            await ctx.close()

    fout.close()
    elapsed = time.monotonic() - started

    # ---- Metrics summary ----
    y_true = [lab for lab, _, _ in results]
    # Threshold sweep on score (label==1 if score >= thr)
    scores = [s for _, _, s in results]
    sweep = []
    for thr in (5, 15, 25, 50, 85):
        y_pred = [1 if s >= thr else 0 for s in scores]
        m = confusion(y_true, y_pred)
        ci = bootstrap_ci(y_true, y_pred, n_boot=300)
        sweep.append({"threshold": thr, **m, **ci})

    # Verdict-based predictions (treat suspicious + dangerous as positive)
    verdict_to_pred = {"safe": 0, "caution": 0, "suspicious": 1, "dangerous": 1,
                       "unknown": 0, "": 0}
    y_pred_verdict = [verdict_to_pred.get(v, 0) for _, v, _ in results]
    m_verdict = confusion(y_true, y_pred_verdict)
    ci_verdict = bootstrap_ci(y_true, y_pred_verdict, n_boot=300)

    summary = {
        "input": str(args.input),
        "n_rows": n_total,
        "n_phish": n_phish,
        "n_benign": n_total - n_phish,
        "elapsed_seconds": round(elapsed, 1),
        "rows_per_second": round(n_total / max(0.01, elapsed), 2),
        "verdict_metrics": {**m_verdict, **ci_verdict},
        "threshold_sweep": sweep,
        "verdict_counts": {
            v: sum(1 for _, vv, _ in results if vv == v)
            for v in ("safe", "caution", "suspicious", "dangerous", "unknown")
        }
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- Report ----
    tbl = Table(title="Tier C — cascade-with-LLM verdict-based metrics")
    tbl.add_column("metric"); tbl.add_column("value")
    for k in ("precision", "recall", "f1", "fpr"):
        v = m_verdict[k]
        if isinstance(v, float) and (v != v):
            tbl.add_row(k.upper(), "N/A")
        else:
            tbl.add_row(k.upper(), f"{v:.3f}")
    for k in ("tp", "fp", "fn", "tn"):
        tbl.add_row(k.upper(), str(m_verdict[k]))
    console.print(tbl)

    sweep_tbl = Table(title="Threshold sweep on score (95% bootstrap CI)")
    sweep_tbl.add_column("thr"); sweep_tbl.add_column("F1 [CI]")
    sweep_tbl.add_column("Precision"); sweep_tbl.add_column("Recall"); sweep_tbl.add_column("FPR")
    for s in sweep:
        f1lo, f1hi = s["f1_ci"]
        prec = "N/A" if (s["precision"] != s["precision"]) else f"{s['precision']:.3f}"
        sweep_tbl.add_row(
            str(s["threshold"]),
            f"{s['f1']:.3f} [{f1lo:.2f}-{f1hi:.2f}]",
            prec,
            f"{s['recall']:.3f}",
            f"{s['fpr']:.3f}"
        )
    console.print(sweep_tbl)

    vc_tbl = Table(title="Verdict distribution")
    vc_tbl.add_column("verdict"); vc_tbl.add_column("count")
    for v, c in summary["verdict_counts"].items():
        vc_tbl.add_row(v, str(c))
    console.print(vc_tbl)

    console.print(f"\n[green]wrote[/green] {out_csv}")
    console.print(f"[green]wrote[/green] {args.summary}")
    console.print(f"[dim]{n_total} rows in {elapsed / 60:.1f} min ({summary['rows_per_second']} rows/s)[/dim]")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", type=Path,
                        default=Path(__file__).parent.parent / "extension" / "dist")
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "datasets/golden_200.jsonl",
                        help="JSONL with rows {url, label, html_excerpt}. Default is the "
                             "117-row matched mixed set (48 phish + 50 Tranco benign + 19 easy-"
                             "misclassify) — gives valid Precision/FPR. Use phreshphish_subset.jsonl "
                             "for phish-only stress test.")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_c_results.csv")
    parser.add_argument("--summary", type=Path,
                        default=Path(__file__).parent / "results/tier_c_summary.json")
    parser.add_argument("--limit", type=int, default=60,
                        help="cap rows (0 = all). Each row costs 5-25 s; 60 rows ~= 15 min, "
                             "500 rows ~= 2 hours.")
    parser.add_argument("--port", type=int, default=8768)
    parser.add_argument("--warmup-s", type=float, default=8.0,
                        help="seconds to wait after launching Chromium so the SW + "
                             "offscreen doc + Nano probe finish before row 1")
    parser.add_argument("--timeout-s", type=float, default=60.0,
                        help="per-row Nano timeout. Lite (Nano) usually <= 25 s.")
    args = parser.parse_args()
    if not args.input.exists():
        Console().print(f"[red]missing[/red] {args.input}")
        return 2
    return asyncio.run(run(args, Console()))


if __name__ == "__main__":
    raise SystemExit(main())
