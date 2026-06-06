"""Tier D — full cascade eval (rules + LLM stage) in pure Python.

This is the experiment that closes the loop on LocalPhish's core claim:
"Stage 3 LLM is necessary to lift the cascade's recall in the grey band."
Tier C runs the real extension but Nano doesn't load inside Playwright
Chromium, so we never actually measured the LLM contribution on a real
dataset. Tier D bypasses that by running the LLM stage in Python against
the same matched mixed set — measuring rules-only vs cascade-with-LLM
F1/P/R/FPR on identical samples.

How it works:
  1. For each row in the matched mixed set (golden_200.jsonl by default):
     a. Run rules-only cascade (Python port of stage1 + stage2 → score).
     b. If `15 <= score <= 84` (cascade grey band), call the local LLM
        with the v2 prompt (English-only output, Nano-equivalent) and
        parse the JSON.
     c. Final = max(rules_score, llm_score), verdict from that.
  2. Aggregate Precision / Recall / F1 / FPR at multiple thresholds
     + bootstrap 95% CI. Compare against rules-only baseline.

LLM backend. Two adapters, picked at runtime:
  - `ollama`   (default; assumes `ollama serve` running locally + a model
                pulled, e.g. `ollama pull qwen2.5:0.5b`)
  - `none`     (rules-only, sanity check that the harness works)

Why Ollama. Same Qwen 2.5 family as the extension's Pro Profile (WebLLM
Qwen 0.5B), runs locally so the "on-device" thesis is preserved, and
the user only needs `pip-free` Ollama install + one `pull`. Llama-cpp /
transformers would also work but require heavier Python deps.

Usage:
    # 1) Start ollama in another terminal:
    #    ollama pull qwen2.5:0.5b
    #    ollama serve
    #
    # 2) Run the eval:
    cd eval
    uv run python tier_d_python_llm.py --backend ollama --model qwen2.5:0.5b
    uv run python tier_d_python_llm.py --backend none   # rules-only sanity
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import sys
import time
from pathlib import Path
from typing import Optional

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


# ---------------------------------------------------------- LLM backends ---


SYSTEM_PROMPT_EN = """You are a senior cybersecurity analyst grading a webpage for phishing risk.

CRITICAL OUTPUT RULES (override everything):
- Output ONLY a single JSON object. No prose, no markdown fences.
- ALL text in your JSON output MUST be ENGLISH ONLY. Even if the input page
  is in Chinese, describe Chinese evidence in English.
- category MUST be a JSON array of strings, not a single string.

Schema: {"risk_score": <int 0-100>, "verdict": "safe"|"caution"|"suspicious"|"dangerous", "category": [<one or more strings>], "reasons": [<short English strings>], "need_visual": <bool>}

Output budget — stay within 3 reasons, 3 categories, total JSON ≤ 400 chars.

High-risk patterns:
- password + OTP, or password + credit card, on a non-canonical domain → dangerous.
- 12/24-word seed phrase request → dangerous (wallet_drainer).
- Brand impersonation: page claims to be Brand X but URL eTLD+1 ≠ X.com.
- Urgency / authority manipulation (24-hour deadline, account suspension threat).
- Cross-strait language slips: Taiwan institution + mainland Chinese terms (短信、激活、賬號).
- Real bank / SaaS login on canonical brand domain → safe.

Set need_visual=true only when text alone is inconclusive.
"""


def build_user_prompt(url: str, etld1: str, title: str, text: str,
                     rule_signals: list[Signal]) -> str:
    sig_lines = "\n".join(
        f"- {s.id} (+{s.weight}){': ' + s.detail if s.detail else ''}"
        for s in rule_signals[:14]
    ) or "(none)"
    return (
        f"URL: {url}\n"
        f"eTLD+1: {etld1 or '(unknown)'}\n"
        f"Page title: {title or '(none)'}\n"
        f"Rule-layer signals already detected:\n{sig_lines}\n"
        f"Visible page text (truncated, may mix 繁中/簡中/English):\n"
        f"{text[:1500] or '(empty)'}"
    )


def extract_json(raw: str) -> Optional[dict]:
    """Pull the first JSON object out of an LLM response, tolerant of
    surrounding markdown fences or apologies."""
    if not raw:
        return None
    raw = raw.strip()
    # Strip markdown fences
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    # Find the outermost { … } that parses
    depth = 0
    start = -1
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                snippet = raw[start:i + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    pass
    # Fallback: try to load the whole thing
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def llm_run_ollama(model: str, base_url: str, prompt: str, timeout_s: float = 60.0) -> Optional[dict]:
    """Call Ollama's /api/chat endpoint. Returns parsed Stage3-style dict
    or None on failure (parse error, network error, timeout)."""
    import httpx
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.post(
                f"{base_url.rstrip('/')}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT_EN},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "options": {"temperature": 0, "num_predict": 384},
                },
            )
        if resp.status_code != 200:
            return None
        msg = resp.json().get("message", {}).get("content", "")
        return extract_json(msg)
    except Exception:
        return None


# ----------------------------------------------------------- pipeline -----


def cascade_score(url: str, html: str, data, data_dir: Path) -> tuple[int, list[Signal]]:
    """Rules-only score (Stage 1 + Stage 2 BS4)."""
    s1 = run_stage1(url, data)
    sigs: list[Signal] = list(s1["signals"])
    if s1["shortCircuit"]:
        return s1["rawScore"], sigs
    s2 = analyze_dom(html, url, data, data_dir)
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
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
    }


def bootstrap_ci(y_true, y_pred, n_boot: int = 500, seed: int = 42) -> dict:
    rng = random.Random(seed)
    n = len(y_true)
    if n == 0:
        return {"f1_ci": [0, 0], "recall_ci": [0, 0], "precision_ci": [0, 0], "fpr_ci": [0, 0]}
    f1s, ps, rs, fprs = [], [], [], []
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        yt = [y_true[i] for i in idx]
        yp = [y_pred[i] for i in idx]
        m = confusion(yt, yp)
        f1s.append(m["f1"])
        ps.append(m["precision"] if m["precision"] == m["precision"] else 0.0)
        rs.append(m["recall"])
        fprs.append(m["fpr"])

    def pct(xs, p):
        xs = sorted(xs)
        k = int(round((p / 100) * (len(xs) - 1)))
        return xs[k]

    return {
        "f1_ci": [pct(f1s, 2.5), pct(f1s, 97.5)],
        "recall_ci": [pct(rs, 2.5), pct(rs, 97.5)],
        "precision_ci": [pct(ps, 2.5), pct(ps, 97.5)],
        "fpr_ci": [pct(fprs, 2.5), pct(fprs, 97.5)],
    }


# --------------------------------------------------------------- runner ---


def run(args, console: Console) -> int:
    data_dir = args.data_dir
    data = load_rule_data(data_dir)

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
    console.print(f"[cyan]Tier D — full cascade on {n_total} rows[/cyan] "
                  f"({n_phish} phish, {n_total - n_phish} benign)")

    # LLM backend probe
    llm_fn = None
    if args.backend == "ollama":
        try:
            import httpx
            with httpx.Client(timeout=5.0) as c:
                r = c.get(f"{args.ollama_url.rstrip('/')}/api/tags")
                if r.status_code != 200:
                    console.print(f"[red]Ollama not responding at {args.ollama_url}[/red]")
                    return 2
                models_listed = [m.get("name", "") for m in r.json().get("models", [])]
                if not any(args.model in m for m in models_listed):
                    console.print(f"[yellow]warn[/yellow] model '{args.model}' not in "
                                  f"Ollama's pulled list: {models_listed}. Run "
                                  f"`ollama pull {args.model}` first.")
        except ImportError:
            console.print("[red]httpx not installed; install via `uv add httpx`[/red]")
            return 2
        except Exception as e:
            console.print(f"[red]Ollama probe failed[/red]: {e}")
            return 2
        llm_fn = lambda prompt: llm_run_ollama(args.model, args.ollama_url, prompt, args.timeout_s)
        console.print(f"  using Ollama backend → model={args.model}")
    elif args.backend == "none":
        console.print("  rules-only mode (no LLM)")
    else:
        console.print(f"[red]unknown backend[/red]: {args.backend}")
        return 2

    # Run cascade
    args.out.parent.mkdir(parents=True, exist_ok=True)
    import csv
    fout = args.out.open("w", encoding="utf-8", newline="")
    writer = csv.writer(fout)
    writer.writerow(["url", "label", "rules_score", "llm_score", "llm_verdict",
                     "final_score", "final_verdict", "llm_latency_s"])

    rules_scores: list[int] = []
    final_scores: list[int] = []
    final_verdicts: list[str] = []
    llm_fired = 0
    llm_succeeded = 0

    started = time.monotonic()
    for i, row in enumerate(rows):
        url = row.get("url", "")
        html = row.get("html_excerpt") or ""
        label = int(row.get("label", 0))

        rules_score, sigs = cascade_score(url, html, data, data_dir)

        llm_score = None
        llm_verdict_str = None
        llm_latency = 0.0
        in_grey_band = (SAFE_CEILING <= rules_score <= 84) and not _short_circuited(sigs)

        if llm_fn is not None and in_grey_band:
            llm_fired += 1
            etld1 = None
            try:
                from urllib.parse import urlparse as _u
                import tldextract
                ext = tldextract.extract(_u(url).hostname or "")
                if ext.domain and ext.suffix:
                    etld1 = f"{ext.domain}.{ext.suffix}"
            except Exception:
                pass
            text = _strip_html_text(html)
            t0 = time.monotonic()
            llm_out = llm_fn(build_user_prompt(url, etld1 or "", "", text, sigs))
            llm_latency = time.monotonic() - t0
            if llm_out and isinstance(llm_out.get("risk_score"), (int, float)):
                llm_succeeded += 1
                llm_score = int(llm_out["risk_score"])
                llm_verdict_str = str(llm_out.get("verdict", ""))

        final_score = max(rules_score, llm_score or 0)
        final_verdict = verdict_from_score(final_score)

        rules_scores.append(rules_score)
        final_scores.append(final_score)
        final_verdicts.append(final_verdict)
        writer.writerow([url, label, rules_score, llm_score or "",
                         llm_verdict_str or "", final_score, final_verdict,
                         f"{llm_latency:.2f}"])

        if (i + 1) % 10 == 0 or (i + 1) == n_total:
            elapsed = time.monotonic() - started
            console.print(f"  [{i + 1}/{n_total}] last: rules={rules_score} llm={llm_score} "
                          f"final={final_verdict}/{final_score} "
                          f"({llm_latency:.1f}s LLM) · LLM fired {llm_fired}, ok {llm_succeeded}")

    fout.close()

    # Metrics: rules-only vs cascade+LLM at threshold 50 (cascade default)
    y_true = [int(r.get("label", 0)) for r in rows]
    y_pred_rules = [1 if s >= 50 else 0 for s in rules_scores]
    y_pred_final = [1 if s >= 50 else 0 for s in final_scores]
    y_pred_verdict = [1 if v in ("suspicious", "dangerous") else 0 for v in final_verdicts]

    m_rules = confusion(y_true, y_pred_rules)
    m_final = confusion(y_true, y_pred_final)
    m_verdict = confusion(y_true, y_pred_verdict)
    ci_rules = bootstrap_ci(y_true, y_pred_rules)
    ci_final = bootstrap_ci(y_true, y_pred_final)

    summary = {
        "input": str(args.input),
        "n_rows": n_total,
        "n_phish": n_phish,
        "n_benign": n_total - n_phish,
        "backend": args.backend,
        "model": args.model if args.backend == "ollama" else None,
        "llm_fired": llm_fired,
        "llm_succeeded": llm_succeeded,
        "llm_failure_rate": (llm_fired - llm_succeeded) / max(1, llm_fired),
        "rules_only_at_thr50": {**m_rules, **ci_rules},
        "cascade_with_llm_at_thr50": {**m_final, **ci_final},
        "verdict_based": m_verdict,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    # Report
    tbl = Table(title=f"Tier D — rules vs cascade+LLM @ threshold 50 (n={n_total})")
    tbl.add_column("metric")
    tbl.add_column("rules-only")
    tbl.add_column("cascade+LLM")
    tbl.add_column("delta")
    for k in ("precision", "recall", "f1", "fpr"):
        rv = m_rules[k]; fv = m_final[k]
        def fmt(v):
            if isinstance(v, float) and (v != v):
                return "N/A"
            return f"{v:.3f}"
        tbl.add_row(k.upper(), fmt(rv), fmt(fv),
                    fmt(fv - rv) if (isinstance(rv, float) and isinstance(fv, float)
                                     and rv == rv and fv == fv) else "—")
    for k in ("tp", "fp", "fn", "tn"):
        tbl.add_row(k.upper(), str(m_rules[k]), str(m_final[k]), str(m_final[k] - m_rules[k]))
    console.print(tbl)

    console.print(
        f"\n[bold]LLM stage stats[/bold]: fired on {llm_fired}/{n_total} grey-band rows; "
        f"{llm_succeeded} succeeded ({summary['llm_failure_rate'] * 100:.1f}% parse/timeout failure)"
    )
    console.print(f"\n[green]wrote[/green] {args.out}")
    console.print(f"[green]wrote[/green] {args.summary}")
    return 0


def _short_circuited(sigs: list[Signal]) -> bool:
    """Did the rules layer short-circuit safe via allowlist or TWNIC TLD?"""
    short_ids = {"url.allowlist_hit", "url.tw_institutional_tld", "url.user_allowlist_hit"}
    return any(s.id in short_ids for s in sigs)


def _strip_html_text(html: str) -> str:
    """Cheap HTML → text for the LLM. Reuses BS4 because rules.py already
    depends on it transitively."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "lxml")
        return " ".join(soup.get_text(" ", strip=True).split())[:2500]
    except Exception:
        # Strip tags + collapse whitespace as a fallback
        return " ".join(re.sub(r"<[^>]+>", " ", html or "").split())[:2500]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path,
                        default=Path(__file__).parent / "datasets/golden_200.jsonl",
                        help="Matched mixed set. Use phreshphish_subset.jsonl for phish-only.")
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).parent.parent / "extension" / "src" / "data")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_d_results.csv")
    parser.add_argument("--summary", type=Path,
                        default=Path(__file__).parent / "results/tier_d_summary.json")
    parser.add_argument("--backend", choices=["ollama", "none"], default="ollama")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Base URL of the local ollama instance")
    parser.add_argument("--model", default="qwen2.5:0.5b",
                        help="Model tag to call. Mirror of WebLLM Pro Profile (Qwen 2.5-0.5B).")
    parser.add_argument("--limit", type=int, default=0, help="cap rows (0 = all)")
    parser.add_argument("--timeout-s", type=float, default=60.0,
                        help="per-LLM-call timeout")
    args = parser.parse_args()

    if not args.input.exists():
        Console().print(f"[red]missing[/red] {args.input}")
        return 2
    return run(args, Console())


if __name__ == "__main__":
    raise SystemExit(main())
