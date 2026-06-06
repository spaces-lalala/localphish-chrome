"""Tier D supplementary — LLM false-positive rate on hard benign fixtures.

Closes the gap in §6.4 / §10.10: in the main Tier D run on golden_200,
all 18 LLM-fired rows were phish (Tranco + TWNIC short-circuit caught all
69 benigns at Stage 1), so the LLM never saw a benign and "FPR = 0%" is
rules-credit not LLM-credit.

This script forces the LLM stage on hand-crafted "hard benign" fixtures
that LOOK structurally phishing-ish (password + OTP + cross-eTLD+1 form
actions, urgency-free copy) but are legitimate. Measures whether Qwen 2.5
-0.5B has a real benign-FPR problem on this attack surface.

Usage:
    # Ollama serve + qwen2.5:0.5b pulled
    uv run python tier_d_benign_fpr.py
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from localphish_eval.rules import load_rule_data
from tier_d_python_llm import (
    build_user_prompt,
    cascade_score,
    llm_run_ollama,
    verdict_from_score,
    _short_circuited,
    _strip_html_text,
)


BENIGN_FIXTURES = [
    ("cathaybk-legit-login.html",
     "https://www.cathaybk.com.tw/personal/login",
     "Cathay United Bank login (TW)"),
    ("google-oauth-consent.html",
     "https://accounts.google.com/o/oauth2/v2/auth/consent?client_id=EXAMPLE",
     "Google OAuth consent screen"),
    ("github-2fa-login.html",
     "https://github.com/sessions/two-factor",
     "GitHub 2FA verification"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures-dir", type=Path,
                        default=Path(__file__).parent.parent / "test" / "fixtures" / "benign")
    parser.add_argument("--data-dir", type=Path,
                        default=Path(__file__).parent.parent / "extension" / "src" / "data")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results/tier_d_benign_fpr.json")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5:0.5b")
    parser.add_argument("--timeout-s", type=float, default=60.0)
    args = parser.parse_args()
    console = Console()

    data = load_rule_data(args.data_dir)
    results: list[dict] = []

    console.print("[cyan]Tier D supplementary — LLM benign FPR on hard fixtures[/cyan]")
    console.print("Forcing LLM call regardless of cascade grey-band gating.\n")

    for fname, url, label in BENIGN_FIXTURES:
        html = (args.fixtures_dir / fname).read_text(encoding="utf-8")
        rules_score, sigs = cascade_score(url, html, data, args.data_dir)
        short = _short_circuited(sigs)

        # Force LLM call even when rules already short-circuit
        text = _strip_html_text(html)
        from urllib.parse import urlparse
        import tldextract
        etld1 = ""
        try:
            host = urlparse(url).hostname or ""
            ext = tldextract.extract(host)
            if ext.domain and ext.suffix:
                etld1 = f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass

        prompt = build_user_prompt(url, etld1, "", text, sigs)
        out = llm_run_ollama(args.model, args.ollama_url, prompt, args.timeout_s)
        llm_score = None
        llm_verdict = None
        if out and isinstance(out.get("risk_score"), (int, float)):
            llm_score = int(out["risk_score"])
            llm_verdict = str(out.get("verdict", ""))

        # Cascade-with-LLM final: in real deployment, short-circuit short-circuits.
        # Here we report BOTH "what cascade would do" and "what LLM said in isolation".
        if short:
            cascade_final_score = rules_score  # short-circuit kept it at rules_score
        else:
            cascade_final_score = max(rules_score, llm_score or 0)

        is_llm_fp = llm_score is not None and llm_score >= 50
        is_cascade_fp = cascade_final_score >= 50

        results.append({
            "fixture": fname,
            "label": label,
            "url": url,
            "rules_score": rules_score,
            "short_circuited": short,
            "llm_score": llm_score,
            "llm_verdict": llm_verdict,
            "cascade_final_score": cascade_final_score,
            "llm_alone_false_positive": is_llm_fp,
            "cascade_false_positive": is_cascade_fp,
        })

        console.print(
            f"  [bold]{label}[/bold]\n"
            f"    rules={rules_score} (short={short}) | "
            f"llm={llm_score}/{llm_verdict} | "
            f"cascade-final={cascade_final_score}"
        )

    # Aggregate
    n = len(results)
    n_llm_fp = sum(1 for r in results if r["llm_alone_false_positive"])
    n_cascade_fp = sum(1 for r in results if r["cascade_false_positive"])

    tbl = Table(title=f"Tier D benign-FPR mini-eval (n={n})")
    tbl.add_column("metric"); tbl.add_column("count"); tbl.add_column("pct")
    tbl.add_row("LLM-alone false positive (llm_score >= 50)", str(n_llm_fp),
                f"{n_llm_fp / n * 100:.0f}%")
    tbl.add_row("Cascade-with-LLM false positive (final >= 50)", str(n_cascade_fp),
                f"{n_cascade_fp / n * 100:.0f}%")
    console.print(tbl)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"\n[green]wrote[/green] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
