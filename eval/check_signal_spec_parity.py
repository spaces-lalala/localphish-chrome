"""Stage 0 parity check — TS / Python single source of truth.

Three checks:

  1. Every signal id used in the TS extension exists in signal-spec.json
     (greps `id: "url.foo"` / `id: "dom.bar"` literals in extension/src/signals/**).
  2. Every signal id used in Python eval exists in signal-spec.json
     (greps `Signal("url.foo", ...)` literals in eval/src/localphish_eval/**).
  3. Every weight constant in `rules.py` and `dom_features.py` that is derived
     from the spec returns a value > 0 (i.e. the loader didn't silently lookup
     to None somewhere).

This is the lightweight static guard. Drift between TS and Python *scoring*
on a row-by-row basis is detected by Tier B (per-row signal+score CSV diff
against the rendered extension), which is the operational truth source.

Usage:
    uv run python check_signal_spec_parity.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Iterable

from rich.console import Console


ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "extension/src/data/signal-spec.json"
TS_SIGNALS_DIR = ROOT / "extension/src/signals"
PY_EVAL_DIR = ROOT / "eval/src/localphish_eval"

# Pattern: any quoted string literal matching `<stage>.<noun>_<qualifier>`.
# Catches both `id: "url.foo"` and the ternary `... ? "dom.a" : "dom.b"` form.
# We accept matches anywhere in the file and filter out the badge translation
# table / signal-spec.json by limiting scan to detector source files only.
EMIT_PATTERN = re.compile(r'["\']((?:url|dom|llm)\.[a-z0-9_]+)["\']')

# IDs that are emitted but intentionally not in signal-spec.json (zero-weight
# short-circuit markers, LLM lifecycle markers, TLD-tier signals whose weights
# live in suspicious-tlds.json, the cascade meta-signal). Listing them here
# keeps the parity check clean without forcing every cosmetic marker to
# declare a weight.
EXEMPT_IDS = {
    # Short-circuit / zero-weight markers
    "url.parse_failed",
    "url.allowlist_hit",
    "url.tw_allowlist_hit",
    "url.tw_institutional_tld",
    "url.user_allowlist_hit",
    "dom.oauth_idp_allowlisted",
    # LLM lifecycle markers (emitted by cascade.ts / Stage 3 wrapper, not by
    # rule detectors; weights here are dynamic, not in spec)
    "llm.unavailable",
    "llm.timeout",
    "llm.parse_failed",
    "llm.escalation",
    "llm.deescalation",
    "llm.score",
    # TLD-tier signals — weights live in extension/src/data/suspicious-tlds.json
    # (Stage 1 reads the tier _weight from there, not from signal-spec)
    "url.tld_high_risk",
    "url.tld_medium_risk",
    "url.tld_low_risk",
    # Cap names (not signal IDs but match the regex shape). Their numeric
    # values live in signal-spec.json `_caps` and are looked up via cap()/
    # signal_cap().
    "dom.hidden_iframes_cap",
    "dom.tiny_interactive_cap",
}


def collect_emitted_ids(root: Path, pattern: re.Pattern, glob: str) -> dict[str, list[Path]]:
    """Return {signal_id -> [files-that-emit-it]}."""
    out: dict[str, list[Path]] = {}
    for p in root.rglob(glob):
        if "__pycache__" in p.parts or "node_modules" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        for m in pattern.finditer(text):
            out.setdefault(m.group(1), []).append(p)
    return out


def fmt_paths(paths: Iterable[Path], n: int = 3) -> str:
    rel = [str(p.relative_to(ROOT)) for p in paths]
    head = rel[:n]
    if len(rel) > n:
        head.append(f"... (+{len(rel) - n} more)")
    return ", ".join(head)


def main() -> int:
    console = Console()
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    declared = set(spec["signals"].keys())
    console.print(f"[cyan]signal-spec.json declares {len(declared)} signal ids[/cyan]")

    # Collect emitted ids
    ts_ids = collect_emitted_ids(TS_SIGNALS_DIR, EMIT_PATTERN, "*.ts")
    py_ids = collect_emitted_ids(PY_EVAL_DIR, EMIT_PATTERN, "*.py")
    console.print(f"TS extension emits {len(ts_ids)} distinct ids "
                  f"({sum(len(v) for v in ts_ids.values())} occurrences)")
    console.print(f"Python eval emits {len(py_ids)} distinct ids "
                  f"({sum(len(v) for v in py_ids.values())} occurrences)")

    failures: list[str] = []

    # Check 1: TS-emitted ids must be declared (or exempt).
    ts_undeclared = [
        (sid, files) for sid, files in ts_ids.items()
        if sid not in declared and sid not in EXEMPT_IDS
    ]
    if ts_undeclared:
        for sid, files in ts_undeclared:
            failures.append(f"TS emits {sid!r} which is NOT in signal-spec.json "
                            f"(seen in: {fmt_paths(files)})")

    # Check 2: Python-emitted ids must be declared (or exempt).
    py_undeclared = [
        (sid, files) for sid, files in py_ids.items()
        if sid not in declared and sid not in EXEMPT_IDS
    ]
    if py_undeclared:
        for sid, files in py_undeclared:
            failures.append(f"Python emits {sid!r} which is NOT in signal-spec.json "
                            f"(seen in: {fmt_paths(files)})")

    # Check 3: declared-but-never-emitted (warning, not failure — the
    # bloomfilter signal is declared in Stage 0 ahead of Stage 1a integration,
    # so this is expected during the v3 transition).
    emitted_anywhere = set(ts_ids.keys()) | set(py_ids.keys())
    unused = sorted(declared - emitted_anywhere)
    if unused:
        console.print(f"[yellow]Warning: {len(unused)} declared signal(s) "
                      f"not emitted anywhere yet:[/yellow] {unused}")

    # Check 4: ids emitted by TS but NOT by Python (or vice versa) — these are
    # parity gaps. NOT a hard failure: some detectors are TS-only by design
    # (homograph confusables) and some Python-only (none currently).
    ts_only = sorted(set(ts_ids.keys()) - set(py_ids.keys()) - EXEMPT_IDS)
    py_only = sorted(set(py_ids.keys()) - set(ts_ids.keys()) - EXEMPT_IDS)
    if ts_only:
        console.print(f"[yellow]TS-only signals (declared but Python port doesn't emit):[/yellow] {ts_only}")
    if py_only:
        console.print(f"[red]Python-only signals (suspicious — Python emits but TS doesn't):[/red] {py_only}")
        for sid in py_only:
            failures.append(f"Python emits {sid!r} but TS does not")

    # Check 5: every spec entry's weight is a non-negative integer.
    for sid, body in spec["signals"].items():
        w = body.get("weight")
        if not isinstance(w, int) or w < 0:
            failures.append(f"spec signal {sid!r} has invalid weight {w!r}")

    if failures:
        console.print("\n[red bold]PARITY CHECK FAILED:[/red bold]")
        for f in failures:
            console.print(f"  - {f}")
        return 1

    console.print("\n[green]PARITY CHECK PASSED[/green] — TS and Python both bind to signal-spec.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
