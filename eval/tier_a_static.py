"""Tier A — static evaluation on PhreshPhish + Tranco samples.

Scaffold only. Will load saved HTML snapshots, run URL + DOM signal extractors
in Python, and emit F1/Precision/Recall/FPR.

Usage:
    uv run python tier_a_static.py --backend rules-only
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["webllm", "nano", "rules-only"], default="rules-only")
    parser.add_argument("--dataset", type=Path, default=Path("datasets"))
    parser.add_argument("--out", type=Path, default=Path("results/tier_a.csv"))
    args = parser.parse_args()
    print(f"[scaffold] tier_a backend={args.backend} dataset={args.dataset} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
