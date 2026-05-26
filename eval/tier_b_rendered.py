"""Tier B — Playwright-rendered evaluation on 200 golden samples.

Scaffold only. Will launch Chromium with the LocalPhish extension loaded
(via --load-extension=<path-to-dist>), navigate to each URL/HTML snapshot,
and harvest the verdict via the page's chrome.runtime messaging.

Usage:
    uv run python tier_b_rendered.py --extension ../extension/dist
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extension", type=Path, default=Path("../extension/dist"))
    parser.add_argument("--golden", type=Path, default=Path("datasets/golden_200.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("results/tier_b.csv"))
    args = parser.parse_args()
    print(f"[scaffold] tier_b extension={args.extension} golden={args.golden} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
