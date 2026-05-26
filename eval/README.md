# LocalPhish — Evaluation Suite

Tier A (static BS4) and Tier B (Playwright-rendered) evaluation pipelines.

## Setup (uv)

```bash
cd eval
uv sync                  # install runtime deps from pyproject.toml
uv sync --extra dev      # add dev tools (ruff/pytest/mypy)
uv sync --extra brand-db # add torch/open-clip for brand-DB build (heavy)
```

Tier B needs Playwright browsers:

```bash
uv run playwright install chromium
```

## Run

```bash
uv run python tier_a_static.py --backend rules-only
uv run python tier_b_rendered.py --extension ../extension/dist
```

Both scripts are scaffolds today; signal extractors and metric reporting arrive in Week 14/15.
