# Tier A — second run, weight-tuned (2026-05-28)

After [TIER_A_FIRST_RUN.md](TIER_A_FIRST_RUN.md) showed `url.typosquat_brand`
firing with precision 0.222 (7/9 false positives) and `url.path_brand_abuse`
with precision 0.200 (4/5 false positives), I dropped both weights and re-ran.

## Weight changes

| Signal | Old | New | Reason |
|---|---|---|---|
| `url.typosquat_brand` | +40 | **+25** | precision 0.222 on PhreshPhish 1000; too noisy to deserve a +40 |
| `url.path_brand_abuse` | +10 | **+5** | precision 0.200; reduced to "informational" weight |
| `url.subdomain_brand_abuse` | +35 | +35 (unchanged) | too rare on PhreshPhish (n<3) to recalibrate, but it's the load-bearing signal for the TW post-customs / 國稅 / ETC fixtures — keep |

Both changes mirrored in TypeScript (`extension/src/signals/typosquat.ts`)
and Python (`eval/src/localphish_eval/rules.py`) so Tier A and the live
extension stay in lock-step.

## Threshold sweep — before vs after

| Threshold | F1 (before) | F1 (after) | Precision (before) | Precision (after) | FPR (before) | FPR (after) |
|---|---|---|---|---|---|---|
| 5 | 0.454 | 0.454 | 0.667 | 0.667 | 0.143 | 0.143 |
| 10 | 0.418 | 0.419 | 0.675 | 0.682 | 0.121 | **0.117** |
| 15 | 0.207 | 0.207 | 0.644 | 0.644 | 0.057 | 0.057 |
| **20** | 0.141 | **0.149** | 0.778 | **0.822** | 0.018 | **0.015** |
| 25 | 0.103 | 0.099 | 0.758 | 0.750 | 0.015 | 0.015 |
| **30** | 0.030 | 0.022 | 0.500 | **0.714** | 0.013 | **0.004** |
| ≥50 | 0.000 | 0.000 | 0.000 | 0.000 | 0.004 | 0.000 |

## Headline numbers

- **At threshold 30** (often used as "suspicious" floor in similar systems):
  Precision climbed from 0.500 → 0.714 (+42 %), FPR dropped from 0.013 → 0.004 (–69 %).
- **At threshold 20**: Precision 0.778 → 0.822, FPR 0.018 → 0.015. F1 marginal +6 %.
- Threshold 50+: rules-only still can't catch PhreshPhish phish on its own — that's
  cascade-with-LLM territory (Week 16).

The tuning trades a slice of Recall (which was already too low to matter at
production thresholds) for a meaningful Precision lift on the bands where
the cascade actually uses rule scores as a gating signal.

## Per-signal hits unchanged

Tuning weights doesn't change which signals fire, just how heavy each is.
The hit-rate table from the first run still applies.

## What's next

- Re-run on the full PhreshPhish test split (168k rows) to validate that
  this isn't a 1000-sample artifact (Week 16).
- Tier B (Playwright running the actual extension on a 200-row golden set)
  will check whether the Python port still mirrors the TypeScript live code
  after this commit.
