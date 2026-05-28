# Tier A — first run notes (2026-05-27)

## What ran

- **Dataset**: PhreshPhish test-000 shard, balanced subset (453 phish + 547 benign)
- **Detector**: Python port of extension Stage 1 + Stage 2-lite (no LLM)
- **Throughput**: 1000 rows / 4.9 s = 203 rows/s
- **Output**: `tier_a_results.csv` + `tier_a_summary.json`

## Headline numbers

| Threshold | F1 | Precision | Recall | FPR |
|---|---|---|---|---|
| 5 | **0.454** | 0.667 | 0.344 | 0.143 |
| 10 | 0.418 | 0.675 | 0.302 | 0.121 |
| 15 | 0.207 | 0.644 | 0.124 | 0.057 |
| 25 | 0.103 | 0.758 | 0.055 | 0.015 |
| **50 (cascade "suspicious")** | **0.000** | 0.000 | **0.000** | 0.004 |
| 85 (cascade "dangerous") | 0.000 | 0.000 | 0.000 | 0.000 |

## Interpretation (the most important takeaway)

**Rules-only is structurally insufficient for PhreshPhish.** At the cascade's
production threshold of 50 the rule layer catches **0%** of PhreshPhish phish
samples. The best F1 is 0.454 at threshold 5, but with FPR 14.3% — operationally
unacceptable (every fifteenth legitimate page would be flagged).

**This is exactly the cascade thesis in numbers.** Stage 1 + Stage 2 are not
meant to be a complete detector; they exist to (a) short-circuit obvious safe
or dangerous cases cheaply, (b) raise rule-layer signals into the LLM's
prompt as grounding evidence. The remaining ~95% of phishing samples require
Stage 3 (LLM) — and the LLM lands on a fundamentally different decision
surface (semantic content, brand-vs-domain inconsistency, urgency language).

For the Week 16 report this is the headline figure to compare against
"cascade with Stage 3 LLM" once Tier A is re-run with the offscreen LLM in
the loop (Week 15 work).

## Per-signal precision (top 13)

| Signal | Fires | On phish | On benign | Precision |
|---|---|---|---|---|
| `url.high_entropy_path` | 102 | 46 | 56 | **0.451** ⚠️ |
| `url.tld_medium_risk` | 90 | 86 | 4 | 0.956 ★★★ |
| `url.long` | 73 | 39 | 34 | **0.534** ⚠️ |
| `url.tld_high_risk` | 11 | 11 | 0 | 1.000 ★★★ |
| `url.double_encoded` | 9 | 9 | 0 | 1.000 ★★★ |
| `url.typosquat_brand` | 9 | 2 | 7 | **0.222** ⚠️⚠️ |
| `url.tld_low_risk` | 6 | 6 | 0 | 1.000 ★★★ |
| `url.nonstandard_port` | 5 | 5 | 0 | 1.000 ★★★ |
| `url.path_brand_abuse` | 5 | 1 | 4 | **0.200** ⚠️⚠️ |
| `url.many_subdomains` | 3 | 3 | 0 | 1.000 ★★★ |
| `dom.password_no_tls` | 2 | 2 | 0 | 1.000 ★★★ |
| `url.ip_as_host` | 1 | 1 | 0 | 1.000 ★★★ |
| `url.many_hyphens` | 1 | 1 | 0 | 1.000 ★★★ |

## Weight tuning recommendations (Week 15)

Based on per-signal precision on this dataset:

1. **`url.typosquat_brand` (+40 currently)** — only 22% precision; consider:
   - Lowering weight to +25
   - Adding eTLD+1 character-set heuristic (a typosquat must look LIKE the
     brand label — currently we accept any Levenshtein ≤2 match)
   - Or use PhreshPhish's `target` column as ground truth and recalibrate
2. **`url.path_brand_abuse` (+10)** — 20% precision; arguably noise. Either
   tighten the match (require brand alias near other suspicious tokens) or
   drop the signal entirely.
3. **`url.long` (+6)** and **`url.high_entropy_path` (+10)** — mediocre
   precision, low weight, leave as soft signals.
4. **Keep `tld_*_risk` exactly as is** — 95–100% precision, the strongest
   structural signals.

## Why DOM signals barely fire

PhreshPhish HTML snapshots are 100–300 KB; even with the 50 KB excerpt we
ship to BS4, many landing-pages are redirect or scrape-time fragments that
do not contain `<form>` / `<input type="password">`. The samples that do
fire `dom.password_no_tls` are clean true positives.

Week 15 idea: use the full HTML column (no excerpt) for DOM analysis. The
50 KB cap was a JSONL-size compromise.

## Caveats

- This is a 1000-row subset of the 168k-row test split. Variance on small
  PhreshPhish slices is meaningful; Tier A should be re-run on the full
  split before any conclusions are written down.
- The detector here is a **Python port** of the extension's TypeScript code
  — there's a drift risk. The Week 15 Tier B run (Playwright loading the
  actual extension) will give us a direct check.
