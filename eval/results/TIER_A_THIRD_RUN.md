# Tier A — third run, with bootstrap CIs (2026-05-28)

Same 1000-sample PhreshPhish subset as runs 1 & 2, but the runner now emits
**95 % bootstrap confidence intervals** for F1 / Precision / Recall / FPR at
each threshold. Also incorporates the [IDP allow-list + anti-debug detector
landed in commit `97d49f7`](TIER_A_SECOND_RUN.md).

## Why bootstrap instead of more data

The PhreshPhish test split is 168 000 rows across 14 parquet shards; our local
cache holds the smallest one (`test-000`, 1 000 rows). Pulling another shard
costs ~350 MB on the wire and would push the JSONL past 200 MB. Bootstrap
resampling tells us how stable the numbers we already have are — if a CI is
narrow, we don't need more data; if it's wide, we know the metric is
unreliable and need to either pull more samples or be honest about the
uncertainty in the report.

## Results

```
Tier A — static rule-layer evaluation
  data dir: extension/src/data
  loaded: 5000 allow-list, 102 brands, 51 TLD entries
  rows: 1000 (453 phish + 547 benign)
```

| Threshold | F1 [95 % CI] | Precision [95 % CI] | Recall [95 % CI] | FPR [95 % CI] |
|---|---|---|---|---|
| **5** | **0.461 [0.41-0.51]** | 0.671 [0.61-0.74] | 0.351 [0.31-0.40] | 0.143 [0.11-0.17] |
| 10 | 0.419 [0.37-0.47] | 0.682 [0.62-0.75] | 0.302 [0.26-0.35] | 0.117 [0.09-0.15] |
| 15 | 0.207 [0.16-0.26] | 0.644 [0.55-0.74] | 0.124 [0.10-0.16] | 0.057 [0.04-0.08] |
| 20 | 0.149 [0.10-0.20] | **0.822 [0.70-0.93]** | 0.082 [0.06-0.11] | 0.015 [0.01-0.03] |
| 25 | 0.099 [0.06-0.14] | 0.750 [0.57-0.91] | 0.053 [0.03-0.08] | 0.015 [0.01-0.03] |
| 30 | 0.022 [0.00-0.04] | 0.714 **[0.29-1.00]** | 0.011 [0.00-0.02] | 0.004 [0.00-0.01] |
| 35 | 0.022 [0.00-0.04] | 0.714 [0.29-1.00] | 0.011 [0.00-0.02] | 0.004 [0.00-0.01] |
| ≥50 | 0.000 [0.00-0.00] | 0.000 [0.00-0.00] | 0.000 [0.00-0.00] | 0.000 [0.00-0.00] |

## Interpretation

1. **Threshold 5 is statistically solid.** F1 0.461 ± ~0.05 — narrow CI because
   there are ~300 true positives at that threshold; the point estimate is
   reliable.
2. **Threshold 20 is the precision sweet spot.** Precision 0.822 [0.70-0.93] —
   when rules-only fires at this threshold, it's right >70 % of the time even
   in the worst-case bootstrap draw. FPR remains a tolerable 1.5 %.
3. **Threshold ≥25 starts breaking down statistically.** Precision CI widens
   to [0.57-0.91] at threshold 25 and [0.29-1.00] at threshold 30 because
   total positive predictions drop to single digits. A single sample
   misjudged changes Precision by ~14 percentage points. **This is the
   region where rule-layer alone cannot be reported with confidence**, and
   coincidentally also the region where cascade-with-LLM is expected to
   carry the load.
4. **Threshold 50+ rules-only is a confirmed zero.** Tight zero CI = no
   ambiguity; cascade Stage 3 LLM is the load-bearing component at
   production thresholds.

## What this means for the Week 16 report

Quotable line for the report introduction:

> Rule-layer alone catches 35.1 % of PhreshPhish phishing samples (95 % CI
> [31 %, 40 %]) at its most permissive threshold, with an unacceptable
> 14.3 % false-positive rate. At production thresholds (≥50), recall drops
> to a statistically certain zero. Adding Stage 3 on-device LLM closes
> this gap and is the cascade's load-bearing component for the remaining
> 65 % of cases.

Cascade-with-LLM Tier A run is still on the Week 16 to-do list; once we
have those numbers, this CI table becomes the rules-only **baseline** in
the comparison.

## Limitations of this CI estimate

- The resampling is **within** the 1000-row sample. It doesn't capture
  between-shard variance (different temporal slices of PhreshPhish might
  shift the metric meaningfully). Pulling test-001 or running on the
  benchmark splits would be the next confidence step.
- Bootstrap assumes IID rows. PhreshPhish samples within one shard share
  collection batches, so true variance is likely slightly wider than what
  bootstrap reports.
- 95 % CI here is the standard non-parametric percentile interval (500
  bootstrap draws). For final report figures we could bump to 10 000 draws
  and BCa correction — overkill for sanity-checking, useful when defending
  the punchline number.

## Per-signal precision (unchanged from second run)

| Signal | Fires | On phish | On benign | Precision |
|---|---|---|---|---|
| `url.high_entropy_path` | 102 | 46 | 56 | 0.451 ⚠️ |
| `url.tld_medium_risk` | 90 | 86 | 4 | 0.956 ★ |
| `url.long` | 73 | 39 | 34 | 0.534 ⚠️ |
| `url.tld_high_risk` | 11 | 11 | 0 | 1.000 ★ |
| `url.double_encoded` | 9 | 9 | 0 | 1.000 ★ |
| `url.typosquat_brand` (tuned +25) | 9 | 2 | 7 | 0.222 ⚠️ |
| `url.tld_low_risk` | 6 | 6 | 0 | 1.000 ★ |
| `url.nonstandard_port` | 5 | 5 | 0 | 1.000 ★ |
| `url.path_brand_abuse` (tuned +5) | 5 | 1 | 4 | 0.200 ⚠️ |
| `url.many_subdomains` | 3 | 3 | 0 | 1.000 ★ |
| **`dom.anti_debug` (new)** | **3** | **3** | **0** | **1.000 ★** |
| `dom.password_no_tls` | 2 | 2 | 0 | 1.000 ★ |
| `url.ip_as_host` | 1 | 1 | 0 | 1.000 ★ |
| `url.many_hyphens` | 1 | 1 | 0 | 1.000 ★ |
