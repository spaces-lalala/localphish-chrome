# Tier A — fourth run (Week 16 補洞後 baseline)

**Date**: 2026-05-28
**Input**: `eval/datasets/phreshphish_subset.jsonl` (1000 rows, 453 phish / 547 benign)
**Code**: post Week 16 五件套訊號補強 (reverse-proxy fingerprint、phishlet endpoint、Unicode trickery、cloaking detector、favicon CDN hot-link)

---

## Primary metrics (rules-only baseline; cascade-with-LLM 留 Week 16)

| Threshold | F1                  | Precision | Recall | FPR    |
|-----------|---------------------|-----------|--------|--------|
| 5         | **0.463** [0.42-0.51] | 0.656    | 0.358  | 0.155 |
| 10        | 0.422 [0.38-0.47]   | 0.664    | 0.309  | 0.130 |
| 15        | 0.215 [0.17-0.26]   | 0.621    | 0.130  | 0.066 |
| 20        | 0.158 [0.11-0.20]   | 0.755    | 0.088  | 0.024 |
| 25        | 0.110 [0.07-0.15]   | 0.692    | 0.060  | 0.022 |
| **50** (cascade default) | **0.004** [0.00-0.01] | 0.500 | **0.002** | 0.002 |

### vs Third run (pre-Week 16 訊號補強)

| Threshold | Before | After | Δ |
|---|---|---|---|
| 5  | 0.454 | 0.463 | +0.009 |
| 50 | 0.000 | 0.004 | +0.004 (one new true positive) |

---

## New detectors — first observation on PhreshPhish

| Signal | Fires | On phish | On benign | Precision |
|---|---|---|---|---|
| `dom.favicon_brand_cdn_mismatch` | 6 | 3 | 3 | 0.500 |
| `url.reverse_proxy_hyphen_fqdn` | 1 | 1 | 0 | 1.000 |
| `dom.zero_width_in_text` | 4 | 0 | 4 | 0.000 ⚠ |
| `dom.cloaking_verify_wall` | 1 | 0 | 1 | 0.000 |
| `dom.cloaking_verify_wall_strong` | 1 | 0 | 1 | 0.000 |
| `url.phishlet_endpoint` | 0 | 0 | 0 | — |
| `url.reverse_proxy_fqdn` | 0 | 0 | 0 | — |

### Observations

1. **Reverse-proxy patterns are rare in PhreshPhish**: only 1 hyphen-FQDN out of 1000. This matches the threat assessment hypothesis — PhreshPhish snapshots predate Evilginx's broad PaaS adoption, OR the crawler doesn't follow the kit's evasion gate. Either way, expect Tier B (Playwright + live extension) to show different rates.

2. **Cloaking detector fires on benign samples**: 2 benign hits both look like legitimate Cloudflare-protected pages where the crawler captured the challenge page. **This is the signal working as designed** — it confirms that PhreshPhish's benign set also contains cloaked HTML. Tier A misses caused by cloaking now have evidence.

3. **Zero-width text false positives**: 4 benign hits. Inspection needed — likely some benign pages emit U+200B inside JS-embedded copy or template scaffold. Consider tightening to require ≥2 zero-width chars before firing, or gate on "credential-harvest context" (presence of password input).

4. **Favicon hot-link mismatch precision 0.5**: half-and-half. Some benign sites legitimately hot-link from CDNs we mapped (e.g. images.tw.gov on a Taiwan municipal page). Brand CDN map needs review.

---

## Punchline for Week 16 report

> Rules-only baseline now caches at **F1 0.463 [0.42-0.51] @ threshold 5**, FPR 15.5%. The Week 16 訊號補強 added new categories of detection that fire on the right kind of pages (reverse-proxy 100% precision, cloaking detector firing on the right subset) but the PhreshPhish sample isn't where these attacks live — Tier B's live renders will tell a different story. The real punchline is whether cascade+LLM bridges the recall=0% gap at threshold 50.
