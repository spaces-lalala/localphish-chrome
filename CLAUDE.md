# CLAUDE.md — LocalPhish working memory

This file is auto-loaded by Claude Code at the start of every session. Read
it before making any changes. Keep it tight; it's a working brief, not a
manual. Update it when a non-obvious decision or gotcha is added to the
codebase.

---

## Project

**LocalPhish** — a Chrome extension that scores any page for phishing risk
**entirely on-device**. No URL, no DOM, no page content leaves the browser.
The product runs a 4-stage cascade (cheap rules → DOM → local LLM → vision)
so the LLM only fires on ambiguous pages, keeping per-page latency tractable.

Primary differentiator: privacy-first + Taiwan-localized. Most commercial
phishing blockers rely on cloud blacklists and are tuned for English-world
brands. We catch 中華郵政 / 健保署 / 國稅局 / ETC impersonation with the
same fluency as PayPal / Microsoft 365.

---

## Repo layout

```
Final/                             ← repo root (independent git repo)
├── extension/                     Chrome MV3 extension (TypeScript + Vite + @crxjs + Preact)
│   ├── src/
│   │   ├── background/index.ts    Service worker: RPC router, verdict cache, webNavigation
│   │   ├── content/               Content scripts (ISOLATED world)
│   │   │   ├── index.ts           Entry: extract features → SW → render badge
│   │   │   ├── dom-extract.ts     DOM scanner (forms, iframes, anti-debug)
│   │   │   └── badge.ts           Shadow DOM in-page badge UI
│   │   ├── offscreen/             Offscreen document — holds the LLM session
│   │   ├── popup/                 Preact popup with ANALYZING loading state
│   │   ├── options/               URL Tester page (12 preset URLs)
│   │   ├── signals/               All cascade detectors
│   │   │   ├── stage1.ts          Stage 1 orchestrator (URL rules)
│   │   │   ├── stage2.ts          Stage 2 orchestrator (DOM)
│   │   │   ├── cascade.ts         Full pipeline (async, integrates Stage 3 RPC)
│   │   │   ├── url-features.ts    IP-as-host, @-sign, port, length, entropy, ...
│   │   │   ├── homograph.ts       Punycode decoder + brand lookalike + mixed-script
│   │   │   ├── typosquat.ts       Levenshtein + subdomain/path brand abuse
│   │   │   ├── suspicious-tld.ts  3-tier TLD risk table
│   │   │   ├── fake-gov-tw.ts     Taiwan 偽政府網域 detector
│   │   │   ├── cross-strait-language.ts  Mainland-Chinese-on-TW-page detector
│   │   │   ├── allowlist.ts       Tranco short-circuit
│   │   │   ├── levenshtein.ts     DP, O(min m,n) space
│   │   │   └── parse-url.ts       tldts wrapper
│   │   ├── llm/
│   │   │   ├── backend.ts         LLMBackendImpl interface (Nano / WebLLM common)
│   │   │   ├── nano.ts            Chrome built-in Prompt API wrapper (defensive)
│   │   │   └── router.ts          Backend selection + retry + JSON repair fallback
│   │   ├── prompts/
│   │   │   ├── phishing_v1_nano.ts        v1 English baseline (kept for A/B)
│   │   │   ├── phishing_v2_tw_nano.ts     v2 Taiwan-localized (active)
│   │   │   └── schema.ts                  Zod schema + extractJsonObject + repairTruncatedJson
│   │   └── data/                  Reference JSONs (Tranco, brands, TLDs, IDP allow-list)
│   ├── manifest.config.ts         @crxjs declarative manifest
│   ├── vite.config.ts             Vite + crx plugin + preact preset
│   └── tsconfig.json
│
├── eval/                          Python evaluation suite (uv-managed)
│   ├── src/localphish_eval/
│   │   ├── rules.py               Python port of Stage 1 detectors (weights mirror TS)
│   │   └── dom_features.py        BS4 port of Stage 2 detectors
│   ├── tier_a_static.py           Tier A runner with bootstrap CI
│   ├── tier_b_rendered.py         Tier B (Playwright + real extension) — scaffold only
│   ├── fetch_tranco.py            tranco-list.eu API client
│   ├── fetch_phreshphish.py       HuggingFace parquet sampler
│   ├── fetch_165_articles.py      165.npa.gov.tw JSON API client (polite)
│   ├── datasets/                  Fetched data (mostly gitignored)
│   └── results/                   Tier A run reports + tier_a_summary.json
│
├── test/
│   ├── fixtures/                  Fake phishing HTML for local end-to-end tests
│   │   ├── microsoft-365-login-fake.html
│   │   ├── paypal-verify-fake.html
│   │   ├── crypto-wallet-connect-fake.html
│   │   └── tw/                    Taiwan-localized fixtures
│   │       ├── post-customs-fake.html         (中華郵政 包裹補繳關稅)
│   │       ├── ntbsa-tax-refund-fake.html     (財政部國稅局 退稅)
│   │       └── etc-overdue-fake.html          (遠通電收 ETC 催繳)
│   └── serve.py                   Stdlib http.server at :8765
│
└── docs/                          Reports + design notes (mostly gitignored)
```

---

## Build & run

```bash
# Extension
cd extension
npm install
npm run build           # emits dist/, also runs tsc --noEmit
npm run dev             # Vite + HMR (@crxjs reloads on save)
npm run typecheck       # tsc only

# Reload at chrome://extensions after every build; SW + content scripts both need it
# Content script changes also require F5 on the affected tabs

# Evaluation (Python via uv)
cd eval
uv sync                 # install deps from pyproject.toml
uv run python tier_a_static.py            # rules-only Tier A on PhreshPhish 1000 subset
uv run python fetch_tranco.py --top 5000  # refresh Tranco allow-list
uv run python fetch_phreshphish.py        # 1000 samples balanced
uv run python fetch_165_articles.py       # 74 TW scam articles (titles)

# Local fixture server (for testing the actual extension end-to-end)
cd test
python serve.py         # http://localhost:8765/
# stdlib only — no uv needed
```

Build artifacts:
- `extension/dist/` — loadable unpacked at chrome://extensions
- `eval/results/tier_a_results.csv` — per-row classifications (gitignored)
- `eval/results/tier_a_summary.json` — metrics with bootstrap CI
- `eval/results/TIER_A_*_RUN.md` — human-readable analyses

---

## Architecture — the cascade

Plan §3. Read this if you're changing any signal or LLM logic.

```
content script (extracts) → SW (Stage 1+2 + cascade orchestrator) → Offscreen (LLM)

Stage 0: page DOMContentLoaded / SPA route change
Stage 1: URL rules (~5 ms, pure JS in SW)
         allowlist hit              → short-circuit SAFE
         raw_score ≥ 85             → short-circuit DANGEROUS
         else                       → continue to Stage 2
Stage 2: DOM features (~5 ms in SW on extracted features from content script)
         compute total = stage1 + stage2
Stage 3: local LLM (~3–25 s, in offscreen)
         only fires when 15 ≤ total ≤ 84 (the "grey band")
         Nano (Lite) / WebLLM (Pro, Week 16) per profile
         strict JSON output; retry once; repairTruncatedJson() fallback
         final = max(rules_score, llm_score)   ← LLM can escalate, never de-escalate
Stage 4: vision (Week 16: CLIP logo retrieval + optional Moondream VLM)
         only when need_visual=true from Stage 3, or ambiguous high score
```

**Why MAX**: rules give "hard evidence", LLM gives "language understanding".
If rules say 80 dangerous but LLM says 10 safe, we keep 80 — LLM may be
fooled, rules cannot be "fooled" into firing without structural evidence.

**Per-tab verdict cache** lives in the SW (`tabVerdicts: Map<number, ClassifyResult>`).
Wiped on `tabs.onRemoved` and `tabs.onUpdated.url`. Popup polls this cache
for up to 28 s before falling back to a synthetic URL-only classify.

---

## Critical gotchas

These have all bitten us. Don't re-learn them.

1. **Chrome Prompt API requires language attestation in three places**:
   `LanguageModel.availability(opts)`, `LanguageModel.create(opts)`, AND
   `session.prompt(text, opts)`. M148 added the requirement to
   `availability()` last; if you forget one, you get a runtime error
   `"No output language was specified in a LanguageModel API request"`.
   Supported codes: `en | es | ja` only. See `extension/src/llm/nano.ts`.

2. **Nano truncates output at an internal token cap we can't configure**.
   `extension/src/prompts/schema.ts:repairTruncatedJson()` tolerantly closes
   open braces/brackets/strings to recover the verdict + category from
   truncated JSON. `reasons[]` is `optional()` in the Zod schema for the
   same reason — Nano may truncate inside the category array before reaching
   reasons.

3. **Prompt v2 (台灣化) MUST demand English-only output**. The system
   prompt allowing 繁中 in `reasons[]` causes Nano to attempt Chinese
   output, conflict with `outputLanguage:"en"` attestation, and fail
   the prompt() call. See `phishing_v2_tw_nano.ts`.

4. **Stage 1 short-circuit safe at score < 15 is WRONG** — a low URL
   score does not mean the page is safe. Only allow-list hits short-circuit
   safe; everything else continues to Stage 2. The old behaviour silently
   skipped DOM analysis on localhost fixtures with only a non-standard
   port signal. See cascade flow in `stage1.ts`.

5. **localhost has no eTLD+1** so `dom.password_cross_etld1_post` and
   relatives don't fire on the local fixture server. Real-world phishing
   always lives on a public eTLD+1 so this is by design. If you write
   new fixtures and they don't trigger the expected signal, check
   whether you depend on a cross-eTLD+1 calculation.

6. **PhreshPhish HTML excerpts**: the parquet `html` column is several
   hundred KB per row, the first 4 KB is almost always inside `<head>`.
   `fetch_phreshphish.py` slices the first 50 KB to give BS4 a chance
   at the body's first form. JSONL grows from 4 MB → 38 MB at this
   setting; gitignored.

7. **Markdown tables**: use ASCII `|`, not the full-width `｜` (U+FF5C).
   wkhtmltopdf silently fails to render full-width pipes as a table
   and the row collapses into a single mashed paragraph.

8. **Badge UI in Shadow DOM**: attach the host to `document.documentElement`,
   not `document.body`. SPA frameworks routinely rewrite body during
   hydration and would orphan the badge.

9. **Content script does NOT have access to MAIN-world scripts'
   `document.oncontextmenu` overrides** because content scripts run in
   ISOLATED world. We can only detect inline `<body oncontextmenu="return false">`
   and inline `<script>` patterns. This is a known coverage gap for
   anti-debug detection.

10. **`@crxjs/vite-plugin` version**: must pin to `^2.4.0` (stable).
    Earlier beta versions don't exist on npm despite some docs referencing
    `2.0.0-beta.34` (ENOENT on install).

---

## Code conventions

**TypeScript**:
- Strict mode on. `noUnusedLocals` and `noUnusedParameters`.
- Path alias `@/*` → `extension/src/*` (in `tsconfig.json` + `vite.config.ts`).
- Signal IDs follow `<stage>.<noun>_<qualifier>` e.g. `url.typosquat_brand`,
  `dom.password_no_tls`. New detectors should match this pattern so the
  badge UI grouping continues to work.
- Cascade weights are constants at module top. **When changing a weight
  in TS, change the matching constant in `eval/src/localphish_eval/rules.py`
  in the same commit** — Tier A is a faithful port and drift makes the
  baseline number meaningless.

**Python**:
- `uv` only. Don't use `pip` directly.
- `polars` for parquet (PhreshPhish), `pandas` available but rarely needed.
- Type hints required on public functions (`uv run python -m mypy` — not
  wired into CI yet but the code is mypy-clean).

**Data files** (`extension/src/data/`):
- Each JSON has a leading `"_comment"` field documenting source + scope.
- `tranco-sample.json` is regenerated by `eval/fetch_tranco.py` (default
  top 5000). Commit the JSON so `npm run build` works on clone.
- `brand-list.json` is hand-curated (102 entries, 46 Taiwan). Each entry
  has `name`, `domain` (canonical eTLD+1), `aliases[]` (lowercased + 繁中).

---

## Style preferences

**Output language**: Traditional Chinese with English technical terms
embedded. Match the codebase's bilingual register.

**No AI clichés**: avoid「核心」「優雅降級」「端到端」「直接落地」
「核心痛點」「正解是」. Write like an over-caffeinated CS senior
debugging at 2 AM, not like a product launch slide.

**Comments**: default to no comments. Only add a comment when the WHY is
non-obvious — a hidden constraint, a workaround for a specific bug, an
invariant that would surprise a reader. Don't describe WHAT well-named
identifiers already say.

**Commit messages**: imperative, no emoji, no Co-Authored-By unless the
human asks. Body should explain the WHY and reference the empirical
evidence that motivated the change (e.g. Tier A precision number,
fixture failure mode).

**No emojis in source files or commit messages** unless the user explicitly
asks.

---

## Testing workflow with the user

The user is the test pilot. They have:
- Chrome 148 with Gemini Nano enabled (`chrome://flags` set up, model
  downloaded, working)
- Windows 11, RTX 4050 6 GB, WebGPU present
- Patience for reloading + F5'ing fixtures

When you want them to test, give a tight checklist:

1. `chrome://extensions` → LocalPhish → 🔄 Reload
2. (Optional) `cd test && python serve.py` for fixture server
3. Specific URLs to visit
4. What to look for (verdict, score, stages line, specific signals)

Ask only the questions whose answers you can't infer from build output.
Don't make them screenshot the obvious. If something fails, you usually
want the raw error from offscreen console (`chrome://extensions` → LocalPhish
→ Service Worker → "Inspect views: offscreen.html" → Console).

> **Personal context note**: there is a `CLAUDE.md.local` next to this file
> (gitignored) with the user's working-on-this-project context — submission
> timelines, strategy notes, plan-file location. Read it if it exists; it
> won't be present in a fresh clone of the open-source repo.

---

## Git workflow

- This repo is independent (`Final/.git`). It is NOT inside the user's
  cross-course monorepo at `D:\Documents\NCCUCP_D`. Don't add anything
  to the parent repo by accident.
- Main branch: `main`. No remote configured by default — don't push
  unless the user explicitly asks.
- Coursework files (`Project_handout.md`, `week12*.md`, `docs/week14_individual.md`,
  `docs/week15_individual.md`, `docs/*.pdf`, etc.) are gitignored. The
  user keeps them locally; don't `git add -f` them.
- Large data files (`eval/datasets/phreshphish_subset.jsonl`,
  `eval/datasets/cache/`, `eval/results/*.csv`,
  `extension/src/data/tranco-top-100k.json`) are gitignored. Smaller
  bundles (`extension/src/data/tranco-sample.json` ~5000 entries) ARE
  committed so `npm run build` works on a fresh clone.
- Commits should be small and topical; the project ships ~15 feature
  commits across a few sessions. Avoid mega-commits that touch unrelated
  files.

---

## Current state pointer

Last commit (at time of writing this file): `0fa2485 fix(stage3): make reasons[] optional…`

Six fixtures all classify as DANGEROUS via the full cascade including
Stage 3 LLM (Gemini Nano). Tier A rules-only baseline on PhreshPhish 1000
subset: F1 0.461 [0.41–0.51] at threshold 5; recall 0 % at production
threshold 50 (cascade-with-LLM Tier A run is on the TODO list).

For the up-to-date list of what's done vs not done, run:
```bash
git log --oneline | head -20
```
and read `docs/week15_individual.md` if it's present locally.
