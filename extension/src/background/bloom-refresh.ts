// Daily refresh of the 165 反詐騙 bloom-filter blob.
//
// Privacy invariant (Stage 0 hard rule): this is a single batch download of
// ONE static blob URL — never a per-page lookup. The fetched blob is binary-
// identical for every user, so the only information leaked to the origin is
// "this extension is installed". (We do not even know which user, the
// extension carries no identifier in the request.)
//
// We DO NOT fetch directly from data.gov.tw at runtime — that endpoint
// returns the raw CSV which we'd have to re-parse + rebuild bloom every
// time. Instead we ship + refresh the pre-built blob from the project's
// own static-asset URL (set REFRESH_URL below; in a real deployment this is
// a GitHub Pages mirror updated by CI). Until that pipeline is published,
// the refresh job no-ops gracefully (URL = null → skip).
//
// On a successful refresh:
//   - blob is stored to chrome.storage.local
//   - bloom.ts is told to swap to the refreshed filter via setRuntimeBloom()
//
// On boot the SW reads chrome.storage.local first and installs the refreshed
// blob if present, so the bloom check uses the freshest available data
// without ever needing a network call at lookup time.

import type { BloomSpec } from "@/signals/bloom";
import { setRuntimeBloom } from "@/signals/bloom";

/** Set this to a CDN URL that mirrors the bloom blob built by
 *  `eval/build_bloom_filter.py`. Leaving it null means daily refresh
 *  no-ops (extension keeps using the bundled blob). For the course
 *  submission we keep null — refresh requires a published mirror, which
 *  is post-submission infrastructure. */
const REFRESH_URL: string | null = null;

const ALARM_NAME = "lp-bloom-refresh";
const STORAGE_KEY = "lp.bloom.runtime";
/** Approx 24 h. Chrome may delay alarms when the browser is closed; we
 *  don't care — even a 48 h-stale filter is dramatically better than no
 *  filter at all because the 165 feed itself updates 不定期 (months
 *  between revisions in practice). */
const PERIOD_MINUTES = 60 * 24;

interface StoredBloom {
  fetchedAt: number;
  spec: BloomSpec;
}

export function installBloomRefresh(): void {
  // Restore any previously-cached runtime blob immediately on SW boot.
  void (async () => {
    const cached = await readCachedBloom();
    if (cached) {
      try {
        setRuntimeBloom(cached.spec);
        console.log(
          `[LocalPhish bloom] restored runtime blob (n=${cached.spec.n_inserted}, m=${cached.spec.m_bits}b, fetched=${new Date(cached.fetchedAt).toISOString()})`
        );
      } catch (e) {
        console.warn(`[LocalPhish bloom] cached blob invalid, ignoring: ${(e as Error).message}`);
      }
    }
  })();

  // Schedule the daily refresh alarm. Chrome dedupes by name so re-creating
  // it on every SW restart is safe.
  chrome.alarms.create(ALARM_NAME, {
    periodInMinutes: PERIOD_MINUTES,
    // delayInMinutes lets us attempt one refresh ~30 s after SW boot so a
    // fresh-install user gets the latest blob without waiting a full day.
    delayInMinutes: 0.5,
  });

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name !== ALARM_NAME) return;
    void refresh();
  });
}

async function readCachedBloom(): Promise<StoredBloom | null> {
  try {
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const raw = got?.[STORAGE_KEY];
    if (!raw || typeof raw !== "object") return null;
    return raw as StoredBloom;
  } catch {
    return null;
  }
}

async function writeCachedBloom(spec: BloomSpec): Promise<void> {
  const entry: StoredBloom = { fetchedAt: Date.now(), spec };
  await chrome.storage.local.set({ [STORAGE_KEY]: entry });
}

async function refresh(): Promise<void> {
  if (!REFRESH_URL) {
    // No mirror configured — silently skip. The bundled blob still works.
    return;
  }
  try {
    const resp = await fetch(REFRESH_URL, { credentials: "omit", cache: "no-cache" });
    if (!resp.ok) {
      console.warn(`[LocalPhish bloom] refresh HTTP ${resp.status}`);
      return;
    }
    const spec = (await resp.json()) as BloomSpec;
    // Defensive: only accept if shape looks valid. Avoids storing a broken
    // blob that would crash bloom.ts on next decode.
    if (
      typeof spec.m_bits !== "number" ||
      typeof spec.k_hashes !== "number" ||
      typeof spec.bits_b64 !== "string" ||
      typeof spec.hash_family !== "string"
    ) {
      console.warn("[LocalPhish bloom] refresh: malformed spec, ignoring");
      return;
    }
    setRuntimeBloom(spec);
    await writeCachedBloom(spec);
    console.log(
      `[LocalPhish bloom] refreshed (n=${spec.n_inserted}, m=${spec.m_bits}b, emp_fpr=${spec.empirical_fpr})`
    );
  } catch (e) {
    console.warn(`[LocalPhish bloom] refresh failed: ${(e as Error).message}`);
  }
}
