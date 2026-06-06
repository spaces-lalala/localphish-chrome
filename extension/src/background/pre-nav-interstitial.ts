// webNavigation.onBeforeNavigate pre-load interstitial.
//
// Review §10 條 14: the cascade runs at DOMContentLoaded. By that point the
// user can have started typing into a phishing login form. For URLs that
// already look catastrophically bad from URL alone — Stage 1 score ≥
// DANGER_FLOOR, or a 165/警政署 bloom hit — we should intercept BEFORE
// the page even loads.
//
// MV3 service workers cannot synchronously block navigation (the old
// webRequest.onBeforeRequest blocking API is gone in MV3). What we CAN do
// is observe onBeforeNavigate and immediately redirect the tab to an
// interstitial page bundled with the extension. The hostile page hosts
// nothing for the brief moment before redirect, so no credential entry
// window exists.
//
// Privacy invariant: This module reads the navigation URL and runs Stage 1
// (pure URL analysis) in the SW — no network call, no LLM, no DOM. Only
// when Stage 1 alone says "dangerous" do we redirect. Benign pages and
// "needs DOM to judge" pages are not redirected (we let them load normally
// and judge them in the standard cascade).

import { runStage1 } from "@/signals/stage1";
import { DANGER_FLOOR } from "@/signals/thresholds";

// Dedicated full-page warning. Lives at src/interstitial/index.html and is
// registered as a web_accessible_resource in the manifest so chrome.tabs
// .update can navigate to it from any origin.
const INTERSTITIAL_PATH = "src/interstitial/index.html";

interface PendingRedirect {
  tabId: number;
  originalUrl: string;
  rawScore: number;
  firedSignalIds: string[];
}

/** When a redirect just landed at the interstitial we keep the original
 *  URL + signals around so the interstitial UI can show "we blocked
 *  $URL" + "because of X, Y, Z". Cleared once the user dismisses. */
const recentlyBlocked = new Map<number, PendingRedirect>();

export function installPreNavInterstitial(): void {
  // frameId === 0 → main-frame navigation. Sub-frames (iframes, ads) are
  // ignored — we only act on top-level navigations the user actually sees.
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    if (!details.url) return;
    // Don't try to intercept our own interstitial / chrome:// pages.
    if (!/^https?:\/\//i.test(details.url)) return;

    let stage1;
    try {
      stage1 = runStage1(details.url);
    } catch (err) {
      console.warn("[LocalPhish pre-nav] Stage 1 threw, letting nav proceed:", (err as Error).message);
      return;
    }

    // Only redirect when Stage 1 ALONE is conclusive AND dangerous. That's
    // either:
    //   - bloom hit (rawScore = W("url.bloomfilter_blacklist_hit"))
    //   - rule weights summed to >= DANGER_FLOOR without seeing DOM
    // We intentionally do NOT redirect on "suspicious" because false-
    // positive friction at the URL bar is the worst possible UX.
    if (!stage1.shortCircuit || stage1.verdict !== "dangerous") return;
    if (stage1.rawScore < DANGER_FLOOR) return;

    const interstitialUrl = chrome.runtime.getURL(INTERSTITIAL_PATH)
      + `?lp_blocked=1&lp_url=${encodeURIComponent(details.url)}`
      + `&lp_score=${stage1.rawScore}`
      + `&lp_signals=${encodeURIComponent(stage1.signals.map((s) => s.id).join(","))}`;

    recentlyBlocked.set(details.tabId, {
      tabId: details.tabId,
      originalUrl: details.url,
      rawScore: stage1.rawScore,
      firedSignalIds: stage1.signals.map((s) => s.id),
    });

    // Redirect the tab. chrome.tabs.update fires asynchronously, so the
    // hostile URL may briefly enter the address bar — but onBeforeNavigate
    // runs before the page's network response is committed, so no DOM
    // ever paints from the hostile origin.
    void chrome.tabs.update(details.tabId, { url: interstitialUrl }).catch(() => {
      // tab may have been closed in the meantime
    });
  });

  // Clean up the blocked-tab record when the user navigates away from the
  // interstitial or closes the tab.
  chrome.tabs.onRemoved.addListener((tabId) => recentlyBlocked.delete(tabId));
  chrome.tabs.onUpdated.addListener((tabId, info) => {
    if (info.url && !info.url.startsWith(chrome.runtime.getURL(""))) {
      recentlyBlocked.delete(tabId);
    }
  });
}

/** Looked up by the interstitial's own logic (currently options.tsx is
 *  reused as the host). Returns null when no block is pending for this tab. */
export function getBlockedRecord(tabId: number): PendingRedirect | null {
  return recentlyBlocked.get(tabId) ?? null;
}
