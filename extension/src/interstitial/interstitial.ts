// LocalPhish pre-navigation interstitial controller.
//
// Reads the redirect URL's query params (set by background/pre-nav-
// interstitial.ts) and populates the warning page with:
//   - the URL we just blocked
//   - the signals that fired in Stage 1
//   - the raw score (with explicit "heuristic, not probability" caveat)
//   - action buttons (back / 165 verify / proceed anyway)
//
// All values come from the redirect URL; no message-passing to SW required.
// This makes the page work even if the SW has been evicted between the
// redirect and the page being shown.

import spec from "@/data/signal-spec.json";

interface SignalSpecEntry { stage: string; weight: number; description: string }
const SIGNALS = (spec as { signals: Record<string, SignalSpecEntry> }).signals;

// Plain-Chinese translation of the most common signal IDs. Mirrors the
// table in content/badge.ts so both surfaces show the same human-readable
// reason. Falls back to the spec's English description when no zh-TW entry.
const ZH_TW_TRANSLATIONS: Record<string, string> = {
  "url.ip_as_host":                      "網址用 IP 數字當主機名（正常服務不會這樣）",
  "url.userinfo_at":                     "網址藏「@」符號，可能把使用者引導到別的網域",
  "url.nonstandard_port":                "使用非標準的連接埠",
  "url.long":                            "網址異常地長",
  "url.many_hyphens":                    "網址含過多連字號（典型偽冒網域手法）",
  "url.many_subdomains":                 "子網域層數過多",
  "url.high_entropy_path":               "網址路徑亂碼很高，疑似自動產生",
  "url.double_encoded":                  "網址含雙重 URL 編碼",
  "url.punycode_label":                  "網址含 Punycode 編碼字元",
  "url.punycode_brand_lookalike":        "解碼後的網域長得像知名品牌（IDN 偽冒）",
  "url.mixed_script_label":              "網域混用拉丁字母與其他文字（混合腳本攻擊）",
  "url.typosquat_brand":                 "網域是知名品牌的拼字錯誤版本（typosquat）",
  "url.subdomain_brand_abuse":           "在子網域偷藏品牌字串（reverse-proxy 釣魚）",
  "url.path_brand_abuse":                "URL 路徑藏品牌字串",
  "url.tld_high_risk":                   "使用高風險頂級網域（如 .tk / .top / .zip）",
  "url.tld_medium_risk":                 "使用中風險頂級網域",
  "url.tld_low_risk":                    "使用低風險頂級網域",
  "url.gov_tw_substring_abuse":          "偽冒 .gov.tw：主機名含 gov.tw 但實際不是政府網域",
  "url.gov_tw_pseudo_tld":               "偽冒 .gov.tw：把 gov.tw 當作假頂級網域",
  "url.gov_tw_hyphen_variant":           "偽冒台灣政府：用連字號變體（gov-tw / twgov）",
  "url.reverse_proxy_fqdn":              "主機名嵌入完整品牌網域，疑似 Evilginx 反向代理",
  "url.reverse_proxy_hyphen_fqdn":       "用連字號攤平品牌完整網域，疑似反向代理",
  "url.phishlet_endpoint":               "命中常見 phishlet OAuth 端點（不在合法 IDP 上）",
  "url.zero_width_in_host":              "主機名含零寬字元",
  "url.zero_width_in_url":               "網址含零寬字元",
  "url.bidi_override_in_host":           "主機名含雙向覆寫字元（網址視覺欺騙）",
  "url.bidi_override_in_url":            "網址含雙向覆寫字元",
  "url.tag_char_in_url":                 "網址含 Unicode tag char",
  "url.bloomfilter_blacklist_hit":       "命中內政部警政署 165 反詐騙專線公告的詐騙網域清單",
};

function describeSignal(id: string): string {
  if (ZH_TW_TRANSLATIONS[id]) return ZH_TW_TRANSLATIONS[id];
  const s = SIGNALS[id];
  return s?.description ?? id;
}

function weightFor(id: string): number {
  return SIGNALS[id]?.weight ?? 0;
}

function escapeText(s: string): string {
  // textContent setters handle escaping for us; this is just for the
  // edge cases where we build a string used elsewhere.
  return s;
}

const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("lp_url") || "";
const score = params.get("lp_score") || "—";
const signalsCsv = params.get("lp_signals") || "";
const signalIds = signalsCsv ? signalsCsv.split(",").filter(Boolean) : [];

// Populate the page. Use textContent everywhere — never innerHTML with a
// value derived from the redirect URL.
const urlEl = document.getElementById("blocked-url");
if (urlEl) urlEl.textContent = blockedUrl || "(網址資訊遺失)";

const scoreEl = document.getElementById("score");
if (scoreEl) scoreEl.textContent = score;

const listEl = document.getElementById("signal-list");
if (listEl) {
  listEl.innerHTML = "";
  if (signalIds.length === 0) {
    const li = document.createElement("li");
    li.classList.add("muted");
    li.textContent = "(訊號資訊遺失 — 請從 LocalPhish Options 查看 misjudgment log)";
    listEl.appendChild(li);
  } else {
    for (const id of signalIds) {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = id;
      li.appendChild(code);
      const w = weightFor(id);
      if (w > 0) {
        const wSpan = document.createElement("span");
        wSpan.textContent = ` +${w} `;
        wSpan.style.opacity = "0.7";
        wSpan.style.fontFamily = "ui-monospace, monospace";
        li.appendChild(wSpan);
      }
      const desc = document.createElement("span");
      desc.textContent = describeSignal(id);
      li.appendChild(desc);
      listEl.appendChild(li);
    }
  }
}

// Back button — uses history.back if there's something to go back to,
// else closes the tab (chrome.tabs API is not available from a regular
// page; window.close() works only on tabs the extension opened, but
// we're acceptable with leaving the user on the interstitial as a
// fallback).
const backBtn = document.getElementById("back-btn");
if (backBtn) {
  backBtn.addEventListener("click", (e) => {
    e.preventDefault();
    if (window.history.length > 1) {
      window.history.back();
    } else {
      // Browser opened this URL fresh — no back history. Best we can do
      // is suggest closing or navigating elsewhere.
      window.location.href = "about:blank";
    }
  });
}

// "Proceed anyway" — confirm twice then send the user back to the blocked
// URL. We intentionally do NOT add the host to the user allowlist here;
// that's a separate, deliberate action via the Options page.
const proceedBtn = document.getElementById("proceed-anyway");
if (proceedBtn && blockedUrl) {
  proceedBtn.addEventListener("click", (e) => {
    e.preventDefault();
    const msg =
      `⚠️ 你即將前往 LocalPhish 標為 DANGEROUS 的網址：\n\n${blockedUrl}\n\n` +
      `規則層分數：${score} / 100\n\n` +
      `這個網域可能在內政部警政署的詐騙清單裡，或結構符合典型釣魚樣態。` +
      `如果你不是受過安全訓練的測試人員或研究員，強烈建議按取消。\n\n` +
      `仍要繼續嗎？`;
    if (window.confirm(msg)) {
      // Second confirmation — friction is the point.
      if (window.confirm("最後確認：你的密碼 / 信用卡 / 身分證可能在這個頁面被盜走。確定要繼續？")) {
        window.location.replace(blockedUrl);
      }
    }
  });
} else if (proceedBtn) {
  proceedBtn.style.display = "none";
}

// Defensive: make textContent setters quiet typescript-unused-import.
void escapeText;
