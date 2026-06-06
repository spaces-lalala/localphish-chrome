// Content script — Shadow DOM badge UI.
//
// Renders a small risk indicator in the bottom-right corner of every page
// the content script runs on. Shadow DOM keeps our CSS isolated from the
// host page's stylesheet (plan §3.5: hostile sites can otherwise override
// styles via `* { display: none !important }`).
//
// Tiered alert policy (Week 16 v2, addressing §10 條 24):
//   - SAFE         → no badge (don't bug the user on legitimate pages)
//   - CAUTION      → small green-ish info badge, auto-fades after 4 s
//   - SUSPICIOUS   → amber pill, persistent, dismissible
//   - DANGEROUS, rules-anchored (rules score ≥ DANGER_FLOOR)
//                  → red pill + full-width top warning bar + action buttons
//   - DANGEROUS, LLM-alone (rules score < DANGER_FLOOR, LLM pushed final ≥ 75)
//                  → amber-red pill + DETAIL PANEL only (no top bar), explicit
//                    "model isn't fully sure" copy. Tier F showed Qwen 0.5B
//                    over-fires on 52% of benigns — we MUST NOT show the
//                    full-width red bar driven purely by a model that's been
//                    measured to over-fire on the user's own bank.
//
// All elements live inside one `<div id="localphish-badge-host">` attached
// to document.documentElement so we survive React/Vue rewrites of <body>.

import type { ClassifyResult, Signal, Verdict } from "@/types";

const HOST_ID = "localphish-badge-host";
const AUTO_HIDE_MS = 4000;

// Rules anchor threshold — only when at least this many rules-stage points
// have accumulated do we trust DANGEROUS enough to interrupt the user with
// the top warning bar. Mirrors DANGER_FLOOR in signals/thresholds.ts.
const RULES_ANCHOR_THRESHOLD = 75;

const VERDICT_COLORS: Record<Verdict, { bg: string; fg: string; ring: string; label: string }> = {
  safe:       { bg: "#dcfce7", fg: "#14532d", ring: "#16a34a", label: "SAFE" },
  caution:    { bg: "#fef9c3", fg: "#713f12", ring: "#eab308", label: "CAUTION" },
  suspicious: { bg: "#fed7aa", fg: "#7c2d12", ring: "#ea580c", label: "SUSPICIOUS" },
  dangerous:  { bg: "#fecaca", fg: "#7f1d1d", ring: "#dc2626", label: "DANGEROUS" }
};

// Signal ID → plain-language description. Shown in the detail panel instead
// of the raw `dom.password_cross_etld1_post`-style IDs which mean nothing to
// non-engineer users. Falls back to the signal's `detail` string when no
// translation exists (forward-compat with future signals).
const SIGNAL_TRANSLATIONS: Record<string, string> = {
  // ---- URL layer (Stage 1) -----------------------------------------------
  "url.ip_as_host":                "網址用 IP 數字當主機名（正常服務不會這樣）",
  "url.userinfo_at":                "網址藏「@」符號，可能把使用者引導到別的網域",
  "url.nonstandard_port":           "使用非標準的連接埠",
  "url.long":                       "網址異常地長",
  "url.many_hyphens":               "網址含過多連字號（典型偽冒網域手法）",
  "url.many_subdomains":            "子網域層數過多",
  "url.high_entropy_path":          "網址路徑亂碼很高，疑似自動產生",
  "url.double_encoded":             "網址含雙重 URL 編碼",
  "url.punycode_label":             "網址含 Punycode 編碼字元",
  "url.punycode_brand_lookalike":   "解碼後的網域長得像知名品牌（IDN 偽冒）",
  "url.mixed_script_label":         "網域混用拉丁字母與其他文字（混合腳本攻擊）",
  "url.typosquat_brand":            "網域是知名品牌的拼字錯誤版本（typosquat）",
  "url.subdomain_brand_abuse":      "在子網域偷藏品牌字串（reverse-proxy 釣魚）",
  "url.path_brand_abuse":           "URL 路徑藏品牌字串",
  "url.tld_high_risk":              "使用高風險頂級網域（如 .tk / .top / .zip）",
  "url.tld_medium_risk":            "使用中風險頂級網域",
  "url.tld_low_risk":               "使用低風險頂級網域",
  "url.gov_tw_substring_abuse":     "偽冒 .gov.tw：主機名含 gov.tw 但實際不是政府網域",
  "url.gov_tw_pseudo_tld":          "偽冒 .gov.tw：把 gov.tw 當作假頂級網域",
  "url.gov_tw_hyphen_variant":      "偽冒台灣政府：用連字號變體（gov-tw / twgov）",
  "url.reverse_proxy_fqdn":         "主機名嵌入完整品牌網域，疑似 Evilginx 反向代理",
  "url.reverse_proxy_hyphen_fqdn":  "用連字號攤平品牌完整網域，疑似反向代理",
  "url.phishlet_endpoint":          "命中常見 phishlet OAuth 端點（不在合法 IDP 上）",
  "url.zero_width_in_host":         "主機名含零寬字元",
  "url.zero_width_in_url":          "網址含零寬字元",
  "url.bidi_override_in_host":      "主機名含雙向覆寫字元（網址視覺欺騙）",
  "url.bidi_override_in_url":       "網址含雙向覆寫字元",
  "url.tag_char_in_url":            "網址含 Unicode tag char",
  // Short-circuits
  "url.allowlist_hit":              "全球熱門站台 allow-list 命中（已視為安全）",
  "url.tw_allowlist_hit":           "台灣本土機構 allow-list 命中（已視為安全）",
  "url.tw_institutional_tld":       ".edu.tw / .gov.tw 屬 TWNIC 認證機構（已視為安全）",
  "url.user_allowlist_hit":         "你的個人 allow-list 命中（已視為安全）",
  // ---- DOM layer (Stage 2) -----------------------------------------------
  "dom.password_no_tls":            "頁面用未加密（http）收集密碼",
  "dom.password_cross_etld1_post":  "密碼表單把資料送到另一個網域（credential exfil）",
  "dom.otp_cross_etld1_post":       "OTP 一次性密碼欄位送到另一個網域",
  "dom.card_cross_etld1_post":      "信用卡欄位送到另一個網域",
  "dom.card_and_password":          "同頁同時收集密碼 + 信用卡",
  "dom.seed_phrase_grid":           "要求輸入 12/24 字助記詞（加密貨幣錢包詐騙）",
  "dom.tw_pii_combo":               "同頁要求身分證字號 + 信用卡 + OTP（疑似身分盜用）",
  "dom.tw_national_id_cross_etld1_post": "身分證字號被送到別的網域",
  "dom.hidden_iframes":             "頁面藏有隱形 iframe",
  "dom.tiny_interactive":           "頁面用 1×1／透明／螢幕外的隱形按鈕",
  "dom.many_foreign_scripts":       "頁面載入過多外部網域的腳本",
  "dom.anti_debug":                 "頁面封鎖右鍵 / F12 / DevTools（防偵測）",
  "dom.cross_strait_terms":         "頁面自稱台灣機構但用語為大陸用語（短信／激活／賬號）",
  "dom.cross_strait_terms_strong":  "強烈跨海峽用語破綻（自稱台灣機構但簡中用語密集）",
  "dom.cloaking_verify_wall":       "頁面只有 Cloudflare Turnstile / hCaptcha 而幾乎沒內容",
  "dom.cloaking_verify_wall_strong": "驗證牆 cloaking：用挑戰把實際內容藏起來",
  "dom.favicon_brand_cdn_mismatch":      "favicon 從品牌官方 CDN 載入，但網域與該品牌不符",
  "dom.favicon_brand_canonical_mismatch": "favicon 來自品牌官方網域，但頁面網域與品牌無關",
  "dom.zero_width_in_text":         "頁面文字含零寬字元",
  "dom.bidi_override_in_text":      "頁面文字含雙向覆寫字元",
  "dom.tag_char_in_text":           "頁面文字含 Unicode tag char",
  "dom.oauth_idp_allowlisted":      "跨網域表單導向已知 OAuth 提供者（已排除）",
  // ---- LLM layer (Stage 3) ----------------------------------------------
  "llm.unavailable":                "本地 LLM 暫時無法使用",
  "llm.timeout":                    "本地 LLM 推論逾時"
};

function translateSignal(s: Signal): string {
  const tx = SIGNAL_TRANSLATIONS[s.id];
  if (tx) return tx;
  // Fall back to detail string (may be technical but at least informative);
  // if neither, use the raw ID.
  return s.detail ?? s.id;
}

/**
 * True when the verdict is driven by rule-layer evidence (not LLM-alone).
 * Used to decide whether the intrusive top warning bar fires.
 *
 * Defensive: only count signals on stage1 / stage2 (rules) and only when
 * they have positive weight. A high score that comes entirely from
 * `llm.unavailable`-style zero-weight markers should NOT count as anchored.
 */
function isRulesAnchored(result: ClassifyResult): boolean {
  let rulesPoints = 0;
  for (const s of result.signals) {
    if (s.stage === "stage1" || s.stage === "stage2") {
      rulesPoints += s.weight || 0;
    }
  }
  return rulesPoints >= RULES_ANCHOR_THRESHOLD;
}

function ensureHost(): { host: HTMLDivElement; root: ShadowRoot } {
  let host = document.getElementById(HOST_ID) as HTMLDivElement | null;
  if (host && host.shadowRoot) {
    return { host, root: host.shadowRoot };
  }
  if (host) host.remove();

  host = document.createElement("div");
  host.id = HOST_ID;
  // Defensive inline styles in case the page tries to hide elements by id.
  host.style.cssText = [
    "all: initial",
    "position: fixed",
    "z-index: 2147483647", // top of int32; bigger than any reasonable page z-index
    "right: 16px",
    "bottom: 16px",
    "pointer-events: none" // children opt back in
  ].join("; ");

  // Attach to <html>, not <body> — body can be replaced by SPA hydration.
  document.documentElement.appendChild(host);
  const root = host.attachShadow({ mode: "open" });
  return { host, root };
}

const BASE_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, "Microsoft JhengHei", sans-serif; }
  .badge {
    pointer-events: auto;
    display: flex; align-items: center; gap: 6px;
    padding: 6px 10px;
    border-radius: 999px;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.2);
    font-size: 12px; font-weight: 600;
    cursor: pointer; user-select: none;
    transition: transform 0.15s ease, box-shadow 0.15s ease, opacity 0.2s ease;
    border: 2px solid var(--ring, #9ca3af);
    background: var(--bg, white);
    color: var(--fg, #1f2937);
  }
  .badge:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(0,0,0,0.25); }
  .badge.collapsed { padding: 4px 8px; font-size: 0; }
  .badge.collapsed .label { display: none; }
  .badge.collapsed .close { display: none; }
  .badge.collapsed .dot { width: 8px; height: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--ring, #9ca3af); }
  /* Score deliberately NOT shown in the outer pill — review §10 條 27 said
   * showing "DANGEROUS 92" makes users over-read a heuristic weight sum as
   * a calibrated probability. Raw score lives only in the detail panel, with
   * an explicit "啟發式加總，非機率" caveat next to it. */
  .close {
    pointer-events: auto;
    margin-left: 2px;
    cursor: pointer;
    background: transparent; border: 0; color: inherit;
    font-size: 16px; line-height: 1;
    padding: 0 2px;
    opacity: 0.6;
  }
  .close:hover { opacity: 1; }
  .danger-bar {
    pointer-events: auto;
    position: fixed; left: 0; right: 0; top: 0;
    padding: 10px 16px;
    background: #b91c1c; color: white;
    font-size: 14px; font-weight: 600;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    display: flex; align-items: center; gap: 10px;
  }
  .danger-bar .icon { font-size: 18px; }
  .danger-bar .actions { margin-left: auto; display: flex; gap: 8px; }
  .danger-bar a.btn, .actions a.btn {
    background: white; color: #b91c1c;
    text-decoration: none;
    padding: 4px 10px; border-radius: 6px;
    font-size: 12px; font-weight: 700;
  }
  .danger-bar a.btn.secondary, .actions a.btn.secondary {
    background: transparent; color: white; border: 1px solid white;
  }
  .panel {
    pointer-events: auto;
    margin-top: 8px;
    max-width: 360px;
    background: white;
    color: #1f2937;
    border: 1px solid #d1d5db;
    border-radius: 10px;
    padding: 10px 12px;
    box-shadow: 0 6px 20px rgba(0,0,0,0.18);
    font-size: 12px;
    display: none;
  }
  .panel.open { display: block; }
  .panel h4 { margin: 0 0 6px; font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.04em; }
  .panel ul { margin: 0; padding-left: 18px; line-height: 1.5; }
  .panel .meta { margin-top: 8px; padding-top: 6px; border-top: 1px solid #f3f4f6; color: #6b7280; font-size: 11px; }
  .panel .uncertain {
    margin-top: 8px; padding: 6px 8px;
    background: #fef3c7; color: #78350f;
    border-radius: 6px; font-size: 11px; line-height: 1.4;
  }
  .panel .panel-actions { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
  .panel .panel-actions a {
    flex: 1; min-width: 0;
    text-align: center;
    text-decoration: none;
    padding: 6px 8px;
    border-radius: 6px;
    background: #1d4ed8; color: white;
    font-size: 11px; font-weight: 600;
  }
  .panel .panel-actions a.secondary { background: #e5e7eb; color: #111827; }
  @media (prefers-color-scheme: dark) {
    .panel { background: #1f2937; color: #e5e7eb; border-color: #4b5563; }
    .panel .meta { border-top-color: #374151; color: #9ca3af; }
    .panel .uncertain { background: #78350f; color: #fef3c7; }
    .panel .panel-actions a.secondary { background: #374151; color: #e5e7eb; }
  }
`;

function buildContent(result: ClassifyResult, host: string): { html: string } {
  const c = VERDICT_COLORS[result.verdict];
  const rulesAnchored = isRulesAnchored(result);

  // Show the strongest weight-bearing signals first; informational ones
  // (LLM reasons with weight=0, llm.unavailable, etc.) come after. Result
  // ordering otherwise is collection order which buries cross-strait /
  // seed-phrase signals despite their +35/+45 weight.
  const ranked = [...result.signals]
    .filter((s) => (s.weight || 0) > 0 || (s.id.startsWith("dom.") || s.id.startsWith("url.")))
    .sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const topSignals = ranked.slice(0, 4);
  const remaining = Math.max(0, ranked.length - topSignals.length);

  const reasonItems = topSignals
    .map((s) => `<li>${escapeHtml(translateSignal(s))}</li>`)
    .join("");
  const more = remaining > 0 ? `<li><em>還有 ${remaining} 項其他證據</em></li>` : "";

  // Action buttons. Always available for dangerous/suspicious — gives the
  // user a next step instead of just shouting "DANGER".
  const verify165 = "https://165.npa.gov.tw/";
  const actionsHtml = (result.verdict === "dangerous" || result.verdict === "suspicious")
    ? `<a class="btn" href="${verify165}" target="_blank" rel="noopener">用 165 查證</a>
       <a class="btn secondary" href="javascript:history.back()">返回上一頁</a>`
    : "";
  const panelActionsHtml = (result.verdict === "dangerous" || result.verdict === "suspicious")
    ? `<div class="panel-actions">
         <a href="${verify165}" target="_blank" rel="noopener">用 165 查證網址</a>
         <a class="secondary" href="javascript:history.back()">返回上一頁</a>
       </div>`
    : "";

  // Show the intrusive top bar ONLY when verdict is dangerous AND rules
  // anchored it. LLM-alone dangerous (Qwen 0.5B fired on rendered DOM with
  // no rule support) does NOT trigger the top bar — Tier F said FPR 52%
  // for that path, so the user would mostly see it on legit pages.
  const showTopBar = result.verdict === "dangerous" && rulesAnchored;
  const dangerBar = showTopBar
    ? `<div class="danger-bar">
         <span class="icon">⚠️</span>
         <strong>LocalPhish：</strong>此頁面強烈疑似釣魚（規則層分數 ≥ ${RULES_ANCHOR_THRESHOLD}），請勿輸入帳密。
         <span class="actions">${actionsHtml}</span>
       </div>`
    : "";

  // When verdict is dangerous but NOT rules-anchored, surface the caveat in
  // the detail panel so the user can interpret the warning correctly.
  const uncertainNote = (result.verdict === "dangerous" && !rulesAnchored)
    ? `<div class="uncertain">⚠️ 本地 LLM 提醒：此頁面結構模型認為偏向釣魚，但規則層證據不足。可能是 false positive — 若這是你信任的頁面（例如自己的銀行），可在 Options 加入個人 allowlist。</div>`
    : "";

  const titleAttr = `LocalPhish ${c.label} score ${result.riskScore}`;
  const html = `
    <style>${BASE_CSS}</style>
    <div style="--bg: ${c.bg}; --fg: ${c.fg}; --ring: ${c.ring};">
      ${dangerBar}
      <div class="badge" id="lp-badge" role="button" tabindex="0" aria-label="${escapeHtml(titleAttr)}">
        <span class="dot"></span>
        <span class="label">${c.label}</span>
        <button class="close" id="lp-close" title="Dismiss" aria-label="Dismiss">×</button>
      </div>
      <div class="panel" id="lp-panel">
        <h4>偵測證據（前 ${topSignals.length} 項）</h4>
        <ul>${reasonItems}${more}</ul>
        ${uncertainNote}
        ${panelActionsHtml}
        <div class="meta">
          ${escapeHtml(host)}
          · 階段 ${escapeHtml(result.stagesRan.join(" → "))}
          · backend ${escapeHtml(result.backend)}
          · ${result.latencyMs.toFixed(0)} ms
          <br>
          內部分數 <code>${result.riskScore}</code> — 啟發式 weight 加總，非校準機率，僅供工程除錯
        </div>
      </div>
    </div>
  `;
  return { html };
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let hideTimer: number | null = null;

const LOADING_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, "Microsoft JhengHei", sans-serif; }
  .pill {
    pointer-events: auto;
    display: flex; align-items: center; gap: 8px;
    padding: 8px 12px;
    border-radius: 999px;
    background: white; color: #1f2937;
    border: 1px solid #d1d5db;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.15);
    font-size: 13px; font-weight: 500;
    opacity: 0.95;
  }
  .spinner {
    width: 12px; height: 12px;
    border: 2px solid #d1d5db;
    border-top-color: #2563eb;
    border-radius: 50%;
    animation: lp-spin 0.8s linear infinite;
  }
  @keyframes lp-spin { to { transform: rotate(360deg); } }
  @media (prefers-color-scheme: dark) {
    .pill { background: #1f2937; color: #e5e7eb; border-color: #4b5563; }
    .spinner { border-color: #4b5563; border-top-color: #60a5fa; }
  }
`;

/**
 * Render a neutral "Analyzing…" pill. The content script calls this 800 ms
 * after dispatching classifyPage so users on heavy pages (longer LLM run)
 * see *something* happening instead of an empty corner and a tempting F5.
 */
export function renderProgressBadge(): void {
  const { root } = ensureHost();
  root.innerHTML = `
    <style>${LOADING_CSS}</style>
    <div class="pill" aria-live="polite">
      <span class="spinner" aria-hidden="true"></span>
      <span>LocalPhish · Analyzing…</span>
    </div>
  `;
}

export function renderBadge(result: ClassifyResult): void {
  // SAFE pages don't get a badge — too noisy. Allow-list hits, content-less
  // pages, and chrome:// derived results fall into this bucket.
  if (result.verdict === "safe") {
    removeBadge();
    return;
  }

  const { host: hostEl, root } = ensureHost();
  const host = (() => {
    try {
      return new URL(location.href).hostname;
    } catch {
      return "";
    }
  })();
  const { html } = buildContent(result, host);
  root.innerHTML = html;

  const badge = root.getElementById("lp-badge") as HTMLDivElement | null;
  const panel = root.getElementById("lp-panel") as HTMLDivElement | null;
  const close = root.getElementById("lp-close") as HTMLButtonElement | null;

  // Click-outside collapse — review §10 條 29: z-index 2147483647 on an
  // always-mounted overlay covers legit cookie banners / 客服 widgets.
  // Auto-collapse to a tiny icon-only pill on outside click so the badge
  // stops blocking the underlying page after the first glance. The user
  // can still see the verdict (small color dot) and re-expand by clicking
  // the dot. Top-level danger bar (rules-anchored only) is the kill-chain
  // protection and is NOT collapsed.
  let collapseTimer: number | null = null;
  let documentClickHandler: ((e: MouseEvent) => void) | null = null;
  const isCollapsed = () => badge?.classList.contains("collapsed") ?? true;
  const collapse = () => {
    badge?.classList.add("collapsed");
    panel?.classList.remove("open");
  };
  const expand = () => {
    badge?.classList.remove("collapsed");
    // Reset auto-collapse window each time the user opens the badge.
    if (collapseTimer != null) clearTimeout(collapseTimer);
    if (result.verdict !== "dangerous") {
      // Soft verdicts auto-collapse after 8 s of no interaction so the
      // badge isn't a permanent screen squatter on the host page.
      collapseTimer = window.setTimeout(() => collapse(), 8000);
    }
  };

  if (badge && panel) {
    // Default state: collapsed icon-only pill except for DANGEROUS, which
    // stays expanded so the user can't miss the warning.
    if (result.verdict !== "dangerous") {
      collapse();
    } else {
      expand();
    }
    const toggle = (e: Event) => {
      e.stopPropagation();
      if (isCollapsed()) {
        expand();
      } else {
        // Already expanded — toggle the detail panel.
        panel.classList.toggle("open");
      }
    };
    badge.addEventListener("click", toggle);
    badge.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") toggle(e);
    });
  }
  if (close) {
    close.addEventListener("click", (e) => {
      e.stopPropagation();
      removeBadge();
    });
  }

  // Outside-click listener — collapse the badge when the user clicks
  // anywhere on the host page that isn't ours. Capture phase so we run
  // before the host page's own handlers, and we don't preventDefault so
  // their click still works.
  documentClickHandler = (e: MouseEvent) => {
    if (!(e.target instanceof Node)) return;
    if (hostEl.contains(e.target)) return;
    if (!isCollapsed()) collapse();
  };
  document.addEventListener("click", documentClickHandler, true);

  // Stash the handler reference on the host element so removeBadge() can
  // tear it down without hunting through closures.
  (hostEl as HTMLDivElement & { __lpClickListener?: (e: MouseEvent) => void })
    .__lpClickListener = documentClickHandler;

  // Auto-hide on caution only — suspicious / dangerous stay until dismissed.
  if (hideTimer != null) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
  if (result.verdict === "caution") {
    hideTimer = window.setTimeout(() => removeBadge(), AUTO_HIDE_MS);
  }
}

export function removeBadge(): void {
  if (hideTimer != null) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
  const host = document.getElementById(HOST_ID) as
    | (HTMLDivElement & { __lpClickListener?: (e: MouseEvent) => void })
    | null;
  if (host) {
    if (host.__lpClickListener) {
      document.removeEventListener("click", host.__lpClickListener, true);
    }
    host.remove();
  }
}
