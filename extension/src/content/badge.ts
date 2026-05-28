// Content script — Shadow DOM badge UI.
//
// Renders a small risk indicator in the bottom-right corner of every page
// the content script runs on. Shadow DOM keeps our CSS isolated from the
// host page's stylesheet (plan §3.5: hostile sites can otherwise override
// styles via `* { display: none !important }`).
//
// Visibility policy:
//   - SAFE         → no badge (don't bug the user on legitimate pages)
//   - CAUTION      → small green-ish info badge, auto-fades after 4s
//   - SUSPICIOUS   → amber badge, persistent, dismissible
//   - DANGEROUS    → red badge with full-width warning bar at top, persistent
//
// All elements live inside one `<div id="localphish-badge-host">` attached to
// document.documentElement so we survive React/Vue rewrites of <body>.

import type { ClassifyResult, Verdict } from "@/types";

const HOST_ID = "localphish-badge-host";
const AUTO_HIDE_MS = 4000;

const VERDICT_COLORS: Record<Verdict, { bg: string; fg: string; ring: string; label: string }> = {
  safe:       { bg: "#dcfce7", fg: "#14532d", ring: "#16a34a", label: "SAFE" },
  caution:    { bg: "#fef9c3", fg: "#713f12", ring: "#eab308", label: "CAUTION" },
  suspicious: { bg: "#fed7aa", fg: "#7c2d12", ring: "#ea580c", label: "SUSPICIOUS" },
  dangerous:  { bg: "#fecaca", fg: "#7f1d1d", ring: "#dc2626", label: "DANGEROUS" }
};

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
    display: flex; align-items: center; gap: 8px;
    padding: 8px 12px;
    border-radius: 999px;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.2);
    font-size: 13px; font-weight: 600;
    cursor: pointer; user-select: none;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
    border: 2px solid var(--ring, #9ca3af);
    background: var(--bg, white);
    color: var(--fg, #1f2937);
  }
  .badge:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(0,0,0,0.25); }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--ring, #9ca3af); }
  .score { font-variant-numeric: tabular-nums; opacity: 0.85; font-weight: 500; }
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
  .panel {
    pointer-events: auto;
    margin-top: 8px;
    max-width: 320px;
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
  @media (prefers-color-scheme: dark) {
    .panel { background: #1f2937; color: #e5e7eb; border-color: #4b5563; }
    .panel .meta { border-top-color: #374151; color: #9ca3af; }
  }
`;

function buildContent(result: ClassifyResult): { html: string; danger: boolean } {
  const c = VERDICT_COLORS[result.verdict];

  // Show the strongest weight-bearing signals first; informational ones
  // (LLM reasons with weight=0, llm.unavailable, etc.) come after. Result
  // ordering otherwise is collection order which buries cross-strait /
  // seed-phrase signals despite their +35/+45 weight.
  const ranked = [...result.signals]
    .sort((a, b) => (b.weight || 0) - (a.weight || 0));
  const topSignals = ranked.slice(0, 3);
  const remaining = Math.max(0, result.signals.length - topSignals.length);

  const reasonItems = topSignals
    .map((s) => `<li>${escapeHtml(s.detail ?? s.id)}</li>`)
    .join("");
  const more = remaining > 0 ? `<li><em>+${remaining} more reason(s)</em></li>` : "";

  const dangerBar = result.verdict === "dangerous"
    ? `<div class="danger-bar"><span class="icon">⚠️</span><strong>LocalPhish:</strong> This page looks like phishing (score ${result.riskScore}). Do not enter credentials.</div>`
    : "";

  const html = `
    <style>${BASE_CSS}</style>
    <div style="--bg: ${c.bg}; --fg: ${c.fg}; --ring: ${c.ring};">
      ${dangerBar}
      <div class="badge" id="lp-badge" role="button" tabindex="0" aria-label="LocalPhish ${c.label} score ${result.riskScore}">
        <span class="dot"></span>
        <span class="label">${c.label}</span>
        <span class="score">${result.riskScore}</span>
        <button class="close" id="lp-close" title="Dismiss" aria-label="Dismiss">×</button>
      </div>
      <div class="panel" id="lp-panel">
        <h4>Top reasons</h4>
        <ul>${reasonItems}${more}</ul>
        <div class="meta">
          Stages: ${escapeHtml(result.stagesRan.join(" → "))}
          · backend ${escapeHtml(result.backend)}
          · ${result.latencyMs.toFixed(0)} ms
        </div>
      </div>
    </div>
  `;
  return { html, danger: result.verdict === "dangerous" };
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

  const { root } = ensureHost();
  const { html } = buildContent(result);
  root.innerHTML = html;

  const badge = root.getElementById("lp-badge") as HTMLDivElement | null;
  const panel = root.getElementById("lp-panel") as HTMLDivElement | null;
  const close = root.getElementById("lp-close") as HTMLButtonElement | null;

  if (badge && panel) {
    const toggle = (e: Event) => {
      e.stopPropagation();
      panel.classList.toggle("open");
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
  const host = document.getElementById(HOST_ID);
  if (host) host.remove();
}
