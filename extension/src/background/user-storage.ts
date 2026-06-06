// User-controlled local storage helpers.
//
// Three buckets, all chrome.storage.local except verdict cache (session):
//   - user_allowlist : Set<eTLD+1> the user added manually (Options page)
//   - misjudgments   : list of pages the user flagged as misclassified
//   - tab_verdicts   : per-tab last verdict, restored on SW reboot (session)
//
// All writes are async and best-effort. Cached in-memory mirrors keep the
// SW hot path (cascade dispatch) synchronous.

import type { ClassifyResult } from "@/types";

const KEY_ALLOWLIST = "user_allowlist";
const KEY_MISJUDGMENTS = "misjudgments";
const KEY_TAB_VERDICTS = "tab_verdicts";
const KEY_PROFILE = "llm_profile";
const MAX_MISJUDGMENTS = 100;

// ---- LLM profile preference (auto / pro / lite) -------------------------

export type StoredProfile = "auto" | "pro" | "lite";

export async function loadProfile(): Promise<StoredProfile> {
  const v = await chrome.storage.local.get(KEY_PROFILE);
  const p = v[KEY_PROFILE] as StoredProfile | undefined;
  if (p === "auto" || p === "pro" || p === "lite") return p;
  // Default to lite: Nano-only, no 1.2 GB surprise download.
  return "lite";
}

export async function saveProfile(p: StoredProfile): Promise<void> {
  await chrome.storage.local.set({ [KEY_PROFILE]: p });
}

// ---- User allowlist ------------------------------------------------------

let allowlistCache: Set<string> | null = null;

export async function loadUserAllowlist(): Promise<Set<string>> {
  if (allowlistCache) return allowlistCache;
  const v = await chrome.storage.local.get(KEY_ALLOWLIST);
  const arr = (v[KEY_ALLOWLIST] as string[] | undefined) ?? [];
  allowlistCache = new Set(arr.map((s) => s.toLowerCase()));
  return allowlistCache;
}

export function userAllowlistHas(etld1: string): boolean {
  return allowlistCache != null && allowlistCache.has(etld1.toLowerCase());
}

export async function addUserAllowlist(etld1: string): Promise<void> {
  await loadUserAllowlist();
  const next = new Set(allowlistCache!);
  next.add(etld1.toLowerCase());
  allowlistCache = next;
  await chrome.storage.local.set({ [KEY_ALLOWLIST]: Array.from(next) });
}

export async function removeUserAllowlist(etld1: string): Promise<void> {
  await loadUserAllowlist();
  const next = new Set(allowlistCache!);
  next.delete(etld1.toLowerCase());
  allowlistCache = next;
  await chrome.storage.local.set({ [KEY_ALLOWLIST]: Array.from(next) });
}

export function watchUserAllowlist(): void {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (!changes[KEY_ALLOWLIST]) return;
    const arr = (changes[KEY_ALLOWLIST].newValue as string[] | undefined) ?? [];
    allowlistCache = new Set(arr.map((s) => s.toLowerCase()));
  });
}

// ---- Misjudgment reports -------------------------------------------------

export interface MisjudgmentEntry {
  url: string;
  verdict: ClassifyResult["verdict"];
  expectedVerdict: ClassifyResult["verdict"];
  riskScore: number;
  reasons: string[];
  ts: number;
}

export async function addMisjudgment(entry: MisjudgmentEntry): Promise<void> {
  const v = await chrome.storage.local.get(KEY_MISJUDGMENTS);
  const list = (v[KEY_MISJUDGMENTS] as MisjudgmentEntry[] | undefined) ?? [];
  list.unshift(entry);
  if (list.length > MAX_MISJUDGMENTS) list.length = MAX_MISJUDGMENTS;
  await chrome.storage.local.set({ [KEY_MISJUDGMENTS]: list });
}

export async function listMisjudgments(): Promise<MisjudgmentEntry[]> {
  const v = await chrome.storage.local.get(KEY_MISJUDGMENTS);
  return (v[KEY_MISJUDGMENTS] as MisjudgmentEntry[] | undefined) ?? [];
}

export async function removeMisjudgment(ts: number, url: string): Promise<void> {
  // Match on (ts, url) so the same URL reported twice doesn't collapse to one
  // removal. Both fields are stable client-side identifiers — no server round-trip.
  const v = await chrome.storage.local.get(KEY_MISJUDGMENTS);
  const list = (v[KEY_MISJUDGMENTS] as MisjudgmentEntry[] | undefined) ?? [];
  const next = list.filter((e) => !(e.ts === ts && e.url === url));
  await chrome.storage.local.set({ [KEY_MISJUDGMENTS]: next });
}

// ---- Per-tab verdict cache (session — persists across SW reboot in same browser session)

export async function loadTabVerdicts(): Promise<Map<number, ClassifyResult>> {
  // chrome.storage.session is MV3-only. Older surfaces won't have it.
  if (!chrome.storage.session) return new Map();
  const v = await chrome.storage.session.get(KEY_TAB_VERDICTS);
  const obj = (v[KEY_TAB_VERDICTS] as Record<string, ClassifyResult> | undefined) ?? {};
  const m = new Map<number, ClassifyResult>();
  for (const [k, val] of Object.entries(obj)) {
    const id = Number(k);
    if (Number.isFinite(id)) m.set(id, val);
  }
  return m;
}

export async function persistTabVerdicts(map: Map<number, ClassifyResult>): Promise<void> {
  if (!chrome.storage.session) return;
  const obj: Record<string, ClassifyResult> = {};
  for (const [id, val] of map.entries()) {
    obj[String(id)] = val;
  }
  await chrome.storage.session.set({ [KEY_TAB_VERDICTS]: obj });
}
