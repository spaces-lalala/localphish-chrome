// Stage 2 — cross-strait (繁/簡) language anomaly detection.
//
// Threat model: a real Taiwanese institution writing 繁體中文 uses Taiwan
// terminology (「簡訊」「啟用」「訊息」「帳號」「影片」「螢幕」「軟體」「設定」).
// Phishing kits produced by mainland actors often slip mainland Chinese
// terminology into pages otherwise targeted at Taiwan ("短信、激活、信息、
// 賬號、視頻、屏幕、軟件、設置"). When a page either:
//   (a) claims to be a Taiwan brand (matches Taiwan brand alias), or
//   (b) is on a `.tw` / `.tw.*` hostname,
// AND its visible text shows mainland-Chinese vocabulary above a small
// threshold, this is a strong tell — much more deterministic than relying
// on the LLM alone.
//
// The dictionary is small and curated for high precision: every entry is a
// term whose mainland form is essentially never used in Taiwan-localized
// official communications.

import type { PageFeatures, Signal } from "@/types";

const W_CROSS_STRAIT_LANGUAGE = 25;
const W_CROSS_STRAIT_LANGUAGE_STRONG = 35; // when ≥ 3 distinct mainland terms

/** Mainland Chinese term → Taiwan equivalent, for evidence reporting. */
const MAINLAND_TERMS: Record<string, string> = {
  "短信": "簡訊",
  "激活": "啟用",
  "信息": "訊息",
  "賬號": "帳號",   // 賬 is the simplified character of 帳 — though both render in 繁體 fonts, the choice is diagnostic
  "視頻": "影片",
  "屏幕": "螢幕",
  "軟件": "軟體",
  "默認": "預設",
  "客戶端": "用戶端",
  "網絡": "網路",
  "服務器": "伺服器",
  "鼠標": "滑鼠",
  "硬盤": "硬碟",
  "內存": "記憶體",
  "打印": "列印",
  "文件夾": "資料夾",
  "登錄": "登入",
  "用戶名": "使用者名稱",
  "驗證碼": "驗證碼"  // identical — kept out of detection; placeholder for completeness
};

// Cheap lookup of which terms are flagged (drop the placeholder-equal ones).
const MAINLAND_TERM_SET: ReadonlySet<string> = new Set(
  Object.entries(MAINLAND_TERMS)
    .filter(([k, v]) => k !== v)
    .map(([k]) => k)
);

const TW_INSTITUTION_HINTS = [
  // government / state services
  "政府", "衛福部", "健保署", "健保卡", "國稅局", "財政部", "內政部", "勞動部",
  "經濟部", "監理服務網", "監理站", "戶政事務所", "警政署", "165",
  // major Taiwan brands users see in phishing
  "中華郵政", "中華電信", "台灣大哥大", "遠傳", "悠遊卡", "悠遊付",
  "遠通電收", "ETC", "蝦皮", "momo購物", "PChome",
  // banks
  "國泰世華", "中國信託", "中信銀行", "玉山銀行", "兆豐", "第一銀行",
  "台新銀行", "富邦銀行", "合作金庫", "台灣銀行"
];

/** Cheap check: does the page's visible text or title self-identify as a
 *  Taiwan institution? Used to gate the cross-strait term anomaly so a
 *  Chinese-language English-targeting tutorial doesn't trip the signal. */
function claimsTaiwanInstitution(features: PageFeatures): { matched: boolean; hint?: string } {
  const haystack = `${features.title} ${features.visibleTextSample}`;
  for (const hint of TW_INSTITUTION_HINTS) {
    if (haystack.includes(hint)) {
      return { matched: true, hint };
    }
  }
  return { matched: false };
}

function isTwHost(features: PageFeatures, pageEtld1: string | null): boolean {
  if (pageEtld1 && pageEtld1.toLowerCase().endsWith(".tw")) return true;
  // hostname directly contains `.tw` but eTLD+1 is missing — defensive
  try {
    const host = new URL(features.url).hostname.toLowerCase();
    return host.endsWith(".tw");
  } catch {
    return false;
  }
}

export function crossStraitLanguageSignals(
  features: PageFeatures,
  pageEtld1: string | null
): Signal[] {
  if (!features.visibleTextSample) return [];

  // Gate the check: either the page claims to be a TW institution, OR
  // the page is on a Taiwan hostname. Without this gate the detector
  // would yell at legitimate Mandarin content from mainland-targeted sites.
  const claim = claimsTaiwanInstitution(features);
  const onTwHost = isTwHost(features, pageEtld1);
  if (!claim.matched && !onTwHost) return [];

  const hits: string[] = [];
  for (const term of MAINLAND_TERM_SET) {
    if (features.visibleTextSample.includes(term)) {
      hits.push(term);
      if (hits.length >= 6) break; // cap collection for sanity
    }
  }
  if (hits.length === 0) return [];

  const strong = hits.length >= 3;
  const weight = strong ? W_CROSS_STRAIT_LANGUAGE_STRONG : W_CROSS_STRAIT_LANGUAGE;

  const examples = hits
    .map((t) => `${t}→${MAINLAND_TERMS[t]}`)
    .join("、");

  let detail: string;
  if (claim.matched) {
    detail = `page references "${claim.hint}" but uses mainland Chinese terms (${examples})`;
  } else {
    detail = `page on .tw host uses mainland Chinese terms (${examples})`;
  }

  return [{
    id: strong ? "dom.cross_strait_terms_strong" : "dom.cross_strait_terms",
    stage: "stage2",
    weight,
    detail
  }];
}
