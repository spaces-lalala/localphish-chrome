import { defineManifest } from "@crxjs/vite-plugin";
import pkg from "./package.json" with { type: "json" };

export default defineManifest({
  manifest_version: 3,
  name: "LocalPhish — On-Device Phishing Sentinel",
  description: "Privacy-first, on-device LLM phishing detection. No data leaves your browser.",
  version: pkg.version,
  minimum_chrome_version: "120",

  action: {
    default_title: "LocalPhish",
    default_popup: "src/popup/index.html",
    default_icon: {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png",
      "48": "icons/icon-48.png",
      "128": "icons/icon-128.png"
    }
  },

  icons: {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },

  options_page: "src/options/index.html",

  // MV3 default CSP for extension pages is "script-src 'self'; object-src
  // 'self';" — no WebAssembly. WebLLM needs WASM for the model runtime; the
  // standard MV3 unlock is 'wasm-unsafe-eval'. This applies to the offscreen
  // document where the LLM lives. We do NOT add 'unsafe-eval' (that's a
  // store-rejection risk and we don't need it).
  content_security_policy: {
    extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
  },

  background: {
    service_worker: "src/background/index.ts",
    type: "module"
  },

  content_scripts: [
    {
      matches: ["http://*/*", "https://*/*"],
      js: ["src/content/index.ts"],
      run_at: "document_idle",
      all_frames: false,
      world: "ISOLATED"
    }
  ],

  permissions: [
    "storage",
    "tabs",
    "scripting",
    "offscreen",
    "webNavigation",
    "alarms"
  ],

  host_permissions: ["http://*/*", "https://*/*"],

  web_accessible_resources: [
    {
      resources: ["src/offscreen/offscreen.html"],
      matches: ["<all_urls>"]
    },
    {
      // Pre-nav interstitial — tabs.update redirects the tab to this URL
      // when Stage 1 alone scores DANGEROUS. Must be web_accessible because
      // the navigation comes from the regular web (the address bar / link
      // the user clicked).
      resources: ["src/interstitial/index.html", "src/interstitial/*"],
      matches: ["<all_urls>"]
    }
  ]
});
