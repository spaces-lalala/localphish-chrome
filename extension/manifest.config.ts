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
    default_popup: "src/popup/index.html"
  },

  options_page: "src/options/index.html",

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
    }
  ]
  // icons intentionally omitted in scaffold; Chrome falls back to default.
});
