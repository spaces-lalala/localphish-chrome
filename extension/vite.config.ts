import { defineConfig } from "vite";
import { crx } from "@crxjs/vite-plugin";
import preact from "@preact/preset-vite";
import { resolve } from "node:path";
import manifest from "./manifest.config";

export default defineConfig({
  plugins: [preact(), crx({ manifest })],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src")
    }
  },
  build: {
    target: "esnext",
    sourcemap: true,
    rollupOptions: {
      input: {
        offscreen: resolve(__dirname, "src/offscreen/offscreen.html"),
        // Pre-nav interstitial page — extension navigates the tab to this
        // URL when Stage 1 alone scores >= DANGER_FLOOR. Not declared on
        // manifest.action / options_page so we must register it as a build
        // input explicitly for crxjs to emit + bundle the assets.
        interstitial: resolve(__dirname, "src/interstitial/index.html")
      }
    }
  },
  server: {
    port: 5173,
    strictPort: true,
    hmr: {
      port: 5173
    }
  }
});
