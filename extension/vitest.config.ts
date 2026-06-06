import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

// Standalone vitest config — avoids loading the @crxjs plugin, which
// expects a real browser-extension build context that the node test
// runner can't provide.
export default defineConfig({
  resolve: {
    alias: {
      "@": resolve(__dirname, "src")
    }
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"]
  }
});
