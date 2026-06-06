#!/usr/bin/env node
// LocalPhish — pack dist/ into a .zip for distribution.
//
// Chrome Web Store accepts a plain zip; for the demo we ship a single-file
// artefact users can unzip + load unpacked. We use PowerShell's
// Compress-Archive on Windows and the `zip` binary on Unix so we don't
// inherit a Node deps subtree just for archiving.
//
// Output: dist/localphish-v<version>.zip alongside the unpacked dist/.

import { stat, readFile, rm } from "node:fs/promises";
import { resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = __dirname;
const distDir = resolve(root, "dist");

async function main() {
  try {
    await stat(distDir);
  } catch {
    console.error(`✗ ${distDir} not found — run 'npm run build' first`);
    process.exit(2);
  }

  const pkg = JSON.parse(await readFile(resolve(root, "package.json"), "utf-8"));
  const version = pkg.version || "0.0.0";
  const outPath = resolve(distDir, `localphish-v${version}.zip`);

  // Drop any previous archive so Compress-Archive doesn't refuse.
  await rm(outPath, { force: true });

  const isWindows = process.platform === "win32";
  let result;
  if (isWindows) {
    // PowerShell Compress-Archive — bundled with Windows 10+.
    const psCmd = `Compress-Archive -Path "${distDir}\\*" -DestinationPath "${outPath}" -CompressionLevel Optimal`;
    result = spawnSync("powershell.exe", ["-NoProfile", "-Command", psCmd], { encoding: "utf-8" });
  } else {
    // Unix: rely on the `zip` binary being on PATH.
    result = spawnSync("zip", ["-r", "-9", outPath, "."], { cwd: distDir, encoding: "utf-8" });
  }

  if (result.status !== 0) {
    console.error("✗ archive command failed:", result.stderr || result.stdout || "(no output)");
    process.exit(result.status ?? 1);
  }

  const bytes = (await stat(outPath)).size;
  console.log(`✓ packed ${relative(root, outPath)} (${(bytes / 1024).toFixed(1)} KB)`);
  console.log(`\nUsers can install by:`);
  console.log(`  1. unzip ${relative(root, outPath)}`);
  console.log(`  2. open chrome://extensions, enable Developer Mode`);
  console.log(`  3. click "Load unpacked", pick the unzipped folder`);
  console.log(`\nFor a true signed .crx (re-publishable), run:`);
  console.log(`  chrome.exe --pack-extension="${distDir}"`);
  console.log(`  → emits dist.crx + dist.pem (keep .pem private for re-signing)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
