// Offscreen Document — persistent host for WebLLM / Transformers.js / WebGPU.
// Scaffold only: receives RPCs and echoes back. Real backends arrive in Week 14/15.

import type { RpcRequest, RpcResponse } from "@/types";

async function probeWebGPU(): Promise<{ available: boolean; adapter?: string }> {
  if (!("gpu" in navigator)) return { available: false };
  try {
    const adapter = await (navigator as Navigator & {
      gpu: { requestAdapter: () => Promise<GPUAdapter | null> };
    }).gpu.requestAdapter();
    if (!adapter) return { available: false };
    return { available: true, adapter: "ok" };
  } catch {
    return { available: false };
  }
}

chrome.runtime.onMessage.addListener(
  (msg: RpcRequest, _sender, sendResponse: (r: RpcResponse) => void) => {
    void (async () => {
      try {
        switch (msg.type) {
          case "ping": {
            const gpu = await probeWebGPU();
            sendResponse({ type: "pong", backend: gpu.available ? "webllm" : "rules-only" });
            return;
          }
          default:
            sendResponse({ type: "error", message: "offscreen: unhandled rpc" });
        }
      } catch (err) {
        sendResponse({ type: "error", message: (err as Error).message });
      }
    })();
    return true;
  }
);

console.log("[LocalPhish] Offscreen document loaded.");

// Minimal interface used above — kept here to avoid pulling @types/webgpu in scaffold.
type GPUAdapter = { limits: { maxBufferSize: number } };
