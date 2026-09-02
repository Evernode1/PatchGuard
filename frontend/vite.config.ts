import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

// base "./" so the static build works on Cloudflare Pages and any static host.
// web3 deps (genlayer-js, Privy) expect Node globals in the browser, so we
// polyfill Buffer/process and alias `global` to `globalThis`.
export default defineConfig({
  base: "./",
  plugins: [
    react(),
    nodePolyfills({
      globals: { Buffer: true, global: true, process: true },
    }),
  ],
  define: {
    global: "globalThis",
  },
  build: {
    target: "es2020",
    outDir: "dist",
    sourcemap: false,
  },
});
