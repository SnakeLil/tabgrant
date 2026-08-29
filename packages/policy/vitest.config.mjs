import { fileURLToPath, URL } from "node:url";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@tabgrant/protocol": fileURLToPath(new URL("../protocol/src/index.ts", import.meta.url)),
    },
  },
});
