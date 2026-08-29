import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const workspaceRoot = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@tabgrant/policy": `${workspaceRoot}/packages/policy/src/index.ts`,
      "@tabgrant/protocol": `${workspaceRoot}/packages/protocol/src/index.ts`,
    },
  },
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
    },
  },
});
