import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    cli: "src/cli.ts",
    "mcp-entry": "src/mcp-entry.ts",
    "native-host-entry": "src/native-host-entry.ts",
  },
  format: ["esm"],
  platform: "node",
  target: "node20",
  dts: true,
  sourcemap: true,
  clean: true,
  noExternal: ["@tabgrant/protocol", "@tabgrant/policy"],
});
