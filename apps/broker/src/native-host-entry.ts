#!/usr/bin/env node
import { runNativeHost } from "./native-host.js";

runNativeHost().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`TabGrant native host failed: ${message}\n`);
  process.exitCode = 1;
});
