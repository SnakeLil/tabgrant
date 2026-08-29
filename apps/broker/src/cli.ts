#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { connectBroker } from "./client.js";
import { TABGRANT_VERSION } from "./constants.js";
import { runDaemon } from "./daemon.js";
import { runDoctor } from "./doctor.js";
import { BrowserChannelSchema, installNativeHost, uninstallNativeHost } from "./installer.js";
import { runMcpServer } from "./mcp.js";
import { runNativeHost } from "./native-host.js";
import { activateKillSwitch, clearKillSwitch } from "./kill-switch.js";
import { getRuntimePaths } from "./paths.js";

interface ParsedArguments {
  readonly command: string;
  readonly flags: Map<string, string | true>;
}

async function main(): Promise<void> {
  const parsed = parseArguments(process.argv.slice(2));
  switch (parsed.command) {
    case "daemon":
      await runDaemon();
      if (!parsed.flags.has("quiet")) {
        process.stderr.write("TabGrant broker is running. Press Ctrl-C to stop.\n");
      }
      return;
    case "mcp":
      await runMcpServer({
        clientId: requiredOption(parsed.flags, "client-id", process.env.TABGRANT_CLIENT_ID),
        declaredModelProvider: requiredOption(
          parsed.flags,
          "declared-model-provider",
          process.env.TABGRANT_DECLARED_MODEL_PROVIDER,
        ),
        taskId:
          optionalOption(parsed.flags, "task-id") ??
          process.env.TABGRANT_TASK_ID ??
          `mcp-${randomUUID()}`,
      });
      return;
    case "native-host":
      await runNativeHost();
      return;
    case "install": {
      const hostPath = optionalOption(parsed.flags, "host-path");
      const result = await installNativeHost({
        extensionId: requiredOption(parsed.flags, "extension-id"),
        browser: BrowserChannelSchema.parse(optionalOption(parsed.flags, "browser") ?? "chrome"),
        ...(hostPath === undefined ? {} : { hostPath }),
      });
      printJson({ ok: true, ...result });
      return;
    }
    case "uninstall": {
      const browser = BrowserChannelSchema.parse(
        optionalOption(parsed.flags, "browser") ?? "chrome",
      );
      printJson(await uninstallNativeHost(browser));
      return;
    }
    case "doctor": {
      const browser = BrowserChannelSchema.parse(
        optionalOption(parsed.flags, "browser") ?? "chrome",
      );
      const checks = await runDoctor(browser);
      printJson({ ok: checks.every((check) => check.ok), checks });
      if (checks.some((check) => !check.ok)) {
        process.exitCode = 1;
      }
      return;
    }
    case "status": {
      const client = await connectBroker({
        clientId: "tabgrant-cli",
        taskId: "cli",
      });
      try {
        printJson(await client.peer.request("broker.status", {}));
      } finally {
        client.peer.close();
      }
      return;
    }
    case "kill": {
      const paths = getRuntimePaths();
      await activateKillSwitch(paths.killSwitchPath);
      printJson({ ok: true, killed: true, persistent: true });
      return;
    }
    case "enable":
      if (
        parsed.flags.get("confirm") !== true ||
        process.stdin.isTTY !== true ||
        process.stderr.isTTY !== true
      ) {
        throw new Error(
          "Re-enabling TabGrant restores browser access. Re-run interactively in a local terminal with `tabgrant enable --confirm`.",
        );
      }
      printJson({ ok: true, ...(await clearKillSwitch(getRuntimePaths().killSwitchPath)) });
      return;
    case "version":
    case "--version":
    case "-v":
      process.stdout.write(`${TABGRANT_VERSION}\n`);
      return;
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(helpText());
      return;
    default:
      throw new Error(`Unknown command: ${parsed.command}\n\n${helpText()}`);
  }
}

function parseArguments(values: string[]): ParsedArguments {
  const command = values[0] ?? "help";
  const flags = new Map<string, string | true>();
  for (let index = 1; index < values.length; index += 1) {
    const current = values[index];
    if (current === undefined || !current.startsWith("--")) {
      throw new Error(`Unexpected argument: ${current ?? ""}`);
    }
    const key = current.slice(2);
    const next = values[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(key, next);
      index += 1;
    } else {
      flags.set(key, true);
    }
  }
  return { command, flags };
}

function optionalOption(flags: Map<string, string | true>, name: string): string | undefined {
  const value = flags.get(name);
  if (value === undefined) {
    return undefined;
  }
  if (value === true) {
    throw new Error(`--${name} requires a value.`);
  }
  return value;
}

function requiredOption(
  flags: Map<string, string | true>,
  name: string,
  fallback?: string,
): string {
  const value = optionalOption(flags, name) ?? fallback;
  if (value === undefined || value.trim() === "") {
    throw new Error(`Missing required option: --${name}`);
  }
  return value;
}

function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function helpText(): string {
  return `TabGrant ${TABGRANT_VERSION} — user-granted browser capabilities for AI agents

Usage:
  tabgrant daemon [--quiet]
  tabgrant mcp --client-id <id> --declared-model-provider <label> [--task-id <id>]
  tabgrant install --extension-id <id> [--browser chrome|chrome-for-testing|chromium|edge|brave]
  tabgrant uninstall [--browser chrome|chrome-for-testing|chromium|edge|brave]
  tabgrant doctor [--browser chrome|chrome-for-testing|chromium|edge|brave]
  tabgrant status
  tabgrant kill
  tabgrant enable --confirm
  tabgrant version

The MCP server never receives cookies, passwords, storage tokens, arbitrary JavaScript, or CDP access.
`;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`TabGrant: ${message}\n`);
  process.exitCode = 1;
});
