import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterEach, describe, expect, it } from "vitest";
import { BrokerDaemon } from "../src/daemon.js";
import type { RuntimePaths } from "../src/paths.js";

describe("MCP stdio integration", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
  });

  it("negotiates MCP, exposes the bounded tool set, and isolates a pending request", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tabgrant-mcp-test-"));
    const paths = testPaths(directory);
    const daemon = new BrokerDaemon(paths);
    await daemon.start();
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--import", "tsx", resolve("src/mcp-entry.ts")],
      cwd: resolve("."),
      env: {
        ...getDefaultEnvironment(),
        TABGRANT_HOME: directory,
        TABGRANT_CLIENT_ID: "codex-test",
        TABGRANT_DECLARED_MODEL_PROVIDER: "openai-test",
        TABGRANT_TASK_ID: "mcp-test-task",
      },
      stderr: "pipe",
      maxBufferSize: 1_048_576,
    });
    const client = new Client({ name: "tabgrant-test", version: "0.1.0" });
    cleanups.push(async () => {
      await client.close().catch(() => undefined);
      await daemon.stop().catch(() => undefined);
      await rm(directory, { recursive: true, force: true });
    });

    await client.connect(transport);
    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "browser_access_request",
      "browser_access_revoke",
      "browser_access_status",
      "browser_highlight",
      "browser_navigate",
      "browser_scroll",
      "browser_snapshot",
      "browser_tabs_list",
      "tabgrant_status",
    ]);

    const brokerStatus = await client.callTool({ name: "tabgrant_status", arguments: {} });
    expect(brokerStatus.isError).not.toBe(true);
    expect(toolJson(brokerStatus.content)).toMatchObject({ browserConnected: false });

    const access = await client.callTool({
      name: "browser_access_request",
      arguments: { reason: "MCP transport integration test", scopes: ["tab.metadata.read"] },
    });
    expect(access.isError).not.toBe(true);
    expect(toolJson(access.content)).toMatchObject({ status: "pending" });
  });
});

function testPaths(directory: string): RuntimePaths {
  return {
    baseDirectory: directory,
    runtimeDirectory: join(directory, "run"),
    socketPath: join(directory, "run", "broker.sock"),
    secretPath: join(directory, "broker.secret"),
    authoritySecretPath: join(directory, "authority.secret"),
    auditPath: join(directory, "audit.jsonl"),
    killSwitchPath: join(directory, "disabled.json"),
  };
}

function toolJson(content: Array<{ type: string; text?: string }>): Record<string, unknown> {
  const text = content.find((block) => block.type === "text")?.text;
  if (text === undefined) throw new Error("Expected an MCP text result.");
  return JSON.parse(text) as Record<string, unknown>;
}
