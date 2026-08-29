import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { connectBrokerWithAutostart } from "./autostart.js";
import { IMPLEMENTED_SCOPES, TABGRANT_VERSION } from "./constants.js";
import { BrokerRpcError } from "./wire.js";

export interface McpOptions {
  readonly clientId: string;
  readonly taskId?: string;
  readonly declaredModelProvider: string;
}

export async function runMcpServer(options: McpOptions): Promise<void> {
  const taskId = options.taskId ?? `mcp-${randomUUID()}`;
  const broker = await connectBrokerWithAutostart({
    clientId: options.clientId,
    taskId,
  });
  const server = new McpServer({ name: "tabgrant", version: TABGRANT_VERSION });

  const call = async (method: string, params: unknown): Promise<CallToolResult> => {
    try {
      return textResult(await broker.peer.request(method, params));
    } catch (error) {
      const safe = safeToolError(error);
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify(safe) }],
      };
    }
  };

  server.registerTool(
    "tabgrant_status",
    {
      title: "TabGrant status",
      description:
        "Check the local broker and whether a browser extension is connected. Does not enumerate browser tabs.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => call("broker.status", {}),
  );

  server.registerTool(
    "browser_access_request",
    {
      title: "Request access to a browser tab",
      description:
        "Ask the user to release current-tab data to this local client. The user must approve in the TabGrant extension; the displayed model provider is client-declared, not network-enforced.",
      inputSchema: {
        reason: z
          .string()
          .min(1)
          .max(240)
          .describe("A concrete, user-readable reason for needing this tab."),
        scopes: z
          .array(z.enum(IMPLEMENTED_SCOPES))
          .min(1)
          .max(IMPLEMENTED_SCOPES.length)
          .optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ reason, scopes }) =>
      call("access.request", {
        reason,
        scopes: scopes ?? [
          "tab.metadata.read",
          "page.a11y.read",
          "page.element.inspect",
          "page.scroll",
          "page.highlight",
          "data.egress.model",
        ],
        declaredModelProvider: options.declaredModelProvider,
      }),
  );

  server.registerTool(
    "browser_access_status",
    {
      title: "Browser access status",
      description: "List only access requests and leases owned by this exact MCP client task.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => call("access.status", {}),
  );

  server.registerTool(
    "browser_access_revoke",
    {
      title: "Revoke browser access",
      description: "Immediately revoke one tab lease owned by this task.",
      inputSchema: { lease_id: z.string().uuid() },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    async ({ lease_id }) => call("access.revoke", { leaseId: lease_id }),
  );

  server.registerTool(
    "browser_tabs_list",
    {
      title: "List granted tabs",
      description:
        "List only active tab leases explicitly granted to this task. Never lists ungranted browser tabs or history.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    async () => call("browser.tabs.list", {}),
  );

  server.registerTool(
    "browser_snapshot",
    {
      title: "Read a granted tab",
      description:
        "Release a minimized accessibility-style snapshot to this local MCP connection. Requires page-read and data-release scopes; TabGrant cannot enforce the client's later network destination.",
      inputSchema: {
        lease_id: z.string().uuid(),
        max_nodes: z.number().int().min(1).max(500).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
    },
    async ({ lease_id, max_nodes }) =>
      call("browser.snapshot", { leaseId: lease_id, maxNodes: max_nodes ?? 200 }),
  );

  server.registerTool(
    "browser_highlight",
    {
      title: "Highlight a page element",
      description:
        "Visually highlight a short-lived element reference so the user can verify the target.",
      inputSchema: {
        lease_id: z.string().uuid(),
        ref: z.string().min(1).max(64),
        epoch: z.number().int().nonnegative(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ lease_id, ref, epoch }) =>
      call("browser.highlight", { leaseId: lease_id, ref, epoch }),
  );

  server.registerTool(
    "browser_scroll",
    {
      title: "Scroll a granted tab",
      description: "Scroll the granted document without clicking, submitting, or changing origin.",
      inputSchema: {
        lease_id: z.string().uuid(),
        delta_y: z.number().int().min(-2_000).max(2_000),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async ({ lease_id, delta_y }) => call("browser.scroll", { leaseId: lease_id, deltaY: delta_y }),
  );

  server.registerTool(
    "browser_navigate",
    {
      title: "Navigate within the granted origin",
      description:
        "Navigate to an HTTP(S) URL on the exact granted origin. Document replacement revokes the lease and requires a new user grant.",
      inputSchema: { lease_id: z.string().uuid(), url: z.string().url().max(2_048) },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async ({ lease_id, url }) => call("browser.navigate", { leaseId: lease_id, url }),
  );

  const transport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: 1_048_576,
  });
  process.stdin.once("close", () => broker.socket.destroy());
  await server.connect(transport);
}

function textResult(value: unknown): {
  content: [{ type: "text"; text: string }];
} {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function safeToolError(error: unknown): { code: string; message: string } {
  if (error instanceof BrokerRpcError) {
    return { code: error.code, message: error.message };
  }
  return {
    code: "BROKER_ERROR",
    message: error instanceof Error ? error.message : "The TabGrant request failed.",
  };
}
