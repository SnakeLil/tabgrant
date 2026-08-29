# TabGrant

> User-granted, local-first access to real browser sessions for AI agents.

[![Developer Preview](https://img.shields.io/badge/status-developer%20preview-orange)](./ROADMAP.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

TabGrant connects an MCP client to a tab in the user's existing Chromium-based
browser without copying the browser profile or exposing every open tab. The agent
requests access, the user grants the current tab from the extension popup, and a
short-lived lease limits what that exact client task can do.

## Developer Preview

The source checkout is usable for development and evaluation on macOS and Linux.
It currently includes:

- a local broker daemon using a Unix-domain socket on macOS/Linux or a named pipe
  on Windows;
- a Manifest V3 extension and Chrome Native Messaging host;
- explicit grant, visible active state, and revoke controls for one current tab;
- nine MCP tools for grant lifecycle, bounded page reading, highlighting,
  scrolling, and same-origin navigation;
- per-connection random broker sessions: a second connection with the same
  client/task identity cannot see or reuse the first connection's lease, and an
  agent disconnect revokes its pending requests and leases;
- browser-key pairing: every shared-HMAC hello is initially an agent, while the
  extension must pass broker-owned macOS/Linux user-presence approval and prove a
  non-extractable P-256 key before receiving browser authority;
- document-, origin-, scope-, expiry-, idle-, use-, concurrency-, rate-, and
  UTF-8 output-bound leases;
- domain-separated IPC, capability, and audit keys;
- redacted, HMAC-authenticated audit segments plus an ordered signed manifest that
  are fully verified at startup;
- a persistent kill marker that blocks broker restart until a local
  `tabgrant enable --confirm`;
- a security gate that rejects broad extension permissions and forbidden browser
  authorities.

This is not a stable or audited release. There is no npm or browser-store release
yet, the protocol may change, and real-browser/client compatibility has not been
certified. Use a disposable browser profile and synthetic or non-sensitive
accounts. See [Current verification boundary](#current-verification-boundary).

## Quickstart from source

### 1. Build TabGrant

Requirements: macOS or Linux, Node.js 20.19.0 or newer, Corepack, and a current
Chromium-based browser. Automated validation currently targets Chrome for Testing
152.0.7977.64; other browser versions and channels are not yet certified.

```bash
git clone https://github.com/SnakeLil/tabgrant.git
cd tabgrant
corepack enable
pnpm install --frozen-lockfile
pnpm build
```

The extension is built at `apps/extension/dist`. The broker CLI is built at
`apps/broker/dist/cli.js`.

### 2. Load the extension

Open the extensions page for your browser, enable Developer mode, choose **Load
unpacked**, and select the absolute path to `apps/extension/dist`.

| Browser            | Extensions page       | Installer channel    |
| ------------------ | --------------------- | -------------------- |
| Chrome             | `chrome://extensions` | `chrome`             |
| Chrome for Testing | `chrome://extensions` | `chrome-for-testing` |
| Chromium           | `chrome://extensions` | `chromium`           |
| Edge               | `edge://extensions`   | `edge`               |
| Brave              | `brave://extensions`  | `brave`              |

The `chrome-for-testing` channel is primarily for disposable automated testing.
[Chrome for Testing 146 and newer use a Native Messaging host directory distinct
from branded Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging);
the installer implements that separate mapping.

Copy the 32-character extension ID shown on the extensions page.

### 3. Install the native messaging host

Set the channel to the browser you loaded in step 2:

```bash
node apps/broker/dist/cli.js install \
  --extension-id YOUR_32_CHARACTER_EXTENSION_ID \
  --browser chrome
```

Installation is create-only and refuses to overwrite any existing manifest. To
change the extension ID, native-host path, or channel manifest, first run the
matching `uninstall` command and inspect its result, then install again. A missing
manifest makes `uninstall` an idempotent no-op.

Reload the extension. Its popup creates a non-extractable P-256 signing key in
IndexedDB and shows a session-only, 160-bit pairing code. Select **Pair this extension**.
The broker opens its production user-presence UI: `osascript` on macOS or
`zenity` on Linux. Compare the full code, extension ID, browser-instance ID, and
key fingerprint shown by the popup/system prompt, then approve in the OS prompt.
Missing UI tooling, cancellation, or timeout denies pairing. Production pairing
currently fails closed on Windows and is unsupported there.

The code is removed from extension session storage after every attempt, whether
approved, denied, or timed out; reopening the unpaired popup produces a new code.
The broker handles the code only for the live prompt and persists no pairing
state before proof succeeds. Dynamic prompt data is sent to `osascript` or
`zenity` over stdin, not exposed in process argv. After approval, the broker creates a
fresh 30-second challenge on that same connection. Only a signature from the
extension's non-extractable key persists `browser-pairing.json` with owner-only
`0600` permissions on supported Unix platforms and upgrades the connection from
agent to browser authority. A failed signature consumes the challenge and leaves
no pairing record. The extension serializes startup authentication and popup
pairing on the exact Native Messaging port. The broker allows one authentication
transition or live challenge per connection; competing starts/pairs fail busy,
and an unknown challenge ID cannot consume the valid challenge. The native host
only relays messages and never receives the
private key. The native host and MCP adapter can start the broker automatically.

Check the persistent kill state, local secrets, native-host manifest, and broker
IPC endpoint:

```bash
node apps/broker/dist/cli.js doctor --browser chrome
```

`doctor` checks local installation state; it is not a real-browser end-to-end
test.

### 4. Connect Codex through MCP

Codex supports local STDIO MCP servers. Add this source build using an absolute
path:

```bash
codex mcp add tabgrant -- \
  node /ABSOLUTE/PATH/TO/tabgrant/apps/broker/dist/cli.js \
  mcp --client-id codex --declared-model-provider openai
```

Then run `codex mcp list`; in an interactive Codex session, use `/mcp` to inspect
the connection. Codex stores MCP configuration in `~/.codex/config.toml`, or in
project-scoped `.codex/config.toml` for a trusted project. The equivalent manual
configuration is:

```toml
[mcp_servers.tabgrant]
command = "node"
args = [
  "/ABSOLUTE/PATH/TO/tabgrant/apps/broker/dist/cli.js",
  "mcp",
  "--client-id",
  "codex",
  "--declared-model-provider",
  "openai",
]
startup_timeout_sec = 20
tool_timeout_sec = 60
default_tools_approval_mode = "prompt"
```

`declared-model-provider` is an unverified label supplied by the MCP client. It is
shown to the user as **Client-declared model provider**; it is not a credential, an
attestation, or a network policy. TabGrant cannot prove which model or service the
client actually uses and cannot constrain where the client sends returned page
data. Do not put API keys or browser credentials in this configuration.
See the [official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
for current Codex configuration behavior.

Other local agents can use the same STDIO command when their MCP client can
launch a local process; choose a stable `client-id` for that client and a fresh
`task-id` for each task. Hosted ChatGPT Work chats do not read local Codex MCP
configuration and instead use plugins with remote MCP tools. TabGrant does not
ship a remote broker in this Developer Preview because that would introduce a
different authority and data-egress boundary.

### 5. Grant a tab

1. Ask the agent to call `browser_access_request` with a concrete reason.
2. Open the HTTPS page, or loopback HTTP development page, you want to share.
3. Open the TabGrant extension and review the client, task, reason, scopes, and
   **client-declared** model-provider label. Treat that label as a client claim, not a
   verified destination.
4. Select **Grant current tab**.
5. The agent calls `browser_access_status` or `browser_tabs_list` to obtain the
   lease ID, then uses the bounded browser tools.
6. Revoke from the extension or with `browser_access_revoke` when finished.

Only one grant can be active in the extension at a time. Granting another tab
replaces the current grant.

## Current MCP tools

| Tool                     | Current behavior                                                          |
| ------------------------ | ------------------------------------------------------------------------- |
| `tabgrant_status`        | Reports broker/browser connection state; never enumerates tabs.           |
| `browser_access_request` | Creates a five-minute pending request for extension approval.             |
| `browser_access_status`  | Lists requests and leases owned by this exact MCP client task.            |
| `browser_access_revoke`  | Revokes a lease owned by this task.                                       |
| `browser_tabs_list`      | Lists only active, explicitly granted tabs, with query/fragment removed.  |
| `browser_snapshot`       | Returns up to 500 visible accessibility-style nodes and short-lived refs. |
| `browser_highlight`      | Highlights one ref from the current snapshot for 1.5 seconds.             |
| `browser_scroll`         | Scrolls the granted document by at most 2,000 px per call.                |
| `browser_navigate`       | Starts same-origin HTTP(S) navigation, then revokes the document lease.   |

Snapshots require both `page.a11y.read` and explicit `data.egress.model` scope.
Each serialized snapshot result is limited to 256,000 UTF-8 bytes, and all
successfully returned snapshots share a 1,000,000-byte UTF-8 lease budget.
Element refs are bound to the current document and snapshot epoch; take a new
snapshot after the page changes.

## Lease behavior

- Default and maximum lifetime: 10 minutes.
- Idle timeout: 2 minutes.
- Maximum admitted commands: 250.
- Concurrency: at most 2 commands in flight per lease.
- Rate: at most 30 admitted commands per fixed one-minute window.
- Snapshot output: at most 256,000 UTF-8 bytes per result and 1,000,000 UTF-8
  bytes cumulatively per lease.
- Supported pages: HTTPS and loopback HTTP only.
- The Chrome Web Store origins, browser-internal pages, file URLs, and credentialed
  URLs are not grantable.
- Tab close, document change, browser disconnect, agent/MCP disconnect, expiry,
  revoke, or activation of the persistent kill marker invalidates the lease.
- Lease ownership includes an internal random broker-session ID. Reconnecting with
  the same public client/task identity does not recover the old lease.
- Same-origin navigation is allowed only with its explicit scope and replaces the
  document, so a fresh grant is required afterward.
- `tabgrant kill` writes the private persistent marker directly; there is no
  `broker.kill` RPC. A running broker notices the marker, revokes active leases,
  closes connections, and stops. Autostart remains blocked until
  `tabgrant enable --confirm` is run in a local terminal.

## Broker-wide resource bounds

- At most 8 pending access requests per agent session and 100 globally.
- `access.request` admits at most 20 calls per session and 120 globally per fixed
  one-minute window.
- In-memory state retains at most 512 access-request records and 200 lease records;
  terminal records are eligible for pruning after 15 minutes.
- Each IPC connection admits at most 240 inbound requests per fixed one-minute
  window, before dispatch to a handler.
- Audit storage uses at most four 1 MiB segments (4 MiB total), plus a bounded
  owner-only `audit.jsonl.manifest.json`. It rotates at 30 days or before a write
  would exceed the active segment. Each segment has its own record HMAC chain;
  the manifest HMAC binds the exact ordered filenames, byte lengths, record
  counts, SHA-256 digests, and first/last record hashes.

## What TabGrant does not currently do

- click buttons, fill forms, submit, send, publish, purchase, delete, or change
  account settings;
- take screenshots or return arbitrary/full DOM, page source, or network bodies;
- read cookies, passwords, authentication tokens, or raw browser storage;
- execute arbitrary JavaScript or expose Chrome DevTools Protocol/debugger access;
- enumerate ungranted tabs, browsing history, other profiles, or other clients'
  leases;
- navigate across origins or keep a grant through navigation;
- support simultaneous multi-tab grants in one extension instance;
- support Firefox, Safari, Windows native-host installation, remote brokers, or
  hosted/cloud agents;
- verify the client's declared model-provider label or prevent an authorized MCP
  client from forwarding returned page data elsewhere;
- protect against arbitrary native code already running as the same OS user, or a
  fully compromised operating system or browser;
- prevent same-UID code from modifying the broker socket/process/private files or
  consuming the bounded OS-pairing prompt budget to delay legitimate pairing;
- bypass CAPTCHAs, anti-bot systems, access controls, or platform policies.

The protocol and policy packages model future actions, including higher-risk
actions, but those are not exposed by the current MCP server or extension.

## Current verification boundary

As of 2026-08-30, this checkout passes:

- `pnpm check`, including formatting, lint, type checking, 109 automated tests
  (63 broker, 20 extension, 8 protocol, and 18 policy), and the manifest/source
  security gate;
- `pnpm build`, producing the extension and three broker executables;
- `pnpm pack:smoke`, which installs the packed `tabgrant@0.1.0` tarball and runs
  its CLI;
- `pnpm e2e:chrome:ci` against Chrome for Testing 152.0.7977.64 after installing
  the disposable browser with `pnpm e2e:chrome:install`.

Automated coverage includes a real MCP STDIO SDK client connected to a spawned
MCP subprocess. Broker unit/integration tests use an in-process mock browser. The
separate Chrome for Testing CI E2E completes extension-key pairing, broker
startup, MCP, Native Messaging, popup rendering and grant, a synthetic
loopback-page snapshot, highlight, scroll, revoke, password-value redaction, and
confirmation that the audit contains no page or pairing content. CI imports the
broker source and injects a test-only approver that accepts only the exact
extension ID, browser-instance ID, pairing code, and key fingerprint discovered
by that run. Production broker startup does not expose that injection path.

The E2E runner uses only a disposable browser profile and writes its Native
Messaging manifest inside that profile; it does not read, create, replace, or
remove a global browser manifest. It copies the built extension to a temporary
directory and adds only `http://127.0.0.1/*` as a test-only host permission. The
production manifest continues to declare no `host_permissions`, and the security
gate rejects adding one. On GitHub's Ubuntu runner, only the dedicated
`e2e:chrome:ci:linux-no-sandbox` command adds Chrome's `--no-sandbox` flag to
work around the runner's restricted user-namespace environment. The harness
rejects that flag unless it is an explicit Linux `CI=true` run using its
disposable profile; the default and manual commands retain Chrome's sandbox.
This CI exception is not a production configuration or evidence for a sandboxed
browser deployment. The CI test opens and operates the popup programmatically.
Because it bypasses the production `osascript`/`zenity`
approver and does not use a real toolbar gesture, it proves neither OS
user-presence UI nor production `activeTab` acquisition. [Branded Chrome removed command-line unpacked-extension loading in
Chrome 137](https://developer.chrome.com/blog/extension-news-june-2025), so
repeatable automation uses Chrome for Testing or Chromium rather than claiming
branded-Chrome coverage. This evidence does **not** establish:

- a live Codex-to-Native-Messaging-to-page workflow;
- the production `activeTab` toolbar-gesture path;
- manual compatibility with each Chrome, Chromium, Edge, or Brave release;
- browser-store packaging or installation;
- production security, external audit results, or resistance to a compromised
  browser/operating system.

`pnpm e2e:chrome:manual` is the interactive harness intended to start the
production broker, show the real macOS/Linux pairing prompt, and wait for a human
toolbar click plus **Grant current tab**. That OS/UI path is still being debugged;
no successful manual evidence is claimed yet. It requires a graphical local
session, and Linux additionally requires `zenity`.

Reports from disposable-profile testing are welcome through the compatibility
issue form.

## CLI operations

```text
tabgrant daemon [--quiet]
tabgrant mcp --client-id <id> --declared-model-provider <provider> [--task-id <id>]
tabgrant install --extension-id <id> [--browser chrome|chrome-for-testing|chromium|edge|brave]
tabgrant uninstall [--browser chrome|chrome-for-testing|chromium|edge|brave]
tabgrant doctor [--browser chrome|chrome-for-testing|chromium|edge|brave]
tabgrant status
tabgrant kill
tabgrant enable --confirm
tabgrant version
```

From a source build, replace `tabgrant` with
`node apps/broker/dist/cli.js`. Runtime state defaults to
`~/Library/Application Support/TabGrant` on macOS and
`$XDG_STATE_HOME/tabgrant` on Linux when `XDG_STATE_HOME` is set, otherwise
`~/.local/state/tabgrant`. Set `TABGRANT_HOME` to use a separate absolute state
directory for testing.

Broker IPC is a filesystem Unix-domain socket on macOS/Linux and a Windows named
pipe, not a TCP loopback listener. Browser Native Messaging installation is still
implemented only for macOS and Linux.

## Architecture and project policies

- [Architecture](./docs/ARCHITECTURE.md)
- [OS user-presence pairing decision](./docs/adr/0002-os-user-presence-browser-pairing.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [Security architecture](./docs/SECURITY_ARCHITECTURE.md)
- [Security policy](./SECURITY.md)
- [Privacy](./PRIVACY.md)
- [Contributing](./CONTRIBUTING.md)
- [Support](./SUPPORT.md)
- [Roadmap](./ROADMAP.md)
- [Governance](./GOVERNANCE.md)

## License

Licensed under the [Apache License 2.0](./LICENSE).
