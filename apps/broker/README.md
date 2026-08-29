# `tabgrant`

The TabGrant broker package contains three executables:

| Executable             | Purpose                                                 |
| ---------------------- | ------------------------------------------------------- |
| `tabgrant`             | Install, diagnose, run, inspect, or stop the broker.    |
| `tabgrant-mcp`         | STDIO MCP adapter; starts the broker when necessary.    |
| `tabgrant-native-host` | Chromium Native Messaging bridge used by the extension. |

TabGrant is a Developer Preview. The package tarball passes a local installation
smoke test, but it is not yet published to npm. Use the repository source build
until a release is listed on the project page.

## Run from a source checkout

From the repository root:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
node apps/broker/dist/cli.js version
```

In the commands below, an installed `tabgrant` binary can replace
`node apps/broker/dist/cli.js` after a public package exists.

## CLI

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

- `install` creates a browser-specific Native Messaging manifest restricted to
  the exact 32-character extension ID. It is create-only and refuses to overwrite
  an existing path; it does not create the broker secret.
- `doctor` checks the persistent kill state, IPC and authority secrets, selected
  browser manifest, and broker IPC endpoint.
- `status` reports broker and extension connection state without enumerating tabs.
- `kill` writes an owner-only persistent disabled marker directly; there is no
  `broker.kill` RPC. The running broker's marker monitor then revokes current
  leases, closes connections, and stops it. Native-host and MCP autostart remain
  blocked afterward.
- `enable --confirm` is the explicit local action that removes the kill marker and
  allows the broker to start again.
- `uninstall` removes only the TabGrant-owned native-host manifest for the selected
  browser. It pins and rechecks the inspected inode and bytes, refuses to remove a
  concurrently replaced manifest, and is idempotent when absent. It does not
  remove the browser extension or runtime state. Reinstallation with changed
  values requires uninstall first.
- Browser pairing is initiated only by the extension popup. The production broker
  owns the macOS `osascript` or Linux `zenity` approval prompt; there is no CLI
  pairing command.

## Browser installation paths

The installer currently supports macOS and Linux:

| Channel              | macOS browser directory                                     | Linux browser directory                                                                           |
| -------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `chrome`             | `~/Library/Application Support/Google/Chrome`               | `$XDG_CONFIG_HOME/google-chrome`, otherwise `~/.config/google-chrome`                             |
| `chrome-for-testing` | `~/Library/Application Support/Google/ChromeForTesting`     | `$XDG_CONFIG_HOME/google-chrome-for-testing`, otherwise `~/.config/google-chrome-for-testing`     |
| `chromium`           | `~/Library/Application Support/Chromium`                    | `$XDG_CONFIG_HOME/chromium`, otherwise `~/.config/chromium`                                       |
| `edge`               | `~/Library/Application Support/Microsoft Edge`              | `$XDG_CONFIG_HOME/microsoft-edge`, otherwise `~/.config/microsoft-edge`                           |
| `brave`              | `~/Library/Application Support/BraveSoftware/Brave-Browser` | `$XDG_CONFIG_HOME/BraveSoftware/Brave-Browser`, otherwise `~/.config/BraveSoftware/Brave-Browser` |

The manifest is written under `NativeMessagingHosts/io.tabgrant.bridge.json` in
that directory. [Chrome for Testing 146 and newer use the independent
`ChromeForTesting`/`google-chrome-for-testing` location](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging);
this channel is primarily for disposable automated testing. The source implements
all five mappings, but real-browser compatibility for every OS/channel combination
is not yet certified.

Example:

```bash
node apps/broker/dist/cli.js install \
  --extension-id YOUR_32_CHARACTER_EXTENSION_ID \
  --browser brave
node apps/broker/dist/cli.js doctor --browser brave
```

Windows installation is not implemented. The broker's Windows named-pipe
abstraction does not make browser pairing available: the production approver
fails closed on Windows, so Windows browser authority is currently unsupported.

[Branded Chrome removed the `--load-extension` flag in Chrome
137](https://developer.chrome.com/blog/extension-news-june-2025). That restriction
affects automated command-line loading, not the documented manual Developer-mode
installation. Use Chrome for Testing or Chromium for the repository E2E runner;
do not treat that as branded-Chrome compatibility evidence.

## MCP configuration

The MCP process requires a stable client identity and an explicit model-egress
provider declaration. A task ID is generated per process when omitted.

```bash
node /ABSOLUTE/PATH/TO/tabgrant/apps/broker/dist/cli.js \
  mcp --client-id codex --declared-model-provider openai
```

For Codex:

```bash
codex mcp add tabgrant -- \
  node /ABSOLUTE/PATH/TO/tabgrant/apps/broker/dist/cli.js \
  mcp --client-id codex --declared-model-provider openai
```

Equivalent `config.toml`:

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
default_tools_approval_mode = "prompt"
```

Any local agent whose MCP client can launch a STDIO process can use the same
broker command with its own stable `client-id` and per-task `task-id`. Hosted
ChatGPT Work chats do not consume local Codex MCP configuration; TabGrant does
not currently expose a remote broker or plugin transport.

Alternatively, invoke `dist/mcp-entry.js` and provide
`TABGRANT_CLIENT_ID` and `TABGRANT_DECLARED_MODEL_PROVIDER` as environment
variables. `TABGRANT_TASK_ID` is optional.

The `declared-model-provider`/`declaredModelProvider` value is an unverified
client claim shown by the popup as **Client-declared model provider**. It is neither a
credential nor an attestation. TabGrant uses it to make the requested disclosure
visible and bind the declared label into capability metadata, but cannot inspect
or constrain the MCP client's downstream network destinations.

Every accepted agent connection also receives a broker-internal random session
ID. Requests and leases belong to that connection, not merely its public
client/task strings. Agent disconnect revokes its pending requests and leases; a
second connection presenting the same public identity cannot recover them.

Every shared-HMAC hello is normalized to agent authority, even when it claims the
`browser` role. The extension stores a non-extractable P-256 private key in
IndexedDB. Its popup shows a session-only 160-bit code and initiates one pairing
attempt. The broker displays the full code, extension ID, browser-instance ID, and
key fingerprint in `osascript` on macOS or `zenity` on Linux; dynamic prompt
data is delivered over stdin rather than process argv. Missing UI tooling,
cancellation, timeout, and Windows all deny pairing.

Every attempt removes the displayed code from extension session storage, so an
unpaired popup generates a new code. The broker persists no pairing state before
proof succeeds. Approval creates a fresh 30-second challenge on the same
connection. Only a valid signature from the non-extractable extension key writes
the paired public key/fingerprint to owner-only `browser-pairing.json` and upgrades
that connection to browser authority. A failed signature consumes the challenge
without creating the pairing file. Startup authentication and popup pairing are
serialized on the exact Native Messaging port. A broker connection permits one
authentication transition or live challenge; competing starts/pairs fail busy,
and an unknown challenge ID leaves the valid challenge intact. Arbitrary same-UID code that can manipulate
local files, sockets, processes, or the browser remains out of scope.

## Runtime state

| State               | macOS default                            | Linux default                                                                |
| ------------------- | ---------------------------------------- | ---------------------------------------------------------------------------- |
| Base directory      | `~/Library/Application Support/TabGrant` | `$XDG_STATE_HOME/tabgrant`, or `~/.local/state/tabgrant`                     |
| IPC secret          | `broker.secret` under the base           | Same                                                                         |
| Authority root      | `authority.secret` under the base        | Same                                                                         |
| Audit segment       | `audit.jsonl` under the base             | Same                                                                         |
| Retained audit      | `audit.jsonl.1` through `.3`             | Same                                                                         |
| Audit inventory     | `audit.jsonl.manifest.json`              | Same                                                                         |
| Browser pairing     | `browser-pairing.json` under the base    | Same                                                                         |
| Persistent kill     | `disabled.json` under the base           | Same                                                                         |
| Broker IPC endpoint | `run/broker.sock` under the base         | `$XDG_RUNTIME_DIR/tabgrant/broker.sock`, or `run/broker.sock` under the base |

Set `TABGRANT_HOME` to an absolute path to isolate state for development tests.
IPC uses a filesystem Unix-domain socket on macOS/Linux and a named pipe on
Windows, not TCP or a loopback port. Browser Native Messaging installation is
still implemented only for macOS and Linux. Secret, marker, manifest, audit, and
socket files are created with owner-only permissions on supported Unix platforms.

Audit entries contain event/outcome metadata, client/task/lease identifiers when
relevant, origin, method, reason code, timestamps, and HMAC links. Each segment has
an independent record chain. An HMAC-SHA256 manifest binds the ordered filenames,
creation times, byte lengths, record counts, complete-file SHA-256 digests, and
first/last record hashes. Startup fails closed on a missing or stale manifest,
whole-segment deletion or reordering, complete-tail removal, malformed or modified
records, permissive files, symlinks, and oversized data. A segment is capped at 1
MiB and rotates 30 days after its first record or by size. Storage is capped at
four segments/4 MiB total plus a 16 KiB manifest, evicting the oldest segment on
rotation. A crash between durable segment mutation and atomic manifest replacement
requires manual recovery; v0.1 has no automatic repair or legacy migration. A
coherent rollback of the complete manifest and segment set is not detectable
without an external monotonic anchor. Logs do not contain snapshot page content or
URL query/fragment data, but still reveal origins and identifiers and should be
handled as private local data.

`broker.secret` authenticates IPC but can establish only an agent session. The
browser extension separately keeps a non-extractable P-256 key, requires explicit
broker-owned OS user-presence approval of its rotating session code, and signs a
fresh single-use challenge before the broker upgrades its relayed connection to
browser authority. A separate `authority.secret` is the root for distinct
HMAC-derived capability and audit keys. Domain separation prevents the same
derived key from being reused for both purposes; it does not protect the root
files from arbitrary native code already running as the same OS user.

## Current limits

The MCP adapter exposes only status, access lifecycle, granted-tab listing,
accessibility-style snapshot, highlight, scroll, and same-origin navigation. It
does not expose cookie/password/storage access, arbitrary JavaScript, CDP,
screenshots, clicks, form entry, submission, or cross-origin navigation.

Each lease permits 250 admitted commands, at most two in flight, and at most 30
per fixed one-minute window. Snapshot results are serialized to UTF-8 JSON and
limited to 256,000 bytes per result and 1,000,000 bytes cumulatively per lease.
The broker allows at most 8 pending requests per session/100 globally,
`access.request` at 20 per session/120 globally per fixed minute, 512 request
records, 200 lease records, and 15 minutes before terminal records are eligible
for pruning. Each IPC connection admits at most 240 inbound requests per fixed
minute before handler dispatch.

These controls limit accidental or agent-driven overuse; they are not a security
boundary against same-UID native code or a compromised OS/browser. Pairing adds
one global prompt at a time, a 30-second post-dismissal cooldown, three attempts
per connection per five minutes, and three attempts globally per ten minutes.
Same-UID code can still consume that global budget and delay a legitimate prompt;
the limits bound prompt occupancy but do not provide process isolation.

See the [project README](https://github.com/SnakeLil/tabgrant#readme),
[roadmap](https://github.com/SnakeLil/tabgrant/blob/main/ROADMAP.md), and
[security policy](https://github.com/SnakeLil/tabgrant/blob/main/SECURITY.md)
before using it with an authenticated browser session.

## Chrome end-to-end test

From the repository root:

```bash
pnpm e2e:chrome:install
pnpm e2e:chrome:ci
```

The recorded CI run on Chrome for Testing 152.0.7977.64 exercised extension-key
pairing, MCP, Native Messaging host, extension popup, and a synthetic loopback
page through snapshot, highlight, scroll, revoke, password redaction, and audit
no-content checks. The harness imports broker source and injects a test approver
that accepts only the exact extension identity, code, and fingerprint observed in
that run. It therefore exercises the challenge/signature/persistence chain but
does not exercise production `osascript` or `zenity`.

The run writes a Native Messaging manifest only inside its temporary browser
profile and never touches the global manifest. It verifies that the production
extension has no `host_permissions`, then copies it to a temporary directory and
grants only `http://127.0.0.1/*` to that test copy. It opens and operates the popup
programmatically, so it does not verify a real toolbar gesture or the production
`activeTab` grant path.

`pnpm e2e:chrome:manual` is intended to start the production daemon, show the
real macOS/Linux pairing prompt, and wait for human toolbar and grant clicks. That
manual OS/UI flow is still being debugged and has not produced claimed evidence.
It requires a graphical session and Linux `zenity`.

The current automated suite contains 109 tests: 63 broker, 20 extension, 8
protocol, and 18 policy.
