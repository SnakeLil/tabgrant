# Privacy

## Scope and status

This document describes the current TabGrant Developer Preview data flow. It is
not a production privacy guarantee or a substitute for the privacy terms of the
MCP client, model provider, browser, or visited website.

TabGrant is local-first: the MCP adapter, broker, Native Messaging host, and
extension communicate on the user's machine. On macOS/Linux the broker uses a
Unix-domain socket; its Windows path abstraction uses a named pipe. It does not
open a TCP loopback listener.

Local-first does **not** mean page data stays on the device. Once a snapshot is
returned to an MCP client, that client can send, retain, or transform it elsewhere.

## Data processed by the current surface

A grant may process:

- client and task labels and an internal, unexposed random connection-session ID;
- the extension's public P-256 key and fingerprint, plus a session-only 160-bit
  pairing code processed transiently by the broker-owned OS prompt;
- a human-readable access reason and requested scopes;
- a client-supplied `declaredModelProvider` label;
- browser-instance, tab, document, lease, and request identifiers;
- tab title, URL, and origin;
- bounded visible accessibility-style node metadata and text-derived accessible
  names;
- highlight, scroll, and same-origin navigation commands;
- grant, denial, expiry, disconnect, revoke, command, and kill events;
- local diagnostic, secret, audit, IPC, and persistent-kill state.

Authenticated pages can contain highly sensitive information. Accessibility names
may reveal account, message, document, or control text even though TabGrant does
not intentionally return the complete DOM.

## Data not exposed by the current tool surface

The current MCP/extension implementation does not expose:

- cookies, password values, authentication tokens, or raw browser storage;
- arbitrary JavaScript results, CDP/debugger access, or raw network bodies;
- screenshots, full page source, or arbitrary DOM queries;
- browsing history, ungranted tabs, other profiles, or other connection sessions'
  leases;
- click, form-entry, submit, send, publish, purchase, delete, or account-setting
  actions.

This describes the reviewed v0.1 source surface, not unreviewed forks or future
versions.

The production extension manifest has no `host_permissions`. The automated Chrome
test copies the built extension and grants only `http://127.0.0.1/*` to the
temporary copy so it can process synthetic, disposable test data. That test-only
permission is not shipped.

The extension stores its non-extractable P-256 private key in IndexedDB. Its raw
160-bit pairing code exists in `chrome.storage.session`, is displayed in extension
UI, and is removed after one pairing attempt regardless of approval, denial, or
timeout. An unpaired popup then generates a fresh code.

When the user selects **Pair this extension**, the broker processes the code, extension
ID, browser-instance ID, and key fingerprint only for the live production prompt.
On macOS it feeds a dynamic AppleScript over stdin to `osascript -`; on Linux it
feeds the prompt body over stdin to `zenity --text-info`. Those values do not
appear in subprocess argv. The OS UI subprocess necessarily receives the prompt
text in memory. The broker persists no pairing state before proof succeeds.
Missing UI tooling, cancellation, timeout, and Windows deny pairing.

After approval, the broker creates a fresh 30-second challenge on the same
connection. Only a valid signature from the extension key writes the public key,
fingerprint, extension ID, and approval time to `browser-pairing.json`, with
owner-only `0600` permissions on supported Unix platforms, and upgrades that
connection from agent to browser. Shared-HMAC hello claims are always reduced to
agent authority. Arbitrary same-UID file/socket/process or browser manipulation
remains outside the protection boundary.

## Snapshot minimization and budgets

Snapshots select visible accessibility-style candidates and return at most 500
nodes. The broker measures `JSON.stringify(result)` as UTF-8 before returning it:

- one snapshot result may contain at most 256,000 UTF-8 bytes;
- successfully returned snapshots may consume at most 1,000,000 UTF-8 bytes over
  one lease.

The lease also permits at most 250 admitted commands, 2 in flight, and 30 per
fixed one-minute window. These limits bound disclosure volume within a lease; they
do not stop an authorized client from copying returned data.

Broker-wide bounds allow 8 pending access requests per session and 100 globally;
`access.request` allows 20 per session and 120 globally per fixed minute. The
broker retains at most 512 request records and 200 lease records, prunes eligible
terminal state after 15 minutes, and admits at most 240 inbound RPC requests per
connection per fixed minute.

## Declared model provider

Snapshot requests require the `data.egress.model` scope and a
`declaredModelProvider` value supplied by the MCP client through
`--declared-model-provider` or `TABGRANT_DECLARED_MODEL_PROVIDER`.

The extension shows **Client-declared model provider**. The value is a client
claim, not an identity verified by TabGrant. Binding it into the request/capability makes
the claim visible and stable for that grant, but TabGrant cannot:

- prove which model, account, or service receives the data;
- inspect all downstream client networking;
- enforce a network destination or retention policy;
- stop the client from forwarding data elsewhere.

Users should evaluate the MCP client and any declared provider as separate privacy
boundaries.

## Connection and grant state

The broker assigns each accepted agent connection a random internal session ID.
Pending requests and leases are owned by that session, not only by public
client/task labels. Agent disconnect revokes that session's pending requests and
leases. A second connection using identical public labels cannot list, use, or
revoke them.

The extension keeps its browser-instance identifier in extension local storage
and pending/active grant state in browser session storage. It holds at most one
active grant. Tab/document change, tab close, browser or agent disconnect, expiry,
revoke, replacement, or persistent kill clears or invalidates authority.

## Local secrets and files

TabGrant stores:

- `broker.secret` for IPC authentication;
- `authority.secret` as the root for separately derived capability and audit HMAC
  keys;
- `audit.jsonl` for the current audit segment;
- up to three retained audit segments alongside it;
- `audit.jsonl.manifest.json`, an owner-only signed inventory of the current and
  retained segments;
- `browser-pairing.json` after completed OS approval and same-connection key
  proof, containing the extension ID, paired public key/fingerprint, and timestamp;
- `disabled.json` while the persistent kill switch is active;
- a browser-specific Native Messaging manifest;
- a Unix socket, or Windows named pipe, while the broker runs.

On supported Unix platforms, TabGrant verifies owner and type, rejects unsafe
permissions/symlinks for security-sensitive files, and uses owner-only modes.
These controls do not protect against arbitrary native code already running as
the same OS user, or a fully compromised operating system/browser. Pairing prompt
budgets also do not stop same-UID code from consuming the three-attempt global
window and delaying a legitimate pairing request.

## Audit data and retention

Audit records can contain timestamp, event/outcome, client/task/lease identifiers,
origin, method, and reason code. They omit page snapshot content, URL query strings
and fragments, credentials, and raw capability secrets. Origins and identifiers
remain private metadata and should not be posted publicly.

Every record is HMAC-authenticated with the prior record's HMAC, and each segment
has an independent record chain. A strict HMAC-SHA256 manifest orders the segment
filenames and binds each file's creation time, byte length, record count, SHA-256
digest, and first/last record hashes. On startup the broker verifies the exact
manifest/segment set and every record chain. Missing or stale inventory,
whole-segment deletion or reordering, complete-tail removal, malformed or modified
records, permissive files, symlinks, and oversized data fail closed. Integrity
authentication does not encrypt the files.

Each segment is limited to 1 MiB; current plus retained segments are limited to
four files and 4 MiB total, plus a manifest limited to 16 KiB. The active segment
rotates 30 days after its first record or before a write would exceed 1 MiB,
evicting the oldest retained segment when necessary. Segment mutation is made
durable before the manifest is atomically replaced, so a crash in that cross-file
window intentionally requires manual recovery rather than silently accepting
unanchored history. v0.1 provides no legacy migration, automatic repair, or
user-facing audit browser/exporter.

Without an external monotonic anchor, TabGrant cannot detect deletion of the
complete audit set or replay of one coherent older snapshot containing both the
manifest and every listed segment. Same-UID code that can also read the authority
root can forge audit authentication and remains outside this boundary.

The persistent kill marker contains its activation timestamp and remains until a
local `tabgrant enable --confirm` removes it. `tabgrant kill` writes that private
file directly; there is no kill RPC. Enabling does not restore old leases.

## Telemetry

The current repository contains no telemetry service. Adding telemetry requires a
public design proposal, privacy review, explicit opt-in, documented fields and
retention, and inspection/deletion controls. URLs, page content, form values,
credentials, secrets, session IDs, capabilities, and grant tokens must not become
telemetry fields.

## Current verification boundary

The 109 automated tests (63 broker, 20 extension, 8 protocol, and 18 policy) verify
session isolation/disconnect revocation, output
budgets, audit HMAC/rotation behavior, key separation, and a spawned MCP STDIO
subprocess. A separate Chrome for Testing 152.0.7977.64 CI E2E completes
extension-key pairing, MCP, Native Messaging, popup, and synthetic page
snapshot/highlight/scroll/revoke; it confirms the password value is not exported
and synthetic page/pairing content is absent from the audit segment. That run
imports broker source and injects a test approver matching the run's exact
extension identity, code, and fingerprint, so it bypasses production OS UI.

That E2E uses the temporary loopback permission described above, opens the popup
programmatically, and writes Native Messaging configuration only inside its
temporary browser profile. It does not touch a global browser manifest, verify a
real user's production `activeTab` toolbar gesture, verify `osascript`/`zenity`
user presence, process authenticated user data, or establish branded-Chrome
compatibility. The separate `pnpm e2e:chrome:manual` path is intended to exercise
the real OS prompt and toolbar/grant gestures, but is still being debugged and has
not produced claimed evidence. No external privacy or security audit has been
completed.

## Changes to this policy

Changes that expand data access, retention, telemetry, persistent state, browser
permissions, downstream transfer, or supported actions require security-owner
review, threat-model updates, and visible release notes. Store disclosures, popup
wording, this document, and actual behavior must agree.
