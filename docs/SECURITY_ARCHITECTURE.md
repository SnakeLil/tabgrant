# Security Architecture

## Status

This document describes controls implemented in the TabGrant Developer Preview
and identifies the boundary they do not provide. It is not an independent audit
or production guarantee.

## Current invariants

1. **No ambient tab enumeration.** Agent tools list only leases granted to the
   current broker connection session.
2. **A grant is explicit and document-scoped.** The user grants the current tab in
   extension-controlled UI; tab, document, or origin change invalidates it.
3. **Connection identity is not lease identity.** Each accepted connection gets an
   internal random session ID. The broker binds requests and leases to that ID,
   and revokes them when the agent disconnects.
4. **A matching public identity cannot resume authority.** A second connection
   using the same `clientId` and `taskId` cannot see, use, or revoke the first
   connection's lease.
5. **Page content is not authorization.** Page text, DOM, and accessibility output
   cannot create a request, grant a tab, change scopes, clear the kill marker, or
   approve an action.
6. **Scope does not expand silently.** A granted scope must be a subset of the
   request, navigation stays on the exact origin, and document replacement
   requires a new grant.
7. **The current execution surface is narrow.** It exposes bounded snapshot,
   highlight, scroll, and same-origin navigation, not clicks, forms, submissions,
   screenshots, credentials, cookies/storage, arbitrary JavaScript, network
   bodies, or CDP/debugger commands.
8. **Failure is closed.** Invalid schema, identity, session, signature, state,
   origin, scope, budget, audit integrity, kill state, or channel lifecycle denies
   work.
9. **Browser authority requires two live proofs.** A new extension key requires
   broker-owned macOS/Linux OS approval and then a fresh same-connection P-256
   challenge signature before any pairing state is persisted.

## Local IPC and authentication

The broker listens on a filesystem Unix-domain socket on macOS/Linux or a Windows
named pipe. It does not expose a TCP loopback port. The MCP adapter and Native
Messaging host connect to that endpoint.

`broker.secret` authenticates a timestamped HMAC handshake. The proof binds the
claimed role, client ID, task ID, process instance ID, nonce, and timestamp. Nonces
are rejected on replay and timestamps have a bounded acceptance window. Every such
handshake is normalized to `agent`; a caller-supplied `browser` role never creates
browser authority. Merely opening the IPC endpoint or knowing a lease ID is
insufficient.

The extension generates and stores a non-extractable P-256 private key in
IndexedDB. While unpaired, its trusted popup displays a 160-bit code held only in
`chrome.storage.session`. The parameter-free **Pair this extension** action sends the
public key, code, extension ID, and browser-instance ID through the untrusted
native relay on that connection.

The production broker owns user-presence approval. It invokes `osascript` on
macOS or `zenity --text-info` on Linux and shows the full code, extension ID,
browser-instance ID, and key fingerprint. Dynamic prompt data is fed over stdin;
the subprocess argv contains no code or identity. The prompt defaults to denial
and gives up after 55 seconds; the subprocess hard-stops at 60 seconds. Missing OS
UI, cancel, timeout, and Windows all deny pairing. The broker persists no pairing
state before proof succeeds, and the extension removes the code from session
storage after every attempt so a retry rotates it.

After approval returns, the broker takes a fresh timestamp and creates a
connection-local 30-second challenge bound to the extension ID, browser-instance
ID, public key, and fingerprint. The extension signs it with the non-extractable
key. Startup authentication and popup pairing share a serial queue bound to the
exact Native Messaging port. The broker permits one authentication transition or
live challenge per connection; competing starts/pairs fail busy, and an unknown
challenge ID cannot consume the valid challenge. A matching completion consumes
the challenge before verification. Only a valid signature
atomically persists `browser-pairing.json` with the extension ID, public key,
fingerprint, and timestamp, applies `0600` mode on supported Unix, and upgrades
that same connection to browser authority. Wrong-key, expired, cross-connection,
and replay attempts fail without writing pairing state. Later connections receive
the same fresh challenge flow only if their extension ID and key fingerprint
match the persisted record.

The shared-secret plus browser proof scheme protects against accidental
unauthenticated clients, agent-to-browser role forgery, stale/replayed handshakes,
and lease reuse by a second broker connection. It does
**not** isolate TabGrant from arbitrary native code already running as the same OS
user: such code can generally read or replace user-owned files, connect to or
modify user-owned socket/process state, and control browser UI. It can also consume
the bounded global pairing-prompt budget and delay a legitimate request. Strong
protection from same-UID native code would require an OS-backed
identity/privilege boundary not present in v0.1.

## Per-connection session binding

After handshake verification, the broker generates a random UUID and associates
it with the in-memory connection context. This value is not client-selected and
is not returned through MCP. Pending requests and leases store that session ID;
all agent access/list/revoke paths compare it rather than trusting public identity
strings.

When an agent connection closes, its pending requests are revoked and all its
active leases are revoked with `AGENT_DISCONNECTED`. When the browser connection
closes, leases for that browser instance are revoked. Sessions are not resumable.

## Capability and key domains

The broker maintains two private root files:

- `broker.secret` for IPC authentication;
- `authority.secret` for authority-related derivation.

The authority root derives separate HMAC keys with explicit `capability` and
`audit` domain labels. Signed capabilities bind public client/task identity,
browser instance, tab, document, origin, scopes, declared provider label, issue
and expiry times, idle timeout, use limit, nonce, audience, and policy version.
The broker also requires the independent in-memory session-bound lease before a
capability can authorize execution.

Domain separation prevents accidental reuse of one derived key across capability
and audit protocols. It does not make the authority root safe from a same-UID
attacker that can read the file.

## Lease budgets

An active lease enforces:

| Budget               | Current limit                                    |
| -------------------- | ------------------------------------------------ |
| Absolute lifetime    | 10 minutes                                       |
| Idle lifetime        | 2 minutes                                        |
| Admitted commands    | 250                                              |
| Concurrent commands  | 2 in flight                                      |
| Command rate         | 30 per fixed one-minute window                   |
| One snapshot result  | 256,000 bytes of serialized UTF-8 JSON           |
| Snapshot lease total | 1,000,000 successfully returned serialized bytes |

Admission updates the use, rate, and in-flight state synchronously before
dispatch. A result is not returned after the lease has been revoked. Concurrent
snapshot settlement cannot overspend the remaining UTF-8 byte budget. Wire and
Native Messaging frames are also bounded to 1 MiB.

These limits reduce resource abuse and bound disclosed snapshot volume within a
lease. They do not prevent an authorized client from copying or forwarding data
after receipt.

## Broker admission and state limits

| Resource                             | Current limit                    |
| ------------------------------------ | -------------------------------- |
| Pending requests per agent session   | 8                                |
| Pending requests globally            | 100                              |
| `access.request` per session         | 20 per fixed minute              |
| `access.request` globally            | 120 per fixed minute             |
| Access-request records               | 512                              |
| Lease records                        | 200                              |
| Terminal-record retention            | 15 minutes before eligible prune |
| Inbound RPC per connection           | 240 per fixed minute             |
| Audit segment / aggregate disk bytes | 1 MiB / 4 MiB across 4 segments  |

The IPC rate limit runs before handler dispatch, so excess requests return
`RATE_LIMITED` without entering broker business logic or creating handler-driven
audit writes. State-capacity checks prune eligible terminal records and otherwise
fail closed instead of growing without bound.

Pairing has separate prompt admission: one prompt may be active globally,
dismissal starts a 30-second cooldown, each connection may attempt three times per
five minutes, and all connections share three attempts per ten minutes. These
limits bound repeated UI occupation. They do not prevent a same-UID attacker from
spending the global budget first and causing a temporary pairing denial of
service.

## Browser boundary

The MV3 extension requests exactly `activeTab`, `scripting`, `nativeMessaging`,
and `storage`, with no persistent host permissions, static content scripts, or
externally connectable surface. The browser's Native Messaging manifest allows
only the exact extension ID.

The real-Chrome test harness verifies this production manifest invariant before
copying the extension into a temporary directory. Only that test copy receives
`http://127.0.0.1/*` host permission for its synthetic page. It is never the
production artifact and is removed after the run.

Native-host installation is create-only: it refuses to overwrite an existing
manifest. Uninstall pins and validates the inspected inode and bytes before
removal, refuses a concurrently replaced path, and is idempotent when absent.
Changing an installation requires uninstall followed by install.

Grant UI runs in the extension popup. The service worker rechecks tab origin and
document identity immediately before execution. The content bridge validates its
document ID, command allowlist, field set, sizes, and snapshot epoch. Tab close,
loading/navigation, bridge loss, extension/native-host disconnect, and expiry
tear down or revoke the grant.

Another extension, a malicious page, and a compromised agent remain untrusted.
A fully compromised browser or operating system can defeat these controls and is
outside the protection boundary.

Windows named-pipe code exists, but browser Native Messaging installation and a
production Windows user-presence approver do not. The system approver returns
denial on Windows, so production browser pairing fails closed and Windows is not
a supported browser platform.

## Declared model provider and egress

`--declared-model-provider` / `TABGRANT_DECLARED_MODEL_PROVIDER` supplies a
`declaredModelProvider` string. The access request and popup present it as
**Client-declared model provider**.

The broker requires a declared value when the request includes
`data.egress.model` and binds the string into capability metadata. The value is a
self-assertion by the MCP client. TabGrant does not authenticate the provider,
observe all client networking, or enforce the destination after returning a
snapshot. It must never be described as a verified egress identity, allowlist, or
network control.

## Audit integrity and retention

Audit records use a strict allowlist and omit page snapshots, credentials,
capability secrets, URL query strings, and fragments. They can include origin and
client/task/lease metadata and therefore remain private data.

Each record contains an HMAC over the full normalized record, timestamp, and
previous HMAC. Each segment has an independent record chain. A separate strict
`audit.jsonl.manifest.json` contains an ordered entry for every segment with its
index, exact filename, creation timestamp, byte length, record count, SHA-256
digest, and first/last record hashes. HMAC-SHA256 over the complete manifest uses
an explicit manifest domain prefix. Broker startup verifies the manifest, exact
on-disk segment set, every record chain, and every manifest descriptor. A missing
manifest when any segment exists, whole-segment deletion or reordering, removal
of complete trailing records, malformed data, permissive files, symlinks, and
oversized segments all fail closed, including when data is old enough to rotate.

Manifest replacement uses a create-exclusive owner-only temporary file in the
same directory, file `fsync`, atomic rename, and directory `fsync` on Unix. The
segment mutation is durable before the new manifest is published. A process or
power failure in that cross-file window therefore causes the next startup to fail
closed rather than silently accept unauthenticated history; v0.1 has no automatic
repair or legacy manifest migration.

Each segment is capped at 1 MiB. The active segment rotates 30 days after its first
record or before the next record would exceed the cap. Current plus retained
segments are limited to four files and 4 MiB total; rotation evicts the oldest.
The small manifest is outside that segment-byte quota. v0.1 does not provide a
user-facing audit viewer/exporter.

## Persistent kill switch

Broker kill is deliberately absent from the public RPC surface. `tabgrant kill`
writes the private `disabled.json` marker directly; the running broker monitors
that marker, closes connections, and stops. Startup checks the marker before
accepting connections, so process restart and autostart remain blocked.

Restoring access is deliberately separate and explicit:

```bash
tabgrant enable --confirm
```

Clearing the marker does not restore prior requests or leases.

## Current and future action classes

The policy package models read, navigation, reversible write, sensitive commit,
and preview-only high-risk actions. Only the current read/highlight/scroll and
same-origin navigation subset is connected to MCP and the extension. Step-up
approval for write/sensitive actions is future work and must not be presented as
a shipped control for tools that do not yet exist.

## Supply chain

The repository has a committed lockfile, dependency review/security workflows,
package smoke tests, and full-commit-SHA-pinned GitHub Actions. The source
security gate checks the exact production extension permissions, rejects
persistent host permissions and selected forbidden browser authorities, blocks a
pairing-confirmation CLI/environment bypass and legacy pre-proof pairing-state
identifiers, verifies that production daemon construction defaults to the system
approver, and checks published-package runtime/native-host metadata. The gate
does not prove the OS UI path or fully prove dependency-injection reachability;
code review and tests must still confirm that the source-injected test approver
is constructed only by the E2E harness while production startup uses the system
approver.
Public release still requires protected repository/release environments, npm OIDC
trusted publishing with provenance, checksums, SBOM, extension-store controls,
and release/rollback rehearsal.

## Verification boundary

The 109 automated tests comprise 63 broker, 20 extension, 8 protocol, and 18 policy
tests. They include a real MCP SDK STDIO client spawning the MCP subprocess,
session isolation and disconnect revocation, pairing/challenge boundaries,
resource limits, persistent kill, installer race resistance, key separation, and
retained-segment audit verification.

Broker-focused integration uses a mock browser connection. Separately,
`pnpm e2e:chrome:ci` has completed on Chrome for Testing 152.0.7977.64 with
extension-key pairing, MCP, Native Messaging host, popup grant, and synthetic page
snapshot/highlight/scroll/revoke. It confirms password values are redacted and
page/pairing content is absent from audit records. The CI harness imports
`BrokerDaemon` source and injects an approver that accepts only the exact
extension identity, pairing code, and fingerprint observed in that run.

GitHub's Ubuntu runner invokes a separate guarded command that adds
`--no-sandbox` for the disposable Chrome for Testing process. The policy helper
requires CI mode, Linux, and `CI=true`, and the harness rechecks that its profile
is under the generated temporary test directory before launching. Default and
manual runs retain Chrome's sandbox. This exception reduces the fidelity of the
hosted Linux test and must never be copied into production or ordinary browsing
instructions.

The E2E writes its Native Messaging manifest only inside a temporary browser
profile and does not touch a global manifest. It programmatically opens and
operates the popup and uses the temporary loopback permission described above.
Because it bypasses the system approver, it verifies neither production
`osascript`/`zenity` user presence nor a real toolbar gesture/`activeTab`
acquisition. The separate `pnpm e2e:chrome:manual` path is intended to cover
those OS/UI boundaries but is still being debugged and has not passed.
[Branded Chrome 137+ disables command-line unpacked
extension loading](https://developer.chrome.com/blog/extension-news-june-2025), so
Chrome for Testing evidence is not a branded-Chrome support claim. An external
security audit has not been completed.
