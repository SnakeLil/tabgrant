# Threat Model

## Status and scope

This threat model covers the current TabGrant Developer Preview: MCP subprocess,
local broker, Native Messaging host, Chromium extension, injected document bridge,
and one explicitly granted tab. It is not an audit and must be updated when any
permission, transport, action, persistence, or distribution boundary changes.

## Security goals

- Do not expose ungranted tabs through the agent tool surface.
- Require a user action in extension-controlled UI before page access.
- Bind a lease to one broker connection session, browser instance, tab, document,
  origin, scope set, and bounded lifetime/resources.
- Revoke agent-owned authority on agent disconnect and browser-owned authority on
  browser disconnect/document replacement.
- Prevent a second connection with the same public client/task strings from
  reusing the first connection's state.
- Require broker-owned OS user presence plus same-connection extension-key proof
  before a new browser key is persisted or receives browser authority.
- Exclude credential/storage/arbitrary-code/debugger authorities from the current
  surface.
- Fail closed on malformed protocol input, policy ambiguity, audit tampering, or a
  persistent kill marker.

## Assets

- confidentiality and integrity of data visible in authenticated browser tabs;
- the user's ability to act on websites;
- cookies, passwords, tokens, browser storage, and password-manager data that the
  current surface is intended not to expose;
- grant intent, scope, and revoke/kill state;
- broker connection sessions, signed capabilities, and leases;
- the extension's non-extractable P-256 private key, session-only rotating pairing
  code, paired public key, and browser-authentication challenges;
- IPC, authority, capability, and audit keys;
- audit integrity and local metadata privacy;
- extension, package, CI, and release supply-chain integrity.

## Actors

- the user controlling the browser and extension popup;
- an MCP client/agent that may be buggy, over-broad, or compromised;
- a malicious page, iframe, or page-supplied prompt injection;
- another broker connection, including one presenting the same public identity;
- another local OS user without access to the current user's private files;
- arbitrary native code already running as the same OS user;
- another extension or a compromised browser/operating system;
- a dependency, build, registry, store, or maintainer-account attacker.

## Trust boundaries

1. Agent to MCP subprocess over STDIO
2. MCP subprocess/native host to broker over Unix socket or Windows named pipe
3. Broker connection identity to broker-internal random session identity
4. Broker to macOS `osascript` or Linux `zenity` user-presence UI
5. Native host to extension over Chrome Native Messaging
6. Extension service worker/popup to the injected content bridge
7. Granted document to all other documents, tabs, profiles, and origins
8. Returned page data to the agent and its downstream network/services
9. Source repository to CI, package registry, and extension store

## Explicit protection boundary

TabGrant assumes the OS user account, browser security boundary, and extension
runtime are not fully compromised. It does not claim to protect against:

- arbitrary native code already running as the same OS user, which can generally
  read/replace user-owned secrets, connect to or modify user-owned sockets and
  processes, control browser UI, or consume pairing-prompt admission budgets;
- a fully compromised operating system;
- a fully compromised browser or malicious privileged extension;
- an authorized MCP client copying or forwarding returned data;
- a false `declaredModelProvider` claim by the MCP client.

Per-connection session binding still prevents an ordinary second connection—even
with identical `clientId`/`taskId` strings—from listing, using, or revoking the
first connection's lease. That property must not be overstated as same-UID process
isolation.

## Threats and current controls

| Threat                           | Example                                                                                       | Current control                                                                                                                    | Current evidence/boundary                                  |
| -------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Ambient authority                | Agent lists unrelated tabs                                                                    | Only session-owned leases are listable; extension grants current tab                                                               | Broker negative tests; production toolbar gesture pending  |
| Public-identity reuse            | Second connection copies client/task strings                                                  | Broker-generated random session ID; ownership compares session                                                                     | Same-identity second-session test                          |
| Stale authority after disconnect | MCP process exits but lease remains                                                           | Agent disconnect revokes pending requests and leases                                                                               | Broker disconnect tests                                    |
| Handshake replay/tamper          | Client reuses nonce or edits task ID                                                          | Timestamped HMAC proof, nonce replay set, strict schema                                                                            | Authentication tests                                       |
| Agent/browser role forgery       | Agent claims `browser` in shared-HMAC hello                                                   | Every hello is downgraded; OS approval plus extension signature needed                                                             | Wrong-key/replay/agent-RPC integration tests               |
| Pairing-key substitution         | Agent asks user to approve its own key                                                        | Full rotating code/identity/fingerprint in broker-owned OS prompt; fresh same-connection signature                                 | Broker pairing tests; real OS UI evidence pending          |
| Pairing-code persistence         | Code leaks from disk/process list or is reused                                                | `chrome.storage.session`; removed after one attempt; broker persists no pre-proof pairing record; prompt data uses stdin, not argv | Extension/schema/source tests                              |
| Pairing-prompt flood             | Same-UID caller repeatedly opens or reserves prompts                                          | One active prompt; 30s cooldown; 3/connection/5m and 3 global/10m                                                                  | Cross-connection occupancy/rate tests; residual budget DoS |
| Cross-key reuse                  | One protocol reuses another protocol's key                                                    | Separate IPC root and authority root; capability/audit domain labels                                                               | Key-separation tests                                       |
| Prompt injection                 | Page asks agent to grant or exfiltrate                                                        | Page content cannot drive popup grant; no write tools                                                                              | Protocol/surface gate; adversarial browser E2E pending     |
| Origin/document confusion        | Tab redirects before execution                                                                | Service worker rechecks tab origin and document ID; navigation revokes                                                             | Unit tests; real browser race tests pending                |
| Scope escalation                 | Browser or agent adds a scope                                                                 | Grant must be subset of request; strict allowlists                                                                                 | Broker integration tests                                   |
| Credential access                | Tool reads cookies/password/storage                                                           | No such scopes/tools; password controls marked sensitive                                                                           | Protocol gate; synthetic Chrome password redaction E2E     |
| Arbitrary execution              | Agent requests JS or CDP                                                                      | No arbitrary JS/CDP/debugger tool or manifest permission                                                                           | Protocol and source security gate                          |
| Over-broad extraction            | Snapshot dumps unlimited content                                                              | Visible-node cap; 256 KB/result and 1 MB/lease UTF-8 budgets                                                                       | Limit/concurrency tests                                    |
| Resource flood                   | Agent sends concurrent/high-rate calls                                                        | Lease, access-request, state-record, IPC, and frame caps                                                                           | Atomic/session/global/IPC limit tests                      |
| In-flight revoke race            | Result returns after user revokes                                                             | Broker rechecks active lease before returning result                                                                               | Revocation race test                                       |
| Declared-provider spoofing       | Client says `openai` but sends elsewhere                                                      | Popup labels it as declared; no enforcement claim                                                                                  | Residual risk, not prevented                               |
| IPC exposure                     | Network host reaches broker                                                                   | Filesystem Unix socket/Windows pipe; authenticated handshake                                                                       | IPC tests; same-UID code out of boundary                   |
| Audit modification               | Record or whole segment is edited/deleted/reordered/truncated                                 | Per-record HMAC chains plus ordered HMAC manifest binding exact files, bytes, digests, counts, and first/last hashes               | Record/manifest/delete/reorder/tail/crash-boundary tests   |
| Unbounded audit retention        | Metadata accumulates indefinitely                                                             | 1 MiB/segment, 4 MiB/4 segments; 30-day or size rotation                                                                           | Size/rotation/restart tests                                |
| Kill privilege confusion         | Agent invokes a kill RPC                                                                      | No `broker.kill`; CLI writes owner-only marker directly                                                                            | Agent-RPC and daemon marker tests                          |
| Kill bypass by restart           | Agent/autostart restarts after emergency stop                                                 | Owner-only persistent marker checked before daemon start                                                                           | Daemon restart test                                        |
| Installer/PATH confusion         | Install replaces config, uninstall deletes replacement, or GUI Chrome cannot resolve nvm Node | Create-only manifest; absolute-runtime launcher; inode/byte-pinned, ownership-checked uninstall                                    | Installer/doctor and Node-free-PATH Chrome E2E             |
| Malicious update                 | Workflow publishes modified artifact                                                          | Pinned Actions, dependency review, CodeQL, planned protected release                                                               | Release rehearsal pending                                  |

## Declared egress risk

Snapshot access requires `data.egress.model` and a
`declaredModelProvider` supplied by the MCP client. The extension shows
**Client-declared model provider** so the user knows it is a claim. The label is bound
into capability metadata but is not authenticated against the real process,
account, model, or network connection.

After returning page data over MCP, TabGrant cannot observe or restrict where the
client sends it. Users must evaluate the MCP client and its configured provider as
a separate privacy/trust boundary.

## Audit residuals

Audit segments omit page snapshot content, query strings, fragments, and secrets,
but record origins and client/task/lease metadata. They are therefore sensitive
local data. Record-chain and manifest HMAC integrity detects isolated changes when
the broker next starts; it does not provide confidentiality, remote attestation,
or protection from a same-UID attacker with access to both the data and authority
root. Without an external monotonic anchor, deleting the complete audit set or
replaying a coherent older snapshot of both manifest and every segment is not
detectable.

Segments have independent record chains and are capped at 1 MiB each. The signed
`audit.jsonl.manifest.json` binds their order and complete contents. Rotation
occurs at 30 days or by size; current plus retained storage is capped at four
segments/4 MiB, excluding the bounded manifest, and the oldest is evicted. The
manifest is atomically replaced after durable segment mutation. A crash between
those two files leaves an intentional fail-closed startup mismatch; v0.1 has no
automatic repair, legacy migration, or user-facing export/verification tool.

Broker flood controls additionally cap pending requests at 8 per session/100
globally, `access.request` at 20 per session/120 globally per fixed minute,
request/lease records at 512/200, and terminal-record retention at 15 minutes.
Each IPC connection admits at most 240 requests per fixed minute before handler
dispatch. These are availability and bounded-state controls, not isolation from a
same-UID attacker. Browser-pairing prompts additionally allow one active prompt,
a 30-second post-dismissal cooldown, three attempts per connection per five
minutes, and three attempts globally per ten minutes. A same-UID caller can spend
the global budget and delay legitimate pairing until the window recovers.

## Residual risks

- A user may grant the wrong current tab or misunderstand a read disclosure.
- Accessibility names may contain sensitive text not obviously visible to the
  user at approval time.
- An authorized client can retain or forward every returned result.
- The declared provider label may be false or stale.
- Websites can change content between grant, snapshot, and user interpretation.
- Other extensions may observe or alter the page.
- Same-UID native code and fully compromised OS/browser environments can defeat
  local files, IPC sockets/processes, extension, or UI assumptions. Same-UID code
  can also cause a bounded pairing denial of service by consuming the global
  prompt budget.
- Knowledge of `broker.secret` alone grants only agent authority; the claimed role
  is always downgraded. New browser authority additionally requires the
  broker-owned macOS/Linux prompt and a fresh same-connection signature from the
  extension's IndexedDB non-extractable key. This does not protect against
  arbitrary same-UID code that can manipulate local files, socket/process state,
  IndexedDB, OS prompts, or browser UI.
- Production pairing fails closed on Windows because no Windows user-presence
  approver or browser Native Messaging installation is implemented.
- The code has no completed independent security audit.

## Verification boundary

Current automated evidence includes 134 tests: 83 broker, 25 extension, 8 protocol,
and 18 policy. A real MCP SDK client spawns and negotiates with the MCP subprocess.
Broker-focused command integration is mocked. A separate Chrome for Testing
152.0.7977.64 CI E2E completes extension-key pairing, MCP startup, Native
Messaging, popup rendering and grant, synthetic snapshot/highlight/scroll/revoke,
password redaction, and audit no-content checks. Chrome runs with no Node
executable in `PATH`, exercising the absolute-runtime launcher and the distinct
pre-pair popup state. It imports broker source and uses
an exact-match injected approver, so it tests challenge/signature/persistence
without invoking production OS UI.

The E2E writes its Native Messaging manifest only inside a temporary browser
profile and never touches a global manifest. It first rejects production
`host_permissions`, then adds only `http://127.0.0.1/*` to a temporary extension
copy and opens/operates its popup programmatically. It therefore verifies neither
production `osascript`/`zenity` user presence nor the production `activeTab`
toolbar gesture. The `pnpm e2e:chrome:manual` harness is intended to cover the
OS prompt and real toolbar/grant gestures, but is still being debugged and has not
passed. [Branded Chrome 137+ command-line unpacked-extension
restrictions](https://developer.chrome.com/blog/extension-news-june-2025) also mean
Chrome for Testing evidence is not branded-Chrome compatibility evidence.

## Review triggers

Re-run threat modeling for write/sensitive actions, remote transport, enforceable
egress, telemetry, persistent/multiple grants, new browser permissions, Windows
browser installation, mobile/managed deployment, new key storage, new audit
retention, or extension execution-model changes.
