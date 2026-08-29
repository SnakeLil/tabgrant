# ADR 0002: Broker-owned OS user presence for browser pairing

- Status: Accepted and implemented for macOS/Linux Developer Preview
- Date: 2026-08-30
- Decision owners: Bootstrap maintainer

## Context

Every local connection initially authenticates with a user-owned shared HMAC
secret. That secret is suitable for identifying a local agent connection but
cannot distinguish an extension relay from arbitrary same-UID native code.
Trusting a claimed `browser` role would therefore let an agent mint browser
authority.

A CLI confirmation flow or persisted pre-approval record also gives automation a
convenient surface to enumerate, confirm, race, or retain pairing material.
Extension UI alone does not create a separate native user-presence checkpoint.
The pairing design needs explicit user comparison without exporting the
extension's private key or persisting its one-time code.

## Decision

New browser keys use this protocol:

1. Every shared-HMAC hello is normalized to `agent`, regardless of its claimed
   role.
2. The extension stores a non-extractable P-256 signing key in IndexedDB. While
   unpaired, it generates a 160-bit code in `chrome.storage.session` and displays
   it in its trusted popup.
3. Only the popup's parameter-free **Pair this extension** action starts pairing. The
   extension sends its public key, extension ID, browser-instance ID, and displayed
   code through the Native Messaging relay on the current broker connection.
4. The production broker invokes `osascript` on macOS or `zenity --text-info` on
   Linux. The prompt displays the full code, extension ID, browser-instance ID, and
   public-key fingerprint. All dynamic prompt data is supplied over stdin, not
   process argv. The prompt defaults to denial, gives up after 55 seconds, and the
   subprocess is terminated after 60 seconds.
5. Missing UI tooling, user denial, prompt cancellation, timeout, and unsupported
   platforms fail closed. The production approver returns denial on Windows;
   Windows browser pairing and Native Messaging installation are not supported.
6. The extension removes the code from session storage after every attempt. If
   still unpaired, the next popup state generates a new code. The broker persists
   no pairing state before proof succeeds.
7. After approval, the broker takes a fresh timestamp and creates a 30-second
   challenge bound to that connection, extension ID, browser-instance ID, public
   key, and fingerprint. The extension signs it with the non-extractable key.
8. Completion consumes the challenge before verifying the signature. Only a valid
   signature atomically persists `browser-pairing.json` with the extension ID,
   public key/fingerprint, and timestamp, applies owner-only `0600` permissions on
   supported Unix platforms, and upgrades that same connection to `browser`.
   Wrong-key, expired, replayed, or cross-connection completion writes nothing.

Prompt admission permits one active prompt, starts a 30-second cooldown at
dismissal, allows three attempts per connection per five minutes, and allows
three attempts globally per ten minutes.

## Test/production separation

The Chrome for Testing CI harness imports `BrokerDaemon` source and passes a
test-only approver through constructor dependency injection. That approver accepts
only the exact extension ID, browser-instance ID, pairing code, and fingerprint
discovered by that disposable run. Production CLI/autostart constructs the system
approver and exposes no auto-approve CLI flag, environment variable, or broker
RPC.

This automated path verifies extension-key generation, code rotation,
Native-Messaging transport, same-connection challenge/signature, pairing
persistence, and subsequent browser authentication. It does not exercise
`osascript`, `zenity`, or real toolbar `activeTab` acquisition.
`pnpm e2e:chrome:manual` is intended to exercise the production OS prompt and
human toolbar/grant gestures, but that flow is still being debugged and has not
passed.

## Alternatives considered

### Trust the shared-secret browser role

Rejected. Any holder of the local IPC secret could claim browser authority.

### Separate terminal confirmation

Rejected. It creates an agent-friendly confirmation surface and encourages
unnecessary pre-approval state. Pairing now stays on one live broker connection
without a terminal confirmation surface.

### Approve only in extension UI

Rejected for initial pairing. The OS prompt gives the user a broker-owned native
checkpoint and an independent place to compare the full code and key identity.
The extension popup remains responsible for initiating pairing and for tab-grant
decisions.

### Treat the OS prompt as same-UID isolation

Rejected as a security claim. A same-UID attacker may manipulate user-owned
files, sockets, processes, or browser/UI state. Stronger isolation would require a
different OS-backed identity and privilege design.

## Consequences and residual risks

Positive consequences:

- an ordinary agent cannot silently gain browser authority by claiming a role or
  invoking a CLI confirmation;
- pairing material is single-attempt and not persisted before proof of possession;
- approval and cryptographic proof are bound to one live connection;
- dynamic code/identity values are absent from process argv.

Costs and residuals:

- macOS and Linux require a graphical session; Linux requires `zenity`;
- Windows pairing fails closed until a native user-presence design exists;
- a user can still approve a deceptive prompt without comparing the popup;
- OS UI subprocesses necessarily receive prompt text in memory;
- same-UID code can consume the three-attempt global budget and temporarily deny
  legitimate pairing, even though one process cannot hold the prompt open
  indefinitely;
- fully compromised same-UID process, browser, or OS state remains outside the
  protection boundary.

## Verification

Broker and extension tests cover role downgrade, exact code shape and rotation,
denial, wrong key, replay, challenge expiry/consumption, persistence only after
proof, connection-local completion, prompt occupancy, cooldown, and per-connection
and global budgets. The source-injected Chrome for Testing E2E covers the
non-OS protocol chain. Successful production OS prompt and real toolbar evidence
remain release gates in [ROADMAP.md](../../ROADMAP.md).
