# Contributing to TabGrant

Thank you for helping build TabGrant. The project is in Developer Preview, so
small, reviewable changes with explicit security assumptions are preferred.

By participating, you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Before opening work

- Use an issue for bugs and bounded improvements.
- Use an RFC issue before changing protocol semantics, browser permissions,
  grant scope, approval behavior, data collection, or public APIs.
- Report vulnerabilities privately according to [SECURITY.md](./SECURITY.md).
- Do not include real credentials, cookies, tokens, pairing codes, private keys,
  private URLs, or private page content in examples, fixtures, logs, screenshots,
  or issues.

## Development setup

Requirements are Node.js 20.19.0 or newer, Corepack, and the pnpm version declared
in `package.json`. macOS and Linux are the currently implemented native-host
platforms.

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm check
pnpm build
pnpm pack:smoke
```

Use a disposable browser profile with synthetic accounts for browser testing.
Never run development builds against your everyday profile or valuable accounts.

`pnpm check` runs formatting, lint, type checking, 134 package/integration tests,
and the extension-authority security gate. The broker suite includes a real MCP
SDK client connected to a spawned MCP subprocess, but it does not launch Chrome or
an OS pairing prompt. `pnpm pack:smoke` builds and installs a temporary package
tarball, verifies its metadata/LICENSE/executables and pinned native-host
launcher, then executes its CLI.

The security gate checks the exact production manifest permissions, rejects
persistent host permissions and selected forbidden browser authorities, blocks a
pairing-confirmation CLI/environment bypass and legacy pre-proof pairing-state
identifiers, verifies that production daemon construction defaults to the system
approver, and checks published-package runtime dependency/native-host metadata.
It is not a browser E2E, OS user-presence test, or substitute for reviewing how a
test approver can be constructed or reached. Test-only pairing approvers must
remain source-injected from the E2E/test harness; never add a production
environment variable, CLI flag, or RPC that auto-approves pairing.

For extension work, load `apps/extension/dist` as an unpacked extension after
`pnpm build`, install the Native Messaging host for that exact extension ID, and
record the browser/OS/client versions used. Follow the root README Quickstart.

## Pull requests

Keep each pull request focused. A pull request should:

- explain the problem, solution, and non-goals;
- identify any security, privacy, permission, protocol, or compatibility impact;
- add tests for allowed and denied behavior;
- update user-facing and architecture documentation when behavior changes;
- avoid unrelated formatting or dependency churn;
- pass `pnpm check` and `pnpm build`;
- pass `pnpm pack:smoke` when broker packaging, executables, or runtime dependencies
  change;
- use a clear commit history and accept maintainer edits when appropriate.

Changes to browser permissions, release workflows, telemetry, grant/approval
logic, browser pairing/key lifecycle, OS prompt behavior, authentication, or
redaction require review from a security owner. The current CODEOWNERS entries are
bootstrap values and must be verified before the repository becomes public.

## Design principles

- Default deny when identity, scope, origin, tab, or action is ambiguous.
- Treat page content and agent output as untrusted input.
- Keep browser authority inside the extension and policy boundary.
- Prefer narrow typed operations over arbitrary code execution.
- Make grants visible, bounded, expiring, and revocable.
- Never treat a page's instruction as user approval.
- Document a limitation instead of implying an unverified guarantee.

## Tests

Security-sensitive changes should include negative cases for wrong-tab use,
expired or replayed grants, redirects or origin changes, malformed messages,
approval bypass, pairing denial/timeout/replay/wrong-key behavior, and
sensitive-data redaction as applicable. Tests must use synthetic pages and
disposable browser state.

Before claiming browser or client compatibility, record a manual end-to-end run:

1. Build the broker and extension from a clean checkout.
2. Load the extension in a disposable browser profile.
3. Install the native host for the observed extension ID and selected channel.
   Confirm `doctor` validates the generated launcher, pinned Node runtime, and
   native-host entry; a legacy `#!/usr/bin/env node` manifest target is not valid.
4. Open the extension popup, keep the session-only 160-bit code visible, and
   select **Pair this extension**. Compare the full code and identity fields with the
   broker-owned macOS `osascript` or Linux `zenity` prompt before approving.
   Windows pairing is unsupported and must fail closed.
5. Confirm that denial or timeout rotates the displayed code and creates no
   `browser-pairing.json`; successful approval plus same-connection P-256 proof
   creates the owner-only record and connects the browser.
6. Run `doctor` and connect the MCP client with an absolute executable path.
7. Request access, open the extension through a real toolbar/Extensions-menu
   gesture, inspect the popup, click **Grant current tab**, take a snapshot,
   highlight and scroll a referenced element, revoke, and confirm further access
   fails.
8. Confirm tab close, navigation, browser disconnect, expiry, and cross-origin
   navigation fail closed.
9. Sanitize logs and screenshots before attaching evidence; pairing codes and key
   material must never be attached.

`pnpm e2e:chrome:ci` uses a source-injected approver and programmatic popup
operation, so it cannot supply OS-prompt or toolbar evidence.
The GitHub-hosted Ubuntu workflow uses the narrower
`pnpm e2e:chrome:ci:linux-no-sandbox` command because that runner blocks Chrome's
user-namespace sandbox. The command is guarded to explicit Linux `CI=true` runs
and a disposable profile; do not use it for local, manual, or production browsing.
`pnpm e2e:chrome:manual` is intended to exercise the production OS prompt and
human toolbar/grant gestures, but that manual flow is still being debugged and is
not currently recorded as passed. The automated/in-process tests remain necessary
but do not substitute for successful manual evidence.

## Dependencies

Explain new runtime dependencies and their trust impact. Avoid packages that add
remote code loading, telemetry, broad filesystem access, or unnecessary network
access. Dependency updates generated by Dependabot receive the same review as
human-authored changes.

## Certificate of Origin

The project uses the [Developer Certificate of Origin
1.1](https://developercertificate.org/). Sign off commits with:

```bash
git commit -s
```

The sign-off certifies that you have the right to submit the contribution under
the project's license. A CLA is not currently required.

## License

Unless stated otherwise, contributions intentionally submitted to TabGrant are
licensed under Apache-2.0.
