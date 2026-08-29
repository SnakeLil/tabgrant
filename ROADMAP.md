# TabGrant Roadmap

This roadmap separates shipped source behavior from release acceptance. A checked
item has evidence in the current repository; it does not imply production support
or a public distribution.

## Current Developer Preview

Implemented in the current source:

- [x] The MCP adapter and Native Messaging host connect to the broker over a Unix
      socket on macOS/Linux or a named pipe on Windows, with authenticated IPC
      handshakes and nonce replay rejection.
- [x] An MCP task can create a pending request; the user can grant the current tab,
      see the active grant, and revoke it from trusted extension UI.
- [x] Each agent connection receives an internal random session ID. Requests and
      leases are session-bound, disconnect revokes them, and a same-identity second
      connection cannot see, use, or revoke them.
- [x] A shared-HMAC hello always yields agent authority regardless of claimed role.
      The extension stores a non-extractable P-256 private key in IndexedDB and a
      rotating 160-bit code in session storage. Its explicit popup action asks the
      broker to show a macOS `osascript` or Linux `zenity` user-presence prompt.
- [x] Dynamic prompt identity/code/fingerprint data travels over stdin rather than
      process argv. Approval produces a fresh same-connection 30-second challenge;
      only a valid extension-key signature persists the public key in owner-only
      `browser-pairing.json` and upgrades that connection. No pairing state is
      persisted before that proof succeeds.
- [x] Pairing fails closed when the OS UI is unavailable, cancelled, or timed out,
      and on Windows. The prompt budget allows one active prompt, a 30-second
      cooldown, three attempts per connection per five minutes, and three globally
      per ten minutes.
- [x] Pairing prevents an ordinary agent from silently substituting its own key,
      but explicitly does not protect against arbitrary same-UID code that can
      tamper with user-owned files/processes/browser UI or consume the global
      prompt budget to delay legitimate pairing.
- [x] One session-, tab-, document-, and origin-bound lease is active at a time,
      with ten-minute absolute expiry, two-minute idle expiry, 250 admitted uses,
      two in-flight commands, and 30 commands per fixed minute.
- [x] Snapshot egress is enforced over serialized UTF-8 JSON: 256,000 bytes per
      result and 1,000,000 bytes cumulatively per lease.
- [x] Nine MCP tools cover status, grant lifecycle, granted-tab listing, bounded
      accessibility snapshots, highlighting, scrolling, and same-origin navigation.
- [x] Navigation replaces the document and revokes the lease; cross-origin
      navigation is denied.
- [x] The public tool surface excludes clicks, forms, submissions, screenshots,
      cookie/password/storage access, arbitrary JavaScript, CDP/debugger access,
      raw network bodies, and ungranted-tab enumeration.
- [x] IPC authentication uses a separate secret from the authority root; capability
      and audit HMAC keys are derived with distinct domain labels.
- [x] Local audit records exclude page content and URL query/fragment data. Each
      segment has an HMAC record chain, while an ordered HMAC manifest binds the
      exact filenames, byte lengths, counts, digests, and endpoint hashes. Startup
      fails closed on missing or stale inventory, whole-segment deletion or
      reordering, and complete-tail removal. Storage is capped at four 1 MiB
      segments/4 MiB total plus a bounded 16 KiB manifest; rotation occurs at 30
      days or by size.
- [x] `tabgrant kill` persists a disabled marker across daemon restart; only an
      explicit local `tabgrant enable --confirm` clears it. Kill is a private-file
      control and is not exposed as `broker.kill` RPC.
- [x] Resource controls cap pending requests at 8 per session/100 globally,
      `access.request` at 20 per session/120 globally per minute, request records
      at 512, lease records at 200, terminal retention at 15 minutes, and inbound
      IPC at 240 requests per connection per minute.
- [x] macOS and Linux native-host manifest locations are implemented for Chrome,
      Chrome for Testing, Chromium, Edge, and Brave. [Chrome for Testing 146+ uses
      its independent `NativeMessagingHosts`
      path](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
      and is primarily a test channel.
- [x] Native-host installation is create-only and never replaces an existing
      manifest. Uninstall pins and rechecks the inspected inode and bytes, is
      idempotent when absent, and is required before reinstalling a changed manifest.

Current automated evidence, recorded on 2026-08-30:

- [x] `pnpm check` passes formatting, lint, type checking, 106 tests (62 broker,
      18 extension, 8 protocol, and 18 policy), and the extension-authority
      security gate.
- [x] `pnpm build` produces the MV3 extension and broker CLI, MCP, and native-host
      executables.
- [x] `pnpm pack:smoke` installs the generated `tabgrant@0.1.0` package tarball and
      executes its version command.
- [x] A real MCP SDK STDIO client test spawns the MCP subprocess, negotiates the
      protocol, lists the bounded tools, calls status, and creates an isolated
      pending request.
- [x] Broker tests cover random-session isolation, agent-disconnect revocation,
      scope escalation, concurrency/rate/use/output budgets, persistent kill,
      HMAC audit verification, cross-origin denial, redaction, malformed input,
      authentication tampering, and nonce replay.
- [x] `pnpm e2e:chrome:install` installs Chrome for Testing 152.0.7977.64, and
      `pnpm e2e:chrome:ci` has completed the extension-key pairing, MCP, Native
      Messaging, popup rendering/grant, synthetic loopback-page snapshot,
      highlight, scroll, revoke, password redaction, and audit no-content chain.
      It imports broker source with an exact-match test approver and therefore does
      not exercise the production OS prompt.
- [x] Chrome E2E writes the Native Messaging manifest only inside its temporary
      profile and does not touch a global browser manifest.
- [x] The Chrome E2E refuses a production manifest with `host_permissions`, then
      copies the extension and adds only `http://127.0.0.1/*` to the temporary test
      manifest. Production continues to use `activeTab` with no host permissions.
- [x] The popup E2E verifies the **Client-declared model provider** label and its
      downstream-enforcement warning.

Still required before declaring v0.1 release acceptance:

- [ ] Complete and record `pnpm e2e:chrome:manual` with the production
      macOS/Linux approver, a human comparison/approval of the full pairing prompt,
      a real toolbar/Extensions-menu gesture, and a human **Grant current tab**
      click. This manual OS/UI harness is still being debugged and has not passed.
- [ ] Manually verify and record the production `activeTab` path initiated by a
      real user toolbar gesture. The automated popup grant uses a temporary
      loopback host permission and injected pairing approver, so it proves neither
      the gesture nor the production OS user-presence path.
- [ ] Record a live Codex MCP smoke test using the documented
      `--declared-model-provider` configuration.
- [ ] Verify at least the minimum supported browser version and one current Chrome
      version on both macOS and Linux.
- [ ] Run the same required checks on the protected default branch in GitHub CI.
- [ ] When making the repository public, enable private vulnerability reporting
      immediately, then verify it before announcing the project. Also verify
      branch protection, required CI and DCO checks, CodeQL, secret scanning, and
      Dependabot. Keep private reporting operational for the lifetime of the
      public preview.
- [ ] Confirm no known critical or high-severity vulnerability remains open.
- [ ] Publish checksums and exact source-install limitations with the tag.
- [ ] Document release support around [branded Chrome's removal of command-line
      unpacked-extension loading in Chrome
      137](https://developer.chrome.com/blog/extension-news-june-2025). Automated
      Chrome for Testing or Chromium evidence is not a branded-Chrome compatibility
      claim.

## v0.3 — Public Alpha

- [ ] Publish the package through npm trusted publishing with provenance; no
      maintainer performs a local token-based publish.
- [ ] Publish a GitHub release with extension archive, checksums, SBOM, provenance,
      and rollback instructions.
- [ ] Publish Chrome Web Store and MCP Registry alpha entries whose permissions and
      availability match the artifacts.
- [ ] Test and publish an exact OS/browser/client support matrix. Chrome, Chromium,
      Edge, and Brave remain candidates until each combination has evidence.
- [ ] Design, implement, and test Windows native-host installation and an
      OS-backed pairing approver before listing Windows as supported; current
      pairing deliberately fails closed there.
- [ ] Test browser and broker crash/reconnect behavior in real browsers and confirm
      it fails closed.
- [ ] Decide whether an enforceable downstream-egress integration is in scope. Do
      not treat `declaredModelProvider` as that enforcement.
- [ ] Keep private vulnerability reporting and repository security controls
      operational; add monitored role-based security and conduct contacts, an
      independent escalation path, Discussions, and protected release environments.
- [ ] A new contributor can complete the documented setup in under 15 minutes.

## v0.5 — Beta

- [ ] Decide through RFC whether to add click, form draft, submit, publish, or other
      write actions; expose none until their approval UI and failure semantics ship.
- [ ] If write actions are accepted, distinguish read, navigation, reversible
      write, and sensitive action classes in the public tool registry.
- [ ] Bind sensitive approval to normalized action, target, material values, current
      document state, and trusted user presence.
- [ ] Re-evaluate redirects, frames, and script-driven origin/document changes in
      adversarial real-browser tests.
- [ ] Support multiple simultaneous grants only after capability isolation and UI
      remain understandable; otherwise retain the one-grant limit.
- [ ] Make local audit retention, inspection, verification, and deletion user
      controllable while preserving default redaction.
- [ ] Demonstrate that page instructions cannot expand a grant or approve an action.
- [ ] Complete a 1,000-cycle grant/revoke/reconnect soak without cross-grant leakage.

## v0.7 — Feature Complete

- [ ] Freeze version negotiation, capability discovery, and deprecation behavior.
- [ ] Keep MCP, CLI, and any public SDK on one typed action registry and policy
      engine.
- [ ] Add a versioned managed-policy format only with authenticated distribution;
      local policy remains the default.
- [ ] Add another browser only with equivalent security behavior and repeatable CI
      or release-gate evidence.
- [ ] Measure local dispatch overhead, targeting p95 below 100 ms excluding page and
      model latency on a named reference environment.
- [ ] Keep telemetry off by default and exclude URLs, page content, form values,
      credentials, capabilities, and grant tokens.
- [ ] Keep same-UID native-code, fully compromised OS, and fully compromised browser
      assumptions explicit unless a new isolation boundary is introduced.

## v0.9 — Release Candidate

- [ ] Freeze the public protocol/schema for the candidate and test upgrades from
      every supported beta.
- [ ] Complete an independent security assessment and resolve or publicly
      disposition findings.
- [ ] Add fuzz or property tests for protocol parsing, native framing, capability
      validation, lease lifecycle, and policy invariants.
- [ ] Complete a 30-day beta soak and 100 synthetic or properly de-identified
      end-to-end QA workflows.
- [ ] Leave no known critical/high vulnerability open; document every medium
      finding decision.
- [ ] Rehearse publish, rollback, package deprecation, extension rollback, signing
      recovery, and incident response.

## v1.0 — Stable

- [ ] Only explicitly granted tabs are accessible; any expansion requires fresh
      user authorization.
- [ ] Page content cannot approve sensitive actions or change policy.
- [ ] Authentication material is not exported by default.
- [ ] SemVer, compatibility, and deprecation windows are published.
- [ ] Every supported client/browser/OS combination has repeatable release-gate
      evidence.
- [ ] Releases are reproducible and include provenance, SBOM, checksums, and tested
      rollback instructions.
- [ ] At least two active maintainers, backup asset owners, and monitored security
      and conduct contacts exist.
- [ ] Documentation, privacy disclosures, store declarations, requested browser
      permissions, and actual data flows agree.
- [ ] External audit, release-candidate soak, rollback rehearsal, and private
      vulnerability disclosure drill are complete.

## Non-goals

- CAPTCHA or anti-bot bypass
- stealth automation or platform-policy evasion
- credential, cookie, or session-token extraction
- unrestricted arbitrary JavaScript or CDP access
- ambient access to every browser tab
- compatibility claims without repeatable evidence
