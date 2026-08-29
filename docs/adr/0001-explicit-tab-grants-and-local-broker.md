# ADR 0001: Explicit tab grants through a local capability broker

- Status: Accepted and implemented for the Developer Preview
- Date: 2026-08-30
- Decision owners: Bootstrap maintainer

## Context

AI agents often use either an isolated automation browser or a bridge with broad
access to an existing signed-in browser. Re-authentication in an isolated profile
is inconvenient, while ambient access to a user's everyday profile creates a
large, poorly visible authority boundary.

We need a design that can use an existing authenticated tab without making every
tab, cookie, password, storage entry, or browser action implicitly available to
the agent. Page content is adversarial input and may attempt prompt injection.
Local processes may also attempt to connect to a broker.

## Decision

TabGrant will use a local broker plus a browser extension and explicit,
user-initiated tab capabilities.

- The extension owns browser privileges and trusted tab-grant UI. Browser-key
  pairing separately uses broker-owned OS user-presence UI as specified by
  [ADR 0002](./0002-os-user-presence-browser-pairing.md).
- The broker exposes typed actions to MCP clients and does not itself create
  browser authority.
- A grant is bound to a broker-generated connection session, client/task labels,
  browser context, tab, document, origin/scopes, constraints, and expiry.
- Policy is default-deny and re-evaluated immediately before execution.
- No write or sensitive-operation tool is currently exposed. Any future sensitive
  operation requires a separate trusted, action-bound approval decision.
- Page content never counts as permission or approval.
- Initial broker transport is local filesystem IPC: a Unix-domain socket on
  macOS/Linux and a named-pipe abstraction on Windows. It is not a TCP loopback
  service; remote relay is a separate decision.
- The default tool surface excludes credential/cookie/raw-storage extraction,
  arbitrary JavaScript, and raw network-body export.

## Alternatives considered

### Dedicated isolated browser

Provides a clean automation boundary but cannot directly use existing user
sessions and may encourage repeated sign-in or unsafe credential transfer. It
remains useful for untrusted automation but does not solve the selected-tab use
case.

### Attach directly through a debugging protocol

Offers broad capability and mature tooling, but its authority is much wider than
the desired grant model. Debugging access may expose all tabs, network data, and
script execution. TabGrant may use browser primitives internally only if the
same policy boundary and least-privilege contract can be preserved.

### Copy cookies or browser profile data

Rejected. It turns scoped task access into reusable authentication material,
increases exfiltration risk, and breaks the user's ability to reason about and
revoke a tab-level grant.

### Browser UI computer use only

Keeps actions visible but can be slow, brittle, and difficult to constrain or
audit semantically. It remains a fallback outside TabGrant rather than the core
protocol.

## Consequences

Positive consequences:

- authorization can be visible, revocable, and narrow;
- clients can share one policy contract without receiving raw browser authority;
- negative tests can target stable grant and action invariants.

Costs and risks:

- extension UI and lifecycle become security-critical;
- broker-owned OS pairing UI and its platform availability become
  security-critical;
- redirects, frames, browser restarts, races, and concurrent clients complicate
  enforcement;
- local-first does not prevent an agent/model from transmitting returned data;
- fewer arbitrary capabilities may limit compatibility with existing automation
  expectations;
- maintaining browser adapters and store distribution adds operational burden.

## Verification

The Developer Preview implements the local broker, session-bound capabilities,
extension grant UI, narrow tool surface, and negative tests described above. That
does not satisfy the [v1.0 criteria](../../ROADMAP.md), which still require
repeatable platform evidence, provenance, independent review, and consistency
between implementation and disclosures.
