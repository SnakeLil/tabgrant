# Governance

## Principles

TabGrant is governed in the open. Decisions should preserve user agency, least
privilege, reviewability, and accurate claims about implementation status.
Security and privacy requirements take priority over tool count or convenience.

## Roles

### Contributors

Anyone who participates through issues, documentation, code, testing, or design.

### Reviewers

Contributors trusted by maintainers to review an area. Reviewers may approve but
do not merge unless they are also maintainers.

### Maintainers

People responsible for triage, review, merges, releases, moderation, and project
direction. Current membership is recorded in [MAINTAINERS.md](./MAINTAINERS.md).

### Security owners

Maintainers designated to review changes to permissions, policy, approval,
authentication, redaction, telemetry, release workflows, and security reports.
Before Public Alpha package or browser-store distribution, at least two security
owners must be active. A source-only Developer Preview may operate with the
bootstrap security owner identified in MAINTAINERS.md if that limitation remains
prominent.

## Decisions

Routine changes use pull-request consensus. A maintainer may merge after required
checks and ownership reviews pass and material objections are resolved.

An RFC is required for:

- protocol or public API changes;
- new browser permissions or host access;
- new action categories or approval semantics;
- telemetry, persistence, or third-party data transfer;
- compatibility or deprecation policy changes;
- governance, licensing, or release-process changes.

RFCs should remain open for at least seven calendar days unless they only address
an urgent vulnerability. Security fixes may be developed privately and
documented after coordinated disclosure.

If consensus cannot be reached, maintainers seek a two-thirds majority. A
security owner may block a release-affecting change that violates a documented
security invariant; the block must identify the invariant and evidence needed to
resolve it.

## Protected changes

Changes to extension permissions, policy enforcement, approval UI, protocol
authentication, logging/telemetry, package publishing, store submission, or this
governance model require two maintainer approvals once two maintainers exist.
Until then, the project must not claim the equivalent two-person control or issue
a supported package/store release. A single bootstrap maintainer may merge
Developer Preview work after required checks pass, but must record security and
privacy implications in the pull request.

## Becoming a maintainer

Candidates should demonstrate sustained, constructive contributions; sound
security judgment; reliable review; and Code of Conduct alignment. Existing
maintainers nominate candidates and approve them by two-thirds vote. Access must
use individual accounts with 2FA; release owners should use hardware-backed
authentication where available.

## Inactivity and removal

A maintainer inactive for six months may be moved to emeritus status after a
private check-in and a 30-day response period. Access may be removed immediately
for account compromise, serious policy violation, or at the maintainer's request.
Code of Conduct removals follow a conflict-free review process.

## Conflicts of interest

Decision-makers disclose relevant employment, financial, or personal interests
and recuse themselves when impartial review is not possible.

## Project assets

The GitHub organization, npm scope, browser-store publisher, signing identities,
domains, and security inbox are project assets. No single maintainer should be
the only recovery path before Public Alpha distribution. Access is
least-privilege and reviewed at least quarterly.

## Amendments

Governance changes require an RFC, a 14-day comment period, and approval by
two-thirds of active maintainers.
