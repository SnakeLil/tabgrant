## Problem

<!-- What user or contributor problem does this solve? Link the issue/RFC. -->

## Solution

<!-- Describe the change and important implementation choices. -->

## Non-goals

<!-- State what this pull request intentionally does not address. -->

## Security and privacy

Check exactly one classification:

- [ ] No browser permission, host access, grant scope, approval behavior, browser
      pairing or key lifecycle, OS user-presence requirement, protocol authentication,
      telemetry, persistence, logging, or release trust changes.
- [ ] Those changes are described below, threat-modeled, documented, and have
      the required security-owner reviews.

Required for every pull request:

- [ ] Tests use synthetic data and disposable browser state.
- [ ] Logs, fixtures, screenshots, and examples contain no credentials, cookies,
      tokens, pairing codes, private keys, grant secrets, private URLs, or private
      page content.

Security/privacy impact:

<!-- Data read/written, permissions, trust boundaries, abuse cases, failure mode. -->

## Compatibility and migration

<!-- Protocol, browser, client, configuration, or user-facing migration impact. -->

## Verification

- [ ] `pnpm check`
- [ ] `pnpm build`
- [ ] Positive behavior is tested.
- [ ] Denied/error behavior is tested where authority is involved.
- [ ] Documentation and current-vs-roadmap status are accurate.
- [ ] The change does not imply stable support, a completed audit, or public
      package/browser-store availability.
- [ ] A changeset is included for a user-facing CLI change, or the omission is
      explained below.

Evidence:

<!-- Commands, sanitized output, screenshots, or explanation of checks not run. -->

## Release note

<!-- User-facing summary, or "Not user-facing". -->

Changeset omission or Developer Preview limitation:

<!-- Explain omitted changeset, checks not run, unsupported environments, or remaining preview risk. -->
