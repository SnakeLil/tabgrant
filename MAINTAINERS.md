# Maintainers

TabGrant is currently in single-maintainer bootstrap governance. This is
appropriate for the source-only Developer Preview, but not for a supported or
stable release.

## Active maintainers

| Maintainer      | GitHub      | Responsibilities                                       |
| --------------- | ----------- | ------------------------------------------------------ |
| Project founder | `@SnakeLil` | Bootstrap stewardship, review, and release preparation |

## Security owners

`@SnakeLil` is the bootstrap security owner. No independent backup security
owner has been established. This blocks Public Alpha package/store distribution,
a stable release, and any claim of two-person release control.

## Current confidential intake

GitHub private vulnerability reporting is the canonical security-reporting
channel and the temporary confidential Code of Conduct channel for the public
Developer Preview. Because GitHub exposes that setting for public repositories,
it must be enabled immediately on publication and verified before announcement.
This bootstrap arrangement is not an independent escalation path and does not
satisfy the requirements for a supported public artifact.

## Required before a supported public artifact

- appoint a second active security owner and update CODEOWNERS;
- publish monitored, role-based security and conduct contacts with an independent
  escalation path;
- require 2FA for organization members;
- protect the default branch and release environments;
- assign backup ownership for GitHub, npm, extension-store, and signing assets.

Publishing the source repository as a clearly labeled Developer Preview does
not satisfy or bypass these artifact-release requirements. Preview tags and
GitHub Releases must remain marked as prereleases and must not imply supported
npm or browser-store availability.

Role definitions, appointment, inactivity, and removal are described in
[GOVERNANCE.md](./GOVERNANCE.md).
