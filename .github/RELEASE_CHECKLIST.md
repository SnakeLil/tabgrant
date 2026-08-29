# Developer Preview release checklist

TabGrant has no supported npm package or browser-store distribution. This
checklist applies only to a source or artifact GitHub prerelease. Public Alpha,
stable, npm, and browser-store releases remain blocked by the roadmap and
governance gates.

## Before tagging

- [ ] The exact commit passed `pnpm check`, `pnpm build`, and `pnpm pack:smoke`.
- [ ] Action references are reviewed full commit SHAs and workflow permissions
      remain least-privilege.
- [ ] Browser permissions, data flows, security limitations, and privacy text
      match the built artifacts.
- [ ] Tests use a disposable profile and synthetic accounts; the release notes
      identify the exact environments actually exercised.
- [ ] No critical or high-severity vulnerability is known to remain open.
- [ ] The changelog distinguishes implemented behavior from roadmap work.
- [ ] The release owner is `@SnakeLil`; no local npm token or browser-store
      credential is used.

## GitHub prerelease

- [ ] Mark the GitHub Release as a **prerelease** and include “Developer Preview”
      in its title and opening paragraph.
- [ ] State that there is no production support, stable compatibility promise,
      completed security audit, npm release, or browser-store release.
- [ ] Link the exact commit and include SHA-256 checksums for uploaded artifacts.
- [ ] Include an SBOM and provenance/attestation when binary or extension
      artifacts are uploaded; otherwise state that only source archives exist.
- [ ] List security-relevant changes, browser permission changes, known
      limitations, and rollback or uninstall steps.
- [ ] Confirm the vulnerability-reporting route described in `SECURITY.md` is
      accurate at publication time.

## After publishing

- [ ] Verify every link, checksum, archive, and prerelease badge from a logged-out
      session.
- [ ] Record the release evidence and any failed or deferred gate without
      upgrading the support claim.
