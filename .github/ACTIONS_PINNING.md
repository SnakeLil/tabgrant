# GitHub Actions pin inventory

Every action in an executable workflow must use a reviewed full commit SHA.
Exact release tags are recorded for readability and provenance, but they are not
the trust boundary. Dependabot may propose digest updates, but a maintainer must
verify the tag and commit in the action's official repository before merging.

Verified from the official repositories on 2026-08-30:

| Action                             | Reviewed tag | Pinned commit                              |
| ---------------------------------- | ------------ | ------------------------------------------ |
| `actions/checkout`                 | `v7.0.1`     | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node`               | `v7.0.0`     | `820762786026740c76f36085b0efc47a31fe5020` |
| `pnpm/action-setup`                | `v6.0.10`    | `0977fd99725f1db4007ccb2928dbb4e90d06cc86` |
| `github/codeql-action`             | `v4.37.9`    | `cdf488f595d80d6e07e03d4674febd5ab45fa938` |
| `actions/dependency-review-action` | `v5.0.0`     | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |

These versions declare the Node.js 24 action runtime. GitHub-hosted runners are
managed by GitHub; any future self-hosted runner must be at least
[`v2.327.1`](https://github.com/actions/runner/releases/tag/v2.327.1) before these
actions are used.

Review action updates for maintainer changes, release notes, runtime changes,
permissions, network behavior, and mutable dependencies. Re-run the pin audit
before any Developer Preview artifact is tagged.
