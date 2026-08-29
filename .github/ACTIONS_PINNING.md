# GitHub Actions pin inventory

Every action in an executable workflow must use a reviewed full commit SHA.
Exact release tags are recorded for readability and provenance, but they are not
the trust boundary. Dependabot may propose digest updates, but a maintainer must
verify the tag and commit in the action's official repository before merging.

Verified from the official repositories on 2026-08-30:

| Action                             | Reviewed tag | Pinned commit                              |
| ---------------------------------- | ------------ | ------------------------------------------ |
| `actions/checkout`                 | `v4.4.0`     | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-node`               | `v4.4.0`     | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `pnpm/action-setup`                | `v4.3.0`     | `b906affcce14559ad1aafd4ab0e942779e9f58b1` |
| `github/codeql-action`             | `v3.37.9`    | `6f5948dfacef28e207b48d0905cf90c03365536d` |
| `actions/dependency-review-action` | `v5.0.0`     | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |

Review action updates for maintainer changes, release notes, runtime changes,
permissions, network behavior, and mutable dependencies. Re-run the pin audit
before any Developer Preview artifact is tagged.
