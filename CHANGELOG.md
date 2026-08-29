# Changelog

All notable user-facing changes to TabGrant will be documented in this file.
The project follows Semantic Versioning once packages are published. Changesets
remain the source for future package release notes.

## 0.1.0 — Developer Preview source release

Initial source release for local development and security evaluation.

- Includes the TabGrant broker CLI, MCP adapter, Native Messaging host, and MV3
  extension source.
- Supports development and evaluation on macOS and Linux with explicitly scoped,
  user-granted access to the active browser tab.
- Automated Chrome for Testing coverage does not yet prove the production OS
  pairing prompt, a real toolbar `activeTab` gesture, or branded-browser support.
- Ships as source only. `tabgrant@0.1.0` has not been published to npm, and no
  browser-store package or supported binary release exists.
- Has not completed an independent security audit and is not intended for
  production or valuable accounts.
