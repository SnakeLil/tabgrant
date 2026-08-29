# Security Policy

## Developer Preview

TabGrant handles a high-risk boundary between agents and authenticated browser
sessions. It has not completed a security audit and is not suitable for
production or valuable accounts. No version is currently designated as a
supported security release.

| Version or channel        | Security support                        |
| ------------------------- | --------------------------------------- |
| Default branch            | Best-effort fixes; no stability promise |
| Developer Preview tags    | Unsupported prereleases                 |
| npm/browser-store release | None currently published or supported   |

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected
vulnerability. Do not include credentials, tokens, cookies, pairing codes,
private keys, private URLs, page content, or exploit details in public channels.

The project's canonical confidential intake is
[GitHub private vulnerability reporting](https://github.com/SnakeLil/tabgrant/security/advisories/new).
Use the repository's **Security → Report a vulnerability** form. Private
vulnerability reporting must be enabled immediately when the repository becomes
public, verified before the project is announced, and kept available while the
public Developer Preview is maintained.

If that form or button is not visible, confidential intake is not operational.
Do not send exploit details through an issue, pull request, discussion, email, or
unsolicited message. Repository administrators should treat loss of the private
reporting channel as a publication incident and restore it before directing users
to report vulnerabilities. The project does not currently advertise a fallback
email address.

Include, when safe:

- affected commit or version;
- browser, operating system, and agent/client;
- prerequisite permissions and grant state;
- minimal reproduction steps;
- observed and expected authorization decisions;
- impact and whether authentication material was exposed;
- suggested mitigation, if known.

Do not test against accounts, data, or systems you do not own or have explicit
permission to use.

## Response targets

These are project targets, not a service-level agreement:

| Stage                       | Target                     |
| --------------------------- | -------------------------- |
| Acknowledge report          | 3 business days            |
| Initial severity assessment | 7 business days            |
| Status update               | Every 14 days while active |

The project will coordinate disclosure, credit reporters who want credit, and
publish a GitHub Security Advisory for confirmed release-impacting issues.
Public disclosure should wait until a fix or documented mitigation is available,
unless continued confidentiality creates greater user risk.

## Security release policy

Before the first supported release, maintainers must document which versions
receive fixes and rehearse advisory and revocation procedures. Private
vulnerability reporting is an operating requirement for the public source
preview, not a future release feature. During Developer Preview, fixes may be
available only on the default branch. Preview GitHub Releases must be marked as
prereleases. A release must not be described as secure merely because no
vulnerabilities have been reported.

## Security invariants

The intended invariants are documented in
[docs/SECURITY_ARCHITECTURE.md](./docs/SECURITY_ARCHITECTURE.md). They are release
requirements until tests and an audit establish them as implemented guarantees.
