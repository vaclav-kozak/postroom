# Security policy

Postroom holds the credentials of every mailbox, calendar and address book of its owner.
Security reports are very welcome.

## Supported versions

Only the latest release (the `latest` image tag) receives security fixes. Please upgrade
before reporting.

## Reporting a vulnerability

Report vulnerabilities **privately** through GitHub Security Advisories: open the
[Security tab](https://github.com/vaclav-kozak/postroom/security) and click
**Report a vulnerability**. Please do not open a public issue, pull request or discussion.

Include the affected version, a description of the issue and its impact, and steps or a
proof of concept to reproduce it. Never include real credentials or email content. You will
get an acknowledgement within a few days; fixes are released as soon as practical and
credited in the advisory unless you prefer otherwise.

## Threat model and scope

Postroom is a single-owner server. In scope, among others:

- **Owner-only admin.** The admin UI has exactly one user, authenticated with an argon2-hashed
  password, signed session cookies bound to the password hash, CSRF tokens on every
  state-changing request, and a per-IP and global login lockout. Any way for someone other
  than the owner to reach the admin UI or its actions is a vulnerability.
- **OAuth 2.1 for MCP clients.** Dynamic client registration only accepts https redirect URIs
  on allow-listed hosts (`POSTROOM_OAUTH_REDIRECT_HOSTS`, exact match) or http on loopback,
  and every authorization needs the owner's explicit consent. Obtaining a token without that
  consent, or redirecting a code elsewhere, is in scope.
- **Secrets at rest.** Account passwords and tokens are encrypted with AES-256-GCM under the
  master key (`POSTROOM_MASTER_KEY`), which is never stored in the database.
- **IMAP command injection.** Untrusted input (search terms, folder names, header values from
  received mail) must not be able to inject IMAP commands; arguments containing CR, LF or NUL
  are rejected.
- **Resource exhaustion** by crafted mail, attachments, calendar or contact data, and
  spoofing the client IP to evade the login lockout or the auth rate limit.
- **Leaks** of secrets or email content through error messages or logs.

Out of scope: attacks that need the owner's `.env` or master key, root on the host or
control of the reverse proxy; the MCP client itself deciding to misuse the tools it was
granted (email content is untrusted input and clients should treat it as such); denial of
service by sheer traffic volume; findings from automated scanners without a demonstrated
impact.
