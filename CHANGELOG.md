# Changelog

All notable changes to Postroom are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-28

First public release.

### Added

- **Remote MCP server** over Streamable HTTP at `/mcp`, with 25 tools and MCP tool
  annotations (read-only, destructive, idempotent) on every tool.
- **Mail** for any IMAP server and for Gmail / Google Workspace through Google OAuth:
  `list_accounts`, `list_folders`, `search_emails` (across accounts, Gmail search syntax on
  Gmail), `get_email`, `get_thread`, `get_attachment` (text, PDF text, images) and
  `create_draft` (including threaded replies).
- **Organising mail:** `mark_emails`, `move_emails` (Gmail-aware archive), `trash_emails`
  and `create_folder`, in batches of up to 500 emails across accounts. Nothing is ever
  deleted permanently.
- **Sending mail** over SMTP (or Gmail with OAuth): `send_email` (with reply, reply-all and
  attachments), `forward_email` and `send_draft`, with a copy in Sent and a per-account
  hourly limit (`POSTROOM_SEND_LIMIT_PER_HOUR`).
- **Per-account mail access levels:** read, organize and full, set in the admin UI or with
  `postroom set-access`.
- **Calendars and tasks** for Google Calendar, Google Tasks and CalDAV servers:
  `list_calendars`, `list_events`, `create_event`, `update_event`, `delete_event`,
  `list_task_lists`, `list_tasks`, `create_task`, `update_task`, `delete_task`. No tool
  invites attendees; events and tasks with attendees or recurrence are read-only.
- **Contacts:** `search_contacts` for Google Contacts and CardDAV address books.
- **OAuth 2.1 authorization server** with PKCE (S256), dynamic client registration limited
  to allow-listed redirect hosts (`POSTROOM_OAUTH_REDIRECT_HOSTS`), an owner consent screen,
  and rotating refresh tokens with family revocation. API keys (`prm_...`) for clients
  without OAuth.
- **Owner-only admin web UI:** accounts (add, test, edit, disable, remove), access levels,
  outgoing mail settings, Google account connection, authorized apps and API keys. Works on
  phones and in dark mode.
- **Security:** AES-256-GCM encryption of stored secrets under `POSTROOM_MASTER_KEY`,
  argon2id admin password, login lockout, CSRF protection, per-IP rate limit on the login
  and OAuth endpoints (`POSTROOM_AUTH_RATE_LIMIT_PER_MINUTE`), trusted-proxy handling of
  forwarded client addresses (`POSTROOM_TRUSTED_PROXIES`), IMAP command-injection guard,
  memory-bounded parsing and PDF extraction in a memory-limited child process.
- **Background account checks** that never retry a failed login (fail2ban-safe).
- **Deployment:** multi-arch Docker image on GHCR, `docker-compose.yml` with bundled Caddy
  and automatic HTTPS, `docker-compose.proxy.yml` and an nginx example for existing reverse
  proxies.
- **Command line:** `serve`, `gen-secrets`, `set-password`, `hash-password`,
  `list-accounts`, `set-access`, `check-accounts`, `create-api-key`, `list-api-keys`,
  `revoke-api-key` and `import-emclient` (import from an eM Client export).

[Unreleased]: https://github.com/vaclav-kozak/postroom/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vaclav-kozak/postroom/releases/tag/v0.1.0
