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
- **Mail** for any IMAP server and for Gmail / Google Workspace, through Google OAuth or as
  an IMAP account with a Google app password:
  `list_accounts`, `list_folders`, `search_emails` (across accounts, Gmail search syntax on
  Gmail), `get_email`, `get_thread`, `get_attachment` (text, PDF text, images) and
  `create_draft` (including threaded replies).
- **Organising mail:** `mark_emails`, `move_emails` (Gmail-aware archive), `trash_emails`
  and `create_folder`, in batches of up to 500 emails across accounts. No tool deletes
  mail permanently: `trash_emails` moves to Trash, and `send_draft` removes only the draft
  it just sent.
- **Sending mail** over SMTP (or Gmail with OAuth): `send_email` (with reply, reply-all and
  up to 2 MiB of attachments), `forward_email` and `send_draft`, with a copy in Sent, a
  per-account hourly limit (`POSTROOM_SEND_LIMIT_PER_HOUR`), a duplicate-send guard
  (`allow_duplicate` to override) and `$MaybeSent` on Sent copies whose delivery is
  uncertain. Sends are never retried.
- **Per-account mail access levels:** read, organize and full, set in the admin UI (per
  account, or for all accounts at once), with `postroom set-access EMAIL LEVEL` or with
  `postroom set-access --all LEVEL`. Accounts start at organize: sending is opt-in.
- **Configurable time zone** (`POSTROOM_TIMEZONE`, an IANA name, default `UTC`) for
  date-times without a UTC offset, new calendar events and the admin UI. An invalid value
  stops startup with a clear configuration error.
- **Calendars and tasks** for Google Calendar, Google Tasks and any CalDAV server:
  `list_calendars`, `list_events`, `create_event`, `update_event`, `delete_event`,
  `list_task_lists`, `list_tasks`, `create_task`, `update_task`, `delete_task`. No tool
  invites attendees; events and tasks with attendees or recurrence are read-only.
- **Contacts:** `search_contacts` for Google Contacts and any CardDAV address book.
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
  proxies (4 MB request bodies on `/mcp`, 1 MB elsewhere).
- **Command line:** `serve`, `gen-secrets`, `set-password`, `hash-password`,
  `list-accounts`, `set-access`, `check-accounts`, `create-api-key`, `list-api-keys`,
  `revoke-api-key` and `import-emclient` (import from an eM Client export).

### Notes

- **Sending is off until you turn it on.** Every account starts at access level
  "organize", including Google accounts (which need no SMTP settings) and imported
  accounts, so no account can send until you set it to "full" in the admin UI or with
  `postroom set-access`.

[Unreleased]: https://github.com/vaclav-kozak/postroom/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vaclav-kozak/postroom/releases/tag/v0.1.0
