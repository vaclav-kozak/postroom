# Security design

Postroom holds the credentials of every mailbox, calendar and address book it connects.
This page describes how it protects them and what remains your responsibility. To report
a vulnerability, follow [SECURITY.md](../SECURITY.md); it also defines what is in scope.

## Who can do what

There are two kinds of callers:

- **The owner** (you), in the admin web UI. There is exactly one owner and no user
  management.
- **MCP clients** (Claude, Claude Code, scripts), on `/mcp`. A client needs either an OAuth
  access token that the owner approved on the consent screen, or an API key the owner
  created. Both carry the same rights; there are no per-client scopes.

What a client can do with each account is limited by that account's **mail access level**
(read, organize or full) and by the account's capabilities (calendar, tasks, contacts).
Levels are stored per account, checked on every call before any server is contacted, and
changes take effect immediately. Every account starts at **organize**, so no account can
send mail until the owner raises it to **full**.

## Owner authentication

- **Password.** The admin password is stored only as an argon2id hash, in
  `POSTROOM_ADMIN_PASSWORD_HASH_B64` in `.env`, never in the database. Login attempts are
  handled one at a time, so parallel guesses cannot race the lockout.
- **Lockout.** 5 failed logins from one IP within 15 minutes, or 20 in total within an
  hour, block further logins until the oldest failure leaves the window. A successful login
  does not erase failures.
- **Sessions.** A signed, timestamped cookie (`HttpOnly`, `SameSite=Lax`, `Secure` when the
  public URL is `https`) valid for 12 hours. The signature is bound to the current password
  hash, so a new password ends every session. Logging out bumps a session version in the
  database, which invalidates every session cookie issued so far, including copies.
- **CSRF.** Every state-changing request carries a CSRF token: the session's token when
  logged in, or one bound to a signed pre-login cookie on `/login`.
- **Headers.** Every response carries `Content-Security-Policy: default-src 'self';
  frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `X-Robots-Tag: noindex`. The templates contain no inline scripts or styles.

## OAuth 2.1 for MCP clients

Postroom is its own authorization server, so no third party is involved in granting access.

- **Dynamic client registration** accepts `https` redirect URIs only on the hosts listed in
  `POSTROOM_OAUTH_REDIRECT_HOSTS` (exact match, no implicit subdomains; default
  `claude.ai,claude.com`) and `http` redirect URIs only on loopback. Registration data is
  size-bounded, and the client table is capped (clients that never obtained a token are
  evicted first).
- **Consent.** Every authorization shows the owner the client's name, the host the code
  will be sent to, the redirect URI and what the client will be able to do, and needs an
  explicit **Allow**. Registering a client grants nothing by itself.
- **PKCE** with `S256` is required. Authorization codes live 5 minutes and are single-use;
  presenting a used code again revokes every token issued from it.
- **Tokens.** Access tokens live 1 hour and are accepted only for this server's own
  resource (RFC 8707 audience). Refresh tokens live 30 days and rotate on every use;
  replaying a rotated refresh token revokes its whole token family.
- **Storage.** Codes, access tokens, refresh tokens and API keys are stored only as SHA-256
  hashes. The plaintext is returned once and never logged. API keys start with `prm_` and
  never expire until revoked.
- **Rate limit.** `/login`, `/register`, `/authorize` and `/token` allow
  `POSTROOM_AUTH_RATE_LIMIT_PER_MINUTE` requests per minute per client IP (default 10,
  burst 10), answering `429` with `Retry-After` beyond that.

## Secrets at rest

- Account passwords and Google refresh tokens are encrypted with **AES-256-GCM** under
  `POSTROOM_MASTER_KEY`, with a random nonce per secret and the account bound in as
  associated data, so an encrypted secret cannot be moved to another account.
- The master key lives only in the environment (`.env`), never in the database. A stolen
  database or backup without `.env` reveals no credentials.
- **Losing the master key** makes the stored secrets unreadable. There is no recovery and
  no key rotation command: with a new key you re-enter every password and reconnect every
  Google account.
- Editing an account reuses its stored password only while its servers stay the same. A new
  IMAP host, SMTP host or CalDAV/CardDAV host needs the password typed again, so an admin
  session alone cannot send a stored password to another server.
- Google access tokens are kept in memory only.
- Secrets never appear in logs or error messages. The server keeps no HTTP access log,
  because query strings can carry one-time OAuth codes. Unexpected errors reach MCP clients
  as a generic message.

## Talking to mail and calendar servers

- **IMAP command injection.** Every inline IMAP argument (search terms, folder names,
  header values taken from received mail) is refused if it contains CR, LF or NUL, so input
  cannot end a command and start another.
- **TLS only.** IMAP and SMTP use SSL/TLS or STARTTLS, and there is no plain-text
  option. CalDAV and CardDAV URLs must be `https` (`http` only for `localhost`), checked
  before the password is decrypted. DAV credentials are sent only to the configured host:
  a calendar id is used only after it matches one of the account's discovered calendars,
  and CardDAV links to other hosts are ignored.
- **No permanent deletion.** There is no tool that expunges mail. `trash_emails` moves to
  Trash; a move uses `MOVE`, or `COPY` plus `UID EXPUNGE` of exactly the moved messages,
  never a folder-wide `EXPUNGE`, and refuses servers that support neither.
- **fail2ban safety.** One failed IMAP, CalDAV or CardDAV login marks the account
  "Login failed", and Postroom does not log in again until the owner fixes it or presses
  **Test now**. A password rejected by the SMTP server (a 5xx reply) pauses sending from
  that account in the same way; a temporary 4xx refusal does not. Each SMTP login makes
  exactly one AUTH attempt (PLAIN, else LOGIN; a server offering neither is refused before
  any attempt), so a wrong password costs one failed login, not one per mechanism. Logins
  for one account are serialised, including the admin's test login when an account is
  saved, so queued calls fail fast instead of repeating a wrong password.
- **Google accounts** connected with **Connect Google account** sign in to IMAP and SMTP
  with XOAUTH2 and a short-lived access token. When Gmail refuses a token, Postroom drops
  it and tries once with a fresh one; these failures never pause sending, since there is
  no password to fix. A Gmail mailbox added as an IMAP account signs in with its app
  password like any other IMAP account.

## Sending mail

- **Opt-in.** Sending needs the account's access level **full** and an outgoing server
  (SMTP, or a Google account). Every account starts at **organize**, including Google
  accounts (which need no SMTP settings) and imported ones, so nothing can send until the
  owner chooses **full** for that account. The consent screen tells the owner how many
  accounts can send.
- Every account can send at most `POSTROOM_SEND_LIMIT_PER_HOUR` emails in any 60 minutes
  (default 60). A rejected send still counts.
- **Duplicate guard.** An identical send (same account, recipients, subject, body and
  attachments) within 10 minutes is refused, and so is the same draft (by `Message-ID`)
  within an hour. `allow_duplicate=true` overrides it; the tool descriptions tell clients
  to use it only when the owner asked. The record is kept in memory: a restart clears it.
- **No automatic retries.** Sends are never retried. A timeout after the message data
  started says the email may already have been sent and tells the client to check Sent
  and ask the owner; a timeout before that says nothing was sent. When the connection
  drops mid-transfer, the Sent copy is marked with the keyword `$MaybeSent` (where the
  server supports keywords) and the error says not to retry automatically.
- **`send_draft`** sends only messages with the `\Draft` flag whose `From` (and `Sender`,
  if present) is one of the account's own addresses, so a message planted in Drafts by
  someone else cannot be sent as is. Concurrent calls for one draft send it once.
- Inline attachments on `send_email` are limited to 2 MiB in total (decoded).
  `forward_email` re-attaches at most 10 MiB, and `send_draft` sends drafts of up to
  10 MiB.
- Recipients, subjects and file names are validated and length-limited; header values
  cannot carry line breaks. `Bcc` is removed from the copy handed to the SMTP server.
- The tools tell clients to send only what the owner asked for and to treat email content
  as untrusted data. That is guidance to the model, not a guarantee: keep accounts that
  should never send at **read** or **organize**.

## Resource limits

Postroom runs comfortably in a 256 MiB container, including with hostile input:

- Mail up to 5 MiB is parsed whole; larger mail is read part by part, and only the parts
  that are needed are fetched. Header, HTML and text sizes are capped.
- Memory-heavy work (parsing, HTML to text, PDF extraction) runs one job at a time.
- PDF text is extracted in a separate Python process with an address-space limit
  (`RLIMIT_AS`), a 20-second timeout, a 50-page limit and a minimal environment that holds
  no `POSTROOM_*` secrets. PDFs over 5 MB and attachments over 10 MB return metadata only.
- Listings are capped: at most 100 search results per page, 500 events or tasks, 200
  messages per thread and 500 emails per batch call.
- Request bodies on `/mcp` are limited to 4 MiB (the MCP SDK's limit), and the OAuth
  endpoints accept at most 16 KiB. The bundled Caddy and the nginx example allow 4 MB on
  `/mcp` and 1 MB everywhere else.
- Sending a large message, like reading one, runs under the same one-at-a-time gate for
  memory-heavy work. Outgoing mail is capped at 10 MiB (see above), and a message is sent
  over SMTP and filed in Sent without further copies of its body.

The compose files run the container read-only, as a non-root user, with all capabilities
dropped, `no-new-privileges`, a 256 MB memory limit and a process limit.

## Client IP addresses

The login lockout and the rate limits work per client IP, so the IP must not be forgeable.
Postroom believes `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto` only when the
connection comes from an address in `POSTROOM_TRUSTED_PROXIES`, and strips them from every
other connection. `X-Forwarded-For` is read from the right, skipping trusted proxies. Your
reverse proxy must set or overwrite `X-Forwarded-For`, not append to a client-supplied one.

## If something is stolen

| What | What the holder can do | What to do |
|---|---|---|
| An OAuth access or refresh token | Call every tool the approved app could, within each account's access level, until the tokens expire (refresh tokens: 30 days, renewed on use). | **Admin → Authorized apps → Revoke**. This revokes all of that client's tokens and deletes the client. |
| An API key | The same, with no expiry. | **Admin → API keys → Revoke**, or `postroom revoke-api-key <id>`. |
| The admin password | Everything, including approving new clients. | Set a new password (`postroom set-password`, update `.env`, restart); all sessions end. Then review Authorized apps and API keys and revoke anything you do not recognise. |
| The database without `.env` | Nothing useful: secrets are encrypted, tokens are hashes. | Nothing urgent. |
| `.env` and the database | All stored mailbox passwords and Google refresh tokens. | Change every mailbox password, revoke Postroom in each Google account's security settings, and generate new secrets. |

To cut off access quickly without revoking anything, disable the account in the admin or
lower its access level; both apply to the next tool call.

## Out of scope

Postroom cannot protect against someone who controls the host, the reverse proxy or
`.env`, or against an approved MCP client that misuses the tools it was granted. Email
content is untrusted input: a message can contain instructions aimed at the model.
Postroom's server instructions tell clients never to follow them, and the access levels
limit the damage if a client does.
