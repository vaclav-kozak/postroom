# Provider settings

Settings for adding common providers as IMAP accounts in Postroom. Your provider's own
help pages are the authority; server names do change occasionally.

A few rules apply to every provider:

- **App passwords.** If your account uses two-step sign-in, create an app password (also
  called app-specific or device password) in the provider's account settings and use it in
  Postroom. Many providers refuse the normal password over IMAP.
- **One password.** Postroom signs in to IMAP, SMTP, CalDAV and CardDAV with the same
  password. The SMTP username can differ (it defaults to the IMAP username); CalDAV and
  CardDAV always use the IMAP username.
- **CalDAV and CardDAV.** Enter any URL from which the server can find your calendars or
  address books. Postroom asks the server for your principal and home set, so the server's
  root DAV URL is usually enough. The URLs must be `https` (`http` only for `localhost`),
  and Postroom sends your password only to the host in the URL you entered.
- **Calendars and tasks** come from the same CalDAV URL: calendars that hold events show up
  in `list_calendars`, and those that hold tasks (VTODO) in `list_task_lists`.

## Mail

| Provider | IMAP | SMTP | Notes |
|---|---|---|---|
| Gmail / Google Workspace | — | — | Use **Connect Google account**; see [Google setup](google-setup.md). App passwords for `imap.gmail.com` do not work in Postroom. |
| Fastmail | `imap.fastmail.com`, 993, SSL/TLS | `smtp.fastmail.com`, 465, SSL/TLS | Needs an app password (Settings → Privacy & Security → App passwords) with IMAP, SMTP and, for calendars and contacts, CalDAV/CardDAV access. |
| iCloud Mail | `imap.mail.me.com`, 993, SSL/TLS | `smtp.mail.me.com`, 587, STARTTLS | Needs an app-specific password from your Apple Account settings. |
| Yahoo Mail | `imap.mail.yahoo.com`, 993, SSL/TLS | `smtp.mail.yahoo.com`, 465, SSL/TLS | Needs an app password from Yahoo's account security page. |
| mailcow | `<mail-host>`, 993, SSL/TLS | `<mail-host>`, 465, SSL/TLS (or 587, STARTTLS) | Use your mailbox password or a mailcow app password. |
| Nextcloud Mail, Zimbra, Dovecot, other servers | from your provider | from your provider | Any IMAP4rev1 server works. |
| Microsoft 365 / Outlook.com | not supported | not supported | Microsoft turned off password sign-in for IMAP and SMTP, and Postroom has no Microsoft OAuth yet. |

## Calendar and contacts

`<email>` is your full email address and `<user>` your username on that server.

| Server | CalDAV URL | CardDAV URL | Status |
|---|---|---|---|
| mailcow / SOGo | `https://<mail-host>/SOGo/dav/<email>/` | `https://<mail-host>/SOGo/dav/<email>/` | Used in production. |
| Radicale | `https://<host>/<user>/` | `https://<host>/<user>/` | Covered by the integration tests. |
| Nextcloud | `https://<host>/remote.php/dav/` | `https://<host>/remote.php/dav/` | Standard Nextcloud DAV endpoint; use an app password if two-factor sign-in is on. |
| Baïkal | `https://<host>/dav.php/` | `https://<host>/dav.php/` | Standard Baïkal endpoint. |
| Fastmail | `https://caldav.fastmail.com/dav/` | `https://carddav.fastmail.com/dav/` | Fastmail's documented DAV servers. |
| iCloud | `https://caldav.icloud.com/` | `https://contacts.icloud.com/` | Not verified. iCloud moves each account to its own server host (`pNN-...icloud.com`); Postroom's CardDAV client does not follow links to another host, so contacts may not work. |
| Zimbra and others | check your provider's docs | check your provider's docs | Any CalDAV/CardDAV server that supports principal discovery should work. |

Only mailcow/SOGo and Radicale have been tested with Postroom. If you get another provider
working, or find a URL here wrong, please open an issue or a pull request.

## Troubleshooting

- **"Test login failed"** when saving: check the server, port and security first. Port 993
  goes with SSL/TLS, 143 with STARTTLS; for SMTP, 465 with SSL/TLS and 587 with STARTTLS.
  Then check the username (some providers want the full address, others only the part
  before `@`) and whether the provider needs an app password.
- **An account shows "Login failed".** Postroom stops using an account after one failed
  login, so that a changed password never gets your server banned by the provider's
  fail2ban. Fix the password with **Edit**, or click **Test now** after fixing it at the
  provider.
- **No calendars or contacts.** The account has `calendar`, `tasks` or `contacts` in its
  capabilities only when the matching URL is set. Check that the URL is `https` and that
  the server offers CalDAV/CardDAV to that user.
