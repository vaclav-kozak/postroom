# Importing accounts from eM Client (advanced, optional)

If you already have your mailboxes set up in [eM Client](https://www.emclient.com/), Postroom
can read an eM Client settings export and create the accounts in one go. Most people do not
need this: adding accounts in the admin UI works just as well.

## What gets imported

- **IMAP accounts:** email, display name, IMAP host, port, security, login name and password.
  Imported accounts start as `pending`, and the background checker tests them.
- **Outgoing mail (SMTP):** host, port and security, when the SMTP account uses the same
  password as IMAP (and its login name when that differs). An SMTP account with a different
  password is skipped: add it in the admin UI. Sending still needs the account's access level
  set to "full" (the default).
- **CalDAV/CardDAV URLs** of those accounts, but only `https` ones (`http` only on loopback).
- **Google accounts** are created without credentials. The refresh tokens in an eM Client
  export belong to eM Client's own OAuth client, so Postroom cannot use them. Reconnect each
  Google account in the admin UI.
- Accounts without IMAP (for example pure CalDAV accounts) are skipped.

Running the import again updates existing accounts instead of duplicating them.

## Export from eM Client

1. In eM Client open **Menu → File → Export**. Choose to export the **settings** (accounts) to
   an XML file.
2. Protect the export with a password when eM Client offers it. The file then contains your
   mailbox passwords only in encoded form. You will need that password (the "passphrase") for
   the import.

Treat the export as a secret: it holds every mailbox password. Delete it after the import.

## Run the import

The command reads the export from a file or from stdin (`-`). Give the passphrase either as the
first line of the input (`--passphrase-first-line`) or in a file (`--passphrase-file`).
Add `--dry-run` to see what would be imported without changing anything.

Put the passphrase on the first line, followed by the XML:

```sh
(cat passphrase.txt; cat export.xml) > export-with-passphrase.txt
```

**Docker Compose** (service named `postroom`):

```sh
docker compose exec -T postroom postroom import-emclient - --passphrase-first-line \
  < export-with-passphrase.txt
```

**Local install with uv** (run it with the same `POSTROOM_*` environment as the server, at
least `POSTROOM_DB_PATH`, `POSTROOM_MASTER_KEY` and `POSTROOM_SESSION_SECRET`):

```sh
uv run postroom import-emclient export.xml --passphrase-file passphrase.txt
```

Afterwards check the result with `postroom list-accounts`, or in the admin UI.
