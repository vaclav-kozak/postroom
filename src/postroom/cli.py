import argparse
import asyncio
import base64
import getpass
import logging
import os
import sys
from datetime import UTC, datetime

from postroom.accounts import AccountRepo, MailAccess
from postroom.config import Settings
from postroom.crypto import SecretBox, generate_key, hash_password, new_token, random_password
from postroom.db import Database
from postroom.importer.emclient import EmClientImportError, apply_import, parse_emclient_export


def _services_minimal() -> tuple[Settings, Database, SecretBox, AccountRepo]:
    settings = Settings()
    db = Database(settings.db_path)
    box = SecretBox(settings.master_key)
    repo = AccountRepo(db, box)
    return settings, db, box, repo


def _write_secret_file(path: str, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)


def _cmd_import_emclient(args: argparse.Namespace) -> int:
    if args.path == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.path, "rb") as f:
            data = f.read()

    passphrase = None
    xml = data
    if args.passphrase_first_line:
        first, _, rest = data.partition(b"\n")
        passphrase = first.rstrip(b"\r").decode()
        xml = rest
    elif args.passphrase_file:
        with open(args.passphrase_file, encoding="utf-8") as f:
            passphrase = f.read().strip()

    try:
        accounts = parse_emclient_export(xml, passphrase)
    except EmClientImportError as e:
        print(str(e), file=sys.stderr)
        return 2

    if args.dry_run:
        for a in accounts:
            dav = "yes" if (a.caldav_url or a.carddav_url) else "no"
            print(
                f"dry-run: {a.email} {a.provider.value} "
                f"{a.imap_host}:{a.imap_port}/{a.imap_security} dav={dav}"
            )
        return 0

    _, _, _, repo = _services_minimal()
    actions = apply_import(repo, accounts)
    for email, action in actions:
        acc = repo.get(email)
        print(f"{email}\t{action}\t{acc.status.value}")
    return 0


def _cmd_list_accounts(args: argparse.Namespace) -> int:
    _, _, _, repo = _services_minimal()
    print("email\tprovider\tstatus\tenabled\tmail_access\tlast_error")
    for acc in repo.list():
        print(
            f"{acc.email}\t{acc.provider.value}\t{acc.status.value}\t"
            f"{acc.enabled}\t{acc.mail_access.value}\t{acc.last_error or ''}"
        )
    return 0


def _cmd_set_access(args: argparse.Namespace) -> int:
    _, _, _, repo = _services_minimal()
    email = args.email.strip().lower()
    if not repo.set_mail_access(email, MailAccess(args.level)):
        print(f"unknown account: {email}", file=sys.stderr)
        return 1
    print(f"{email}\t{args.level}")
    return 0


def _cmd_gen_secrets(args: argparse.Namespace) -> int:
    master_key = generate_key()
    session_secret = new_token()
    password = random_password(32)
    hash_b64 = base64.b64encode(hash_password(password).encode()).decode()

    env_content = (
        f"POSTROOM_MASTER_KEY={master_key}\n"
        f"POSTROOM_SESSION_SECRET={session_secret}\n"
        f"POSTROOM_ADMIN_PASSWORD_HASH_B64={hash_b64}\n"
    )
    _write_secret_file(args.env_out, env_content)
    _write_secret_file(args.password_out, password + "\n")
    print(f"wrote {args.env_out} and {args.password_out}")
    return 0


def _cmd_hash_password(args: argparse.Namespace) -> int:
    password = sys.stdin.readline().rstrip("\n")
    print(base64.b64encode(hash_password(password).encode()).decode())
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from postroom.app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for name in ("httpx", "httpcore", "imapclient"):
        logging.getLogger(name).setLevel(logging.WARNING)
    # Uvicorn's proxy-header handling is off: the app's ClientAddressMiddleware believes
    # X-Forwarded-For / X-Real-IP only from POSTROOM_TRUSTED_PROXIES.
    # The access log is off: query strings may contain one-time codes (e.g. Google's
    # OAuth callback `code`).
    uvicorn.run(
        create_app(),
        host=args.host,
        port=args.port,
        proxy_headers=False,
        access_log=False,
        log_level="info",
    )
    return 0


def _cmd_check_accounts(args: argparse.Namespace) -> int:
    from postroom.app import build_services

    services = build_services(Settings())
    if args.email:
        emails = [e.strip().lower() for e in args.email]
    else:
        emails = [a.email for a in services.repo.list(include_disabled=False)]

    async def run() -> None:
        for email in emails:
            if services.repo.get(email) is None:
                print(f"unknown account: {email}", file=sys.stderr)
                continue
            await services.checker.check_account(email, manual=False)
            acc = services.repo.get(email)
            print(f"{acc.email}\t{acc.status.value}\t{acc.last_error or ''}")

    try:
        asyncio.run(run())
    finally:
        services.pool.close_all()
    return 0


def _cmd_set_password(args: argparse.Namespace) -> int:
    if args.stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("New admin password: ")
        if getpass.getpass("Repeat: ") != password:
            print("passwords do not match", file=sys.stderr)
            return 1
    if not password:
        print("password must not be empty", file=sys.stderr)
        return 1
    hash_b64 = base64.b64encode(hash_password(password).encode()).decode()
    print(f"POSTROOM_ADMIN_PASSWORD_HASH_B64={hash_b64}")
    return 0


def _provider():
    from postroom.auth.provider import PostroomOAuthProvider

    settings = Settings()
    return PostroomOAuthProvider(settings, Database(settings.db_path))


def _fmt_ts(ts: int | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cmd_create_api_key(args: argparse.Namespace) -> int:
    name = args.name.strip()
    if not 1 <= len(name) <= 60:
        print("API key name must be 1-60 characters", file=sys.stderr)
        return 2
    # Only the key itself goes to stdout, so it can be captured by a script.
    print(_provider().create_api_key(name))
    return 0


def _cmd_list_api_keys(args: argparse.Namespace) -> int:
    for k in _provider().list_api_keys():
        state = "revoked" if k.revoked else "active"
        print(
            f"{k.id}\t{k.name}\t{k.prefix}\t{_fmt_ts(k.created_at)}\t"
            f"{_fmt_ts(k.last_used_at)}\t{state}"
        )
    return 0


def _cmd_revoke_api_key(args: argparse.Namespace) -> int:
    provider = _provider()
    if not any(k.id == args.id for k in provider.list_api_keys()):
        print(f"no API key with id {args.id}", file=sys.stderr)
        return 1
    provider.revoke_api_key(args.id)
    print(f"revoked API key {args.id}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="postroom")
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser(
        "import-emclient",
        help="Advanced, optional: import IMAP accounts from an eM Client export",
        description=(
            "Advanced, optional feature: import IMAP accounts (and their CalDAV/CardDAV URLs) "
            "from an eM Client settings export. Google accounts must be connected in the admin "
            "UI. See docs/advanced/emclient-import.md."
        ),
    )
    p_import.add_argument("path", help="Path to the eM Client XML export, or - for stdin")
    p_import.add_argument("--passphrase-file", help="File containing the export passphrase")
    p_import.add_argument(
        "--passphrase-first-line",
        action="store_true",
        help="The first line of the input is the passphrase, the rest is the XML",
    )
    p_import.add_argument(
        "--dry-run", action="store_true", help="Print what would change, do nothing"
    )
    p_import.set_defaults(func=_cmd_import_emclient)

    p_list = sub.add_parser("list-accounts", help="List configured accounts")
    p_list.set_defaults(func=_cmd_list_accounts)

    p_access = sub.add_parser(
        "set-access",
        help="Set what the MCP tools may do with an account's mail",
        description=(
            "Set an account's mail access level: read (search, read, create drafts), "
            "organize (also mark read/flagged, move, trash, create folders) or full "
            "(also send). New and existing accounts default to full."
        ),
    )
    p_access.add_argument("email", help="The account's email address")
    p_access.add_argument("level", choices=[m.value for m in MailAccess])
    p_access.set_defaults(func=_cmd_set_access)

    p_gen = sub.add_parser(
        "gen-secrets", help="Generate master key, session secret and admin password"
    )
    p_gen.add_argument("--env-out", required=True, help="Where to write the .env fragment")
    p_gen.add_argument(
        "--password-out", required=True, help="Where to write the plaintext password"
    )
    p_gen.set_defaults(func=_cmd_gen_secrets)

    p_hash = sub.add_parser("hash-password", help="Hash a password read from stdin")
    p_hash.set_defaults(func=_cmd_hash_password)

    p_serve = sub.add_parser("serve", help="Run the HTTP server (behind the reverse proxy)")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=_cmd_serve)

    p_check = sub.add_parser(
        "check-accounts", help="Check accounts now (never retries needs_reconnect accounts)"
    )
    p_check.add_argument(
        "--email", action="extend", nargs="+", help="Only these accounts (default: all enabled)"
    )
    p_check.set_defaults(func=_cmd_check_accounts)

    p_setpw = sub.add_parser(
        "set-password", help="Print a new POSTROOM_ADMIN_PASSWORD_HASH_B64 line"
    )
    p_setpw.add_argument("--stdin", action="store_true", help="Read the password from stdin")
    p_setpw.set_defaults(func=_cmd_set_password)

    p_ckey = sub.add_parser("create-api-key", help="Create an MCP API key (printed once)")
    p_ckey.add_argument("name", help="A label for the key, e.g. claude-code-laptop")
    p_ckey.set_defaults(func=_cmd_create_api_key)

    p_lkeys = sub.add_parser("list-api-keys", help="List API keys (never prints the keys)")
    p_lkeys.set_defaults(func=_cmd_list_api_keys)

    p_rkey = sub.add_parser("revoke-api-key", help="Revoke an API key by id")
    p_rkey.add_argument("id", type=int)
    p_rkey.set_defaults(func=_cmd_revoke_api_key)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
