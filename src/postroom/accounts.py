import time
from dataclasses import dataclass
from enum import StrEnum

from postroom.crypto import SecretBox
from postroom.db import Database


class Provider(StrEnum):
    IMAP = "imap"
    GOOGLE = "google"


class AccountStatus(StrEnum):
    PENDING = "pending"
    CONNECTED = "connected"
    ERROR = "error"
    NEEDS_RECONNECT = "needs_reconnect"
    NEEDS_GOOGLE_CONNECT = "needs_google_connect"


class SmtpStatus(StrEnum):
    """The last SMTP login's outcome (None: never tried). Separate from `AccountStatus`,
    which is about IMAP: an account can read mail fine while its SMTP login fails."""

    OK = "ok"
    ERROR = "error"
    AUTH_FAILED = "auth_failed"


# Google accounts send through Gmail's SMTP server with the account's OAuth access token
# (XOAUTH2); the https://mail.google.com/ scope covers SMTP as well as IMAP.
GMAIL_SMTP = ("smtp.gmail.com", 465, "ssl")


class MailAccess(StrEnum):
    """What the MCP tools may do with an account's mail. Each level includes the ones before.

    read: search, read and create drafts. organize: also change flags, move, trash and
    create folders. full: also send mail.
    """

    READ = "read"
    ORGANIZE = "organize"
    FULL = "full"

    @property
    def rank(self) -> int:
        return list(MailAccess).index(self)


# How an access level is named in an error message.
_ACCESS_LABEL = {
    MailAccess.READ: "read-only",
    MailAccess.ORGANIZE: "organize-only (no sending)",
    MailAccess.FULL: "full",
}


ACCESS_HINT = (
    "the owner can change this in the admin UI (the account's access level) "
    "or with the `postroom set-access` command"
)


class MailAccessDenied(Exception):
    """A mail operation needs a higher access level than the account allows."""

    def __init__(self, email: str, level: MailAccess):
        super().__init__(
            f"account {email} is set to {_ACCESS_LABEL[level]} mail access; {ACCESS_HINT}"
        )


class SendingDisabled(Exception):
    """The account may not send mail: its access level is below "full", or it has no
    outgoing (SMTP) server."""


@dataclass(frozen=True)
class Account:
    id: int
    email: str
    display_name: str | None
    provider: Provider
    imap_host: str | None
    imap_port: int | None
    imap_security: str | None
    imap_username: str | None
    caldav_url: str | None
    carddav_url: str | None
    has_secret: bool
    enabled: bool
    status: AccountStatus
    last_error: str | None
    last_ok_at: int | None
    last_check_at: int | None
    # Fail closed: an Account built without a level may only read. Stored accounts always
    # carry theirs (the database default for them is "full").
    mail_access: MailAccess = MailAccess.READ
    # Outgoing mail (IMAP accounts only; no host = no sending). The password is the IMAP one.
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_security: str | None = None
    smtp_username: str | None = None
    smtp_status: SmtpStatus | None = None
    smtp_error: str | None = None
    smtp_checked_at: int | None = None

    @property
    def is_gmail(self) -> bool:
        return (
            self.provider == Provider.GOOGLE or (self.imap_host or "").lower() == "imap.gmail.com"
        )

    def allows(self, level: MailAccess) -> bool:
        return self.mail_access.rank >= level.rank

    def require_mail_access(self, level: MailAccess) -> None:
        """Raise `MailAccessDenied` unless the account's mail access is at least `level`."""
        if not self.allows(level):
            raise MailAccessDenied(self.email, self.mail_access)

    @property
    def smtp_configured(self) -> bool:
        """Whether the account has an outgoing mail server (always, for Google accounts)."""
        return self.provider == Provider.GOOGLE or bool(self.smtp_host)

    @property
    def smtp_server(self) -> tuple[str, int, str] | None:
        """(host, port, security) of the outgoing mail server, or None when there is none."""
        if self.provider == Provider.GOOGLE:
            return GMAIL_SMTP
        if not self.smtp_host:
            return None
        default_port = 465 if self.smtp_security != "starttls" else 587
        return self.smtp_host, self.smtp_port or default_port, self.smtp_security or "ssl"

    @property
    def smtp_login(self) -> str:
        if self.provider == Provider.GOOGLE:
            return self.email
        return self.smtp_username or self.login

    @property
    def can_send(self) -> bool:
        """Whether this account may send mail: the one place that decides it.

        The access level must be "full" and the account needs an outgoing (SMTP) server.
        """
        return self.mail_access == MailAccess.FULL and self.smtp_configured

    def require_send(self) -> None:
        """Raise `SendingDisabled` (with the reason) unless `can_send`."""
        if not self.allows(MailAccess.FULL):
            raise SendingDisabled(
                f"sending is disabled for account {self.email} (access level "
                f"{self.mail_access.value}); {ACCESS_HINT}"
            )
        if not self.smtp_configured:
            raise SendingDisabled(
                f"SMTP is not configured for account {self.email}; the owner can add the "
                "outgoing mail server in the admin UI"
            )

    @property
    def capabilities(self) -> list[str]:
        caps = ["mail"]
        if self.allows(MailAccess.ORGANIZE):
            caps.append("mail.organize")
        if self.can_send:
            caps.append("mail.send")
        if self.provider == Provider.GOOGLE or self.caldav_url:
            caps.append("calendar")
            caps.append("tasks")
        if self.provider == Provider.GOOGLE or self.carddav_url:
            caps.append("contacts")
        return caps

    @property
    def login(self) -> str:
        return self.imap_username or self.email


def _row_to_account(row) -> Account:
    return Account(
        id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        provider=Provider(row["provider"]),
        imap_host=row["imap_host"],
        imap_port=row["imap_port"],
        imap_security=row["imap_security"],
        imap_username=row["imap_username"],
        caldav_url=row["caldav_url"],
        carddav_url=row["carddav_url"],
        has_secret=row["secret_enc"] is not None,
        enabled=bool(row["enabled"]),
        status=AccountStatus(row["status"]),
        last_error=row["last_error"],
        last_ok_at=row["last_ok_at"],
        last_check_at=row["last_check_at"],
        mail_access=MailAccess(row["mail_access"]),
        smtp_host=row["smtp_host"],
        smtp_port=row["smtp_port"],
        smtp_security=row["smtp_security"],
        smtp_username=row["smtp_username"],
        smtp_status=SmtpStatus(row["smtp_status"]) if row["smtp_status"] else None,
        smtp_error=row["smtp_error"],
        smtp_checked_at=row["smtp_checked_at"],
    )


class AccountRepo:
    def __init__(self, db: Database, box: SecretBox):
        self._db = db
        self._box = box

    def list(self, include_disabled: bool = True) -> list[Account]:
        sql = "SELECT * FROM accounts"
        if not include_disabled:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY email"
        return [_row_to_account(r) for r in self._db.query(sql)]

    def get(self, email: str) -> Account | None:
        row = self._db.one("SELECT * FROM accounts WHERE email = ?", (email.strip().lower(),))
        return _row_to_account(row) if row else None

    def get_by_id(self, id: int) -> Account | None:
        row = self._db.one("SELECT * FROM accounts WHERE id = ?", (id,))
        return _row_to_account(row) if row else None

    def upsert(
        self,
        *,
        email: str,
        provider: Provider,
        display_name: str | None = None,
        imap_host: str | None = None,
        imap_port: int | None = None,
        imap_security: str | None = None,
        imap_username: str | None = None,
        caldav_url: str | None = None,
        carddav_url: str | None = None,
        secret: str | None = None,
        status: AccountStatus | None = None,
        mail_access: MailAccess | None = None,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_security: str | None = None,
        smtp_username: str | None = None,
    ) -> Account:
        email = email.strip().lower()
        now = int(time.time())

        # `provider` is required (never None) so it is always part of the dynamic SET list.
        # The rest only overwrite the stored value when explicitly given (non-None).
        columns: dict[str, object] = {"provider": provider.value}
        for col, val in {
            "display_name": display_name,
            "imap_host": imap_host,
            "imap_port": imap_port,
            "imap_security": imap_security,
            "imap_username": imap_username,
            "caldav_url": caldav_url,
            "carddav_url": carddav_url,
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_security": smtp_security,
            "smtp_username": smtp_username,
        }.items():
            if val is not None:
                columns[col] = val
        if secret is not None:
            columns["secret_enc"] = self._box.encrypt(secret, f"account:{email}")
        if status is not None:
            columns["status"] = status.value
        if mail_access is not None:
            columns["mail_access"] = MailAccess(mail_access).value

        insert_cols = ["email", "enabled", "created_at", "updated_at", *columns.keys()]
        insert_vals = [email, 1, now, now, *columns.values()]

        set_clauses = [f"{col} = excluded.{col}" for col in columns]
        set_clauses.append("updated_at = excluded.updated_at")
        set_sql = ", ".join(set_clauses)

        sql = (
            f"INSERT INTO accounts ({', '.join(insert_cols)}) "
            f"VALUES ({', '.join('?' for _ in insert_vals)}) "
            f"ON CONFLICT(email) DO UPDATE SET {set_sql}"
        )
        self._db.execute(sql, insert_vals)
        return self.get(email)

    def get_secret(self, email: str) -> str | None:
        row = self._db.one(
            "SELECT secret_enc FROM accounts WHERE email = ?", (email.strip().lower(),)
        )
        if row is None or row["secret_enc"] is None:
            return None
        return self._box.decrypt(row["secret_enc"], f"account:{email.strip().lower()}")

    def set_secret(self, email: str, secret: str) -> None:
        email = email.strip().lower()
        enc = self._box.encrypt(secret, f"account:{email}")
        self._db.execute(
            "UPDATE accounts SET secret_enc = ?, updated_at = ? WHERE email = ?",
            (enc, int(time.time()), email),
        )

    def set_status(self, email: str, status: AccountStatus, error: str | None = None) -> None:
        email = email.strip().lower()
        now = int(time.time())
        if status == AccountStatus.CONNECTED:
            self._db.execute(
                "UPDATE accounts SET status = ?, last_check_at = ?, last_ok_at = ?, "
                "last_error = NULL, updated_at = ? WHERE email = ?",
                (status.value, now, now, now, email),
            )
        else:
            truncated = error[:500] if error else None
            self._db.execute(
                "UPDATE accounts SET status = ?, last_check_at = ?, last_error = ?, "
                "updated_at = ? WHERE email = ?",
                (status.value, now, truncated, now, email),
            )

    def mark_connected(self, email: str, expected: AccountStatus) -> bool:
        """Set CONNECTED only if the status is still `expected` (compare-and-set).

        A login that succeeded must not erase a breaker trip (`needs_reconnect`) that
        another call recorded while the login was in flight. False when nothing changed.
        """
        now = int(time.time())
        return bool(
            self._db.execute(
                "UPDATE accounts SET status = ?, last_check_at = ?, last_ok_at = ?, "
                "last_error = NULL, updated_at = ? WHERE email = ? AND status = ?",
                (
                    AccountStatus.CONNECTED.value,
                    now,
                    now,
                    now,
                    email.strip().lower(),
                    expected.value,
                ),
            )
        )

    def set_mail_access(self, email: str, level: MailAccess | str) -> bool:
        """Set the account's mail access level. False when there is no such account.

        Raises ValueError for an unknown level."""
        level = MailAccess(level)
        return bool(
            self._db.execute(
                "UPDATE accounts SET mail_access = ?, updated_at = ? WHERE email = ?",
                (level.value, int(time.time()), email.strip().lower()),
            )
        )

    def set_smtp(
        self,
        email: str,
        *,
        host: str | None,
        port: int | None = None,
        security: str | None = None,
        username: str | None = None,
    ) -> None:
        """Replace the account's outgoing mail settings; no host removes them (no sending).

        The last SMTP check result is cleared: it was about the old settings."""
        if not host:
            host = port = security = username = None
        elif security not in ("ssl", "starttls"):
            raise ValueError(f"invalid SMTP security: {security!r}")
        self._db.execute(
            "UPDATE accounts SET smtp_host = ?, smtp_port = ?, smtp_security = ?, "
            "smtp_username = ?, smtp_status = NULL, smtp_error = NULL, smtp_checked_at = NULL, "
            "updated_at = ? WHERE email = ?",
            (host, port, security, username or None, int(time.time()), email.strip().lower()),
        )

    def set_smtp_status(self, email: str, status: SmtpStatus, error: str | None = None) -> None:
        """Record the outcome of an SMTP login (the error text must be secret-free)."""
        now = int(time.time())
        self._db.execute(
            "UPDATE accounts SET smtp_status = ?, smtp_error = ?, smtp_checked_at = ?, "
            "updated_at = ? WHERE email = ?",
            (
                SmtpStatus(status).value,
                None if status == SmtpStatus.OK else (error or "")[:500] or None,
                now,
                now,
                email.strip().lower(),
            ),
        )

    def set_display_name(self, email: str, display_name: str | None) -> None:
        self._db.execute(
            "UPDATE accounts SET display_name = ?, updated_at = ? WHERE email = ?",
            (display_name or None, int(time.time()), email.strip().lower()),
        )

    def set_enabled(self, email: str, enabled: bool) -> None:
        self._db.execute(
            "UPDATE accounts SET enabled = ?, updated_at = ? WHERE email = ?",
            (int(enabled), int(time.time()), email.strip().lower()),
        )

    def delete(self, email: str) -> None:
        self._db.execute("DELETE FROM accounts WHERE email = ?", (email.strip().lower(),))
