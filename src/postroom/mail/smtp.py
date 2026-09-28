"""Outgoing mail over SMTP: the connector (connect, TLS, login) and the per-account sender
with the same fail2ban care as the IMAP pool.

- Password accounts make exactly one AUTH attempt per login: PLAIN when the server offers
  it, else LOGIN (both UTF-8). `smtplib.login()` is not used: it tries every advertised
  mechanism in turn, so one wrong password would cost two or three failed logins.
- Google (OAuth) accounts use XOAUTH2 with the same Google access token as IMAP. When
  Gmail refuses it, the cached token is dropped and the login is retried once with a fresh
  one; these failures never pause sending (no fail2ban there, and no password to fix).
  A Gmail mailbox added as an IMAP account logs in like any password account (PLAIN, with
  a Google app password), and a refused app password pauses sending like any other.
- Every SMTP login holds the account's shared login lock (`login_locks.py`) and re-reads the
  account under it, so an SMTP login never races an IMAP or DAV login to the same server.
- A password login refused with a permanent (5xx) reply is recorded as
  `smtp_status = auth_failed`, and no further send logs in again until the owner tests the
  account (`manual=True`): a wrong SMTP password costs one failed login, not one per send.
  A temporary (4xx) refusal is an ordinary error and does not pause sending. An account whose IMAP login failed (`needs_reconnect`)
  does not send either: it would fail the same way with the same password.
- A send is never retried here. Once DATA has begun the server may have accepted the
  message, so a lost connection from then on is reported as "may have been sent".
- DATA streams the message from the caller's bytes (dot-stuffed on the fly) instead of
  `smtplib.data()`, which makes three whole-message copies first.

Error messages are safe to show to the owner and the model: they carry the server's
SMTP reply code and text, never the password or the token.
"""

import base64
import re
import smtplib
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from postroom.accounts import Account, AccountRepo, AccountStatus, SmtpStatus
from postroom.login_locks import LoginLocks
from postroom.mail.imap import LOGIN_LOCK_TIMEOUT, AuthFailed, TokenSource

CONNECT_TIMEOUT = 15
# Every later socket operation (a command reply, or one chunk of a large DATA upload).
COMMAND_TIMEOUT = 60

_BLOCKED_STATUSES = (AccountStatus.NEEDS_RECONNECT, AccountStatus.NEEDS_GOOGLE_CONNECT)


class SmtpError(Exception):
    """Base for SMTP failures. Nothing was sent unless the subclass says otherwise.
    The message is secret-free."""


class SmtpAuthFailed(SmtpError):
    """The SMTP server rejected the password for good (a 5xx reply): sending pauses."""


class SmtpUnavailable(SmtpError):
    """The account may not log in to SMTP right now (disabled, or a login failed before)."""


class SmtpRejected(SmtpError):
    """The server refused the sender, every recipient or the message: nothing was sent."""


class SmtpMaybeSent(SmtpError):
    """The connection broke after the message was handed over: it may have been sent."""


@dataclass
class SendOutcome:
    # Recipients the server refused ("addr" -> "550 5.1.1 ..."); every other one was accepted.
    refused: dict[str, str] = field(default_factory=dict)


def _reply(code: int | None, text: bytes | str | None) -> str:
    """An SMTP reply as "550 5.7.1 relaying denied" (one line, bounded)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    words = " ".join((text or "").split())
    return f"{code} {words}".strip()[:300]


def _safe(e: BaseException) -> str:
    """An exception as owner-safe text. smtplib's own errors carry the server's reply."""
    if isinstance(e, smtplib.SMTPResponseException):
        return _reply(e.smtp_code, e.smtp_error)
    return f"{type(e).__name__}: {e}"[:300]


def _xoauth2(user: str, token: str) -> Callable[..., str]:
    """The XOAUTH2 initial response; an empty answer to the server's error challenge makes
    it finish with the final 535 reply (RFC 7628 style)."""
    initial = f"user={user}\x01auth=Bearer {token}\x01\x01"

    def respond(challenge: bytes | None = None) -> str:
        return initial if challenge is None else ""

    return respond


def _quit_quietly(smtp) -> None:
    try:
        smtp.quit()
    except Exception:  # noqa: BLE001 -- the connection may already be gone
        try:
            smtp.close()
        except Exception:  # noqa: BLE001, S110 -- best-effort cleanup
            pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _auth_mechanisms(smtp) -> list[str]:
    features = getattr(smtp, "esmtp_features", {}) or {}
    return str(features.get("auth", "")).upper().split()


# The message to send: one bytes object, or its pieces in order (e.g. a rebuilt header and a
# view of the body), so the caller never joins them into another whole-message copy.
Wire = bytes | Sequence[bytes | memoryview]
_NON_ASCII = re.compile(rb"[^\x00-\x7f]")
_LF_DOT = re.compile(rb"\n\.")


def _chunks(raw: Wire) -> list[bytes | memoryview]:
    return [raw] if isinstance(raw, bytes | bytearray | memoryview) else list(raw)


def _send_data(smtp, raw: Wire) -> tuple[int, bytes]:
    """DATA with `raw` (CRLF lines) streamed from the caller's bytes: lines that start with
    "." get a second one (RFC 5321 4.5.2), then the terminator. Same wire bytes and
    errors as `smtplib.SMTP.data()`, without its whole-message copies."""
    code, resp = smtp.docmd("DATA")
    if code != 354:
        raise smtplib.SMTPDataError(code, resp)
    line_start, tail = True, b""
    for chunk in _chunks(raw):
        if not len(chunk):
            continue
        view = memoryview(chunk)
        if line_start and view[:1] == b".":
            smtp.send(b".")
        start = 0
        for m in _LF_DOT.finditer(view):
            smtp.send(view[start : m.start() + 1])
            smtp.send(b".")
            start = m.start() + 1
        smtp.send(view[start:])
        line_start = view[-1:] == b"\n"
        tail = (tail + bytes(view[-2:]))[-2:]
    smtp.send(b".\r\n" if tail == b"\r\n" else b"\r\n.\r\n")
    return smtp.getreply()


def _has_extn(smtp, name: str) -> bool:
    try:
        return bool(smtp.has_extn(name))
    except Exception:  # noqa: BLE001 -- a fake or odd client: treat as not offered
        return False


class SmtpConnector:
    """Opens an authenticated SMTP connection for an account (no breaker, no lock: see
    `SmtpSender`). The admin UI also uses it for the test login before saving."""

    def __init__(
        self,
        google_token: TokenSource | None = None,
        ssl_context: ssl.SSLContext | None = None,
        google_invalidate: Callable[[str], None] | None = None,
        connect_timeout: float = CONNECT_TIMEOUT,
        command_timeout: float = COMMAND_TIMEOUT,
        local_hostname: str | None = None,
        smtp_class=smtplib.SMTP,
        smtp_ssl_class=smtplib.SMTP_SSL,
    ):
        self.google_token = google_token
        self.google_invalidate = google_invalidate
        self.ssl_context = ssl_context
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.local_hostname = local_hostname
        self.smtp_class = smtp_class
        self.smtp_ssl_class = smtp_ssl_class

    def _credentials(self, account: Account, secret: str | None) -> str | None:
        """The Google access token for Google (OAuth) accounts; None for password accounts,
        which include Gmail mailboxes added as IMAP accounts with an app password."""
        if not account.uses_google_oauth:
            if secret is None:
                raise SmtpAuthFailed("SMTP: no password stored")
            return None
        if self.google_token is None:
            raise SmtpError("SMTP: no Google token source configured")
        try:
            return self.google_token(account.email)
        except AuthFailed as e:
            raise SmtpError(f"SMTP: {e}") from e
        except Exception as e:  # GoogleOAuthError (secret-free message) or unexpected
            raise SmtpError(f"SMTP: Google access token unavailable ({_safe(e)})") from e

    def connect(self, account: Account, secret: str | None):
        """A logged-in `smtplib.SMTP` for the account. Raises `SmtpError` subclasses."""
        server = account.smtp_server
        if server is None:
            raise SmtpError("SMTP is not configured for this account")
        token = self._credentials(account, secret)
        if token is None:
            return self._open(account, server, secret, None)
        try:
            return self._open(account, server, None, token)
        except SmtpAuthFailed as e:
            if self.google_invalidate is None:
                raise SmtpError(str(e)) from e  # never the fail2ban pause for Google
        # The cached access token may be stale: drop it and try once with a fresh one.
        self.google_invalidate(account.email)
        token = self._credentials(account, secret)
        try:
            return self._open(account, server, None, token)
        except SmtpAuthFailed as e:
            raise SmtpError(
                f"{e}; Google refused a fresh access token too: reconnect the Google account "
                "in the admin UI if this persists"
            ) from e

    def _open(self, account: Account, server: tuple[str, int, str], secret, token):
        host, port, security = server
        ctx = self.ssl_context or ssl.create_default_context()
        try:
            if security == "ssl":
                smtp = self.smtp_ssl_class(
                    host,
                    port,
                    local_hostname=self.local_hostname,
                    timeout=self.connect_timeout,
                    context=ctx,
                )
            else:
                smtp = self.smtp_class(
                    host, port, local_hostname=self.local_hostname, timeout=self.connect_timeout
                )
        except (OSError, smtplib.SMTPException) as e:
            raise SmtpError(f"SMTP: could not connect to {host}:{port}: {_safe(e)}") from e

        try:
            sock = getattr(smtp, "sock", None)
            if sock is not None:
                sock.settimeout(self.command_timeout)
            smtp.ehlo()
            if security == "starttls":
                if not _has_extn(smtp, "starttls"):
                    raise SmtpError(
                        "SMTP: the server does not offer STARTTLS; choose SSL/TLS (usually "
                        "port 465) instead"
                    )
                smtp.starttls(context=ctx)
                smtp.ehlo()
            self._login(smtp, account.smtp_login, secret, token)
        except smtplib.SMTPAuthenticationError as e:
            _quit_quietly(smtp)
            if 400 <= e.smtp_code < 500:
                raise SmtpError(
                    f"SMTP: temporary authentication failure ({_safe(e)}); try again later"
                ) from e
            raise SmtpAuthFailed(f"SMTP: authentication failed ({_safe(e)})") from e
        except smtplib.SMTPNotSupportedError as e:
            _quit_quietly(smtp)
            raise SmtpError(f"SMTP: the server does not support login here ({e})") from e
        except SmtpError:
            _quit_quietly(smtp)
            raise
        except (OSError, smtplib.SMTPException) as e:
            _quit_quietly(smtp)
            raise SmtpError(f"SMTP: {_safe(e)}") from e
        return smtp

    @staticmethod
    def _login(smtp, user: str, secret: str | None, token: str | None) -> None:
        """Exactly one AUTH exchange (see the module docstring)."""
        if token is not None:
            smtp.auth("XOAUTH2", _xoauth2(user, token), initial_response_ok=True)
            return
        if not _has_extn(smtp, "auth"):
            raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server")
        mechanisms = _auth_mechanisms(smtp)
        name, password = user.encode(), (secret or "").encode()
        if "PLAIN" in mechanisms:  # RFC 4616, UTF-8, with the initial response
            code, resp = smtp.docmd("AUTH", "PLAIN " + _b64(b"\0" + name + b"\0" + password))
        elif "LOGIN" in mechanisms:
            code, resp = smtp.docmd("AUTH", "LOGIN")
            if code == 334:
                code, resp = smtp.docmd(_b64(name))
            if code == 334:
                code, resp = smtp.docmd(_b64(password))
        else:
            offered = " ".join(mechanisms) or "none"
            raise SmtpError(
                f"SMTP: the server offers no password login Postroom supports (AUTH {offered}; "
                "PLAIN or LOGIN is needed)"
            )
        if code != 235:
            raise smtplib.SMTPAuthenticationError(code, resp)

    def check(self, account: Account, secret: str | None) -> None:
        """Connect, EHLO, (STARTTLS), AUTH, QUIT: nothing is sent."""
        _quit_quietly(self.connect(account, secret))

    @staticmethod
    def transmit(smtp, sender: str, recipients: list[str], raw: Wire) -> SendOutcome:
        """MAIL FROM, RCPT TO each recipient, DATA. `raw` goes out exactly as given (CRLF)."""
        options = []
        chunks = _chunks(raw)
        size = sum(len(c) for c in chunks)
        if any(_NON_ASCII.search(c) for c in chunks) and _has_extn(smtp, "8bitmime"):
            options.append("BODY=8BITMIME")
        if not all(a.isascii() for a in (sender, *recipients)):
            if not _has_extn(smtp, "smtputf8"):
                raise SmtpRejected("the SMTP server does not accept non-ASCII email addresses")
            options.append("SMTPUTF8")
        limit = smtp.esmtp_features.get("size", "") if hasattr(smtp, "esmtp_features") else ""
        if limit.isdigit() and int(limit) and size > int(limit):
            raise SmtpRejected(
                f"the message ({size} bytes) is larger than the SMTP server accepts ({limit} bytes)"
            )
        try:
            code, resp = smtp.mail(sender, options)
            if code != 250:
                raise SmtpRejected(
                    f"the SMTP server refused the sender {sender}: {_reply(code, resp)}"
                )
            refused: dict[str, str] = {}
            for rcpt in recipients:
                code, resp = smtp.rcpt(rcpt)
                if code not in (250, 251):
                    refused[rcpt] = _reply(code, resp)
            if len(refused) == len(recipients):
                listed = "; ".join(f"{a}: {r}" for a, r in refused.items())
                raise SmtpRejected(f"the SMTP server refused every recipient ({listed})")
        except SmtpRejected:
            try:
                smtp.rset()
            except Exception:  # noqa: BLE001, S110 -- the connection is closed next anyway
                pass
            raise
        except (OSError, smtplib.SMTPException) as e:
            raise SmtpError(f"SMTP: the connection failed before sending: {_safe(e)}") from e

        # From here on the server may accept the message even if we never hear back.
        try:
            code, resp = _send_data(smtp, chunks)
        except smtplib.SMTPDataError as e:  # DATA itself refused (no 354): nothing sent
            raise SmtpRejected(f"the SMTP server rejected the message: {_safe(e)}") from e
        except (OSError, smtplib.SMTPException) as e:
            raise SmtpMaybeSent(
                "the connection to the SMTP server broke while sending; the email may or may "
                f"not have been sent ({_safe(e)})"
            ) from e
        if code != 250:
            raise SmtpRejected(f"the SMTP server rejected the message: {_reply(code, resp)}")
        return SendOutcome(refused=refused)


class SmtpSender:
    """Sends mail for stored accounts: login lock, SMTP breaker and status bookkeeping."""

    def __init__(
        self,
        repo: AccountRepo,
        connector: SmtpConnector,
        locks: LoginLocks | None = None,
        lock_timeout: float = LOGIN_LOCK_TIMEOUT,
    ):
        self.repo = repo
        self.connector = connector
        self.locks = locks or LoginLocks()
        self.lock_timeout = lock_timeout

    def _available(self, email: str, manual: bool) -> Account:
        account = self.repo.get(email)
        if account is None:
            raise SmtpUnavailable(f"unknown account: {email}")
        if not account.enabled:
            raise SmtpUnavailable("account is disabled")
        if account.status in _BLOCKED_STATUSES:
            # Even a manual test: the IMAP login with the same credentials failed; fix it first.
            raise SmtpUnavailable(f"account needs reconnect: {account.last_error}")
        if account.smtp_status == SmtpStatus.AUTH_FAILED and not manual:
            raise SmtpUnavailable(
                f"sending is paused because the SMTP login failed ({account.smtp_error}); "
                "the owner must fix the account in the admin UI and press Test now"
            )
        return account

    def _login(self, email: str, manual: bool):
        lock = self.locks.account(email)
        if not lock.acquire(timeout=self.lock_timeout):
            raise SmtpError("account busy; try again later")
        try:
            account = self._available(email, manual)
            secret = None if account.uses_google_oauth else self.repo.get_secret(email)
            try:
                smtp = self.connector.connect(account, secret)
            except SmtpAuthFailed as e:
                self.repo.set_smtp_status(email, SmtpStatus.AUTH_FAILED, str(e))
                raise
            except SmtpError as e:
                self.repo.set_smtp_status(email, SmtpStatus.ERROR, str(e))
                raise
        finally:
            lock.release()
        if account.smtp_status != SmtpStatus.OK:
            self.repo.set_smtp_status(email, SmtpStatus.OK)
        return smtp

    def check(self, email: str) -> str | None:
        """The owner's "Test now": log in and out, record the result. None when it worked,
        else the (secret-free) error."""
        try:
            _quit_quietly(self._login(email, manual=True))
        except SmtpError as e:
            return str(e)
        return None

    def send(self, email: str, sender: str, recipients: list[str], raw: Wire) -> SendOutcome:
        """Send `raw` once. Raises `SmtpError` subclasses; never retries."""
        smtp = self._login(email, manual=False)
        try:
            return self.connector.transmit(smtp, sender, recipients, raw)
        finally:
            _quit_quietly(smtp)
