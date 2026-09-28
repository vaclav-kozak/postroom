"""IMAP connector and the per-account connection pool with a fail2ban-safe
circuit breaker.

The pool never retries an account that is `needs_reconnect` /
`needs_google_connect` unless a caller explicitly passes `manual=True` (an
owner-triggered "try again" action). This is what keeps a wrong password
from hammering the upstream server and tripping its own fail2ban.
"""

import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, LoginError
from imapclient.imapclient import SocketTimeout, _is8bit

from postroom.accounts import Account, AccountRepo, AccountStatus
from postroom.login_locks import LoginLocks

FETCH_BODY = "BODY.PEEK[]"
FETCH_HEADER = "BODY.PEEK[HEADER]"
RESP_BODY = b"BODY[]"
RESP_HEADER = b"BODY[HEADER]"
SUMMARY_FIELDS = ["ENVELOPE", "INTERNALDATE", "FLAGS", "RFC822.SIZE", "BODYSTRUCTURE"]

_BLOCKED_STATUSES = (AccountStatus.NEEDS_RECONNECT, AccountStatus.NEEDS_GOOGLE_CONNECT)

_UNSAFE_ARG = re.compile(rb"[\r\n\x00]")

# How long a connect waits for the account's login lock (held by an in-flight
# CalDAV/CardDAV call) before giving up.
LOGIN_LOCK_TIMEOUT = 90


class UnsafeImapArgument(ValueError):
    """A command argument contains CR, LF or NUL and would break out of its command line."""

    def __init__(self) -> None:
        super().__init__(
            "line breaks and NUL characters are not allowed in search terms or folder names"
        )


class SafeIMAPClient(IMAPClient):
    """IMAPClient that refuses CR, LF or NUL in any inline command argument.

    imapclient quotes strings but does not escape line breaks, so a search term or folder name
    containing CRLF would end the command and let the rest run as new commands with the
    owner's credentials (e.g. a hostile Message-ID header fed into a thread search). Arguments
    that imapclient sends as literals (8-bit data) are length-prefixed and therefore safe.
    """

    def _raw_command(self, command, args, uid=True):
        items = args if isinstance(args, (list, tuple)) else [args]
        for item in items:
            if isinstance(item, bytes) and not _is8bit(item) and _UNSAFE_ARG.search(item):
                raise UnsafeImapArgument()
        return super()._raw_command(command, args, uid)

    def _normalise_folder(self, folder_name):
        raw = folder_name.encode("utf-8") if isinstance(folder_name, str) else folder_name
        if _UNSAFE_ARG.search(raw):
            raise UnsafeImapArgument()
        return super()._normalise_folder(folder_name)


def is_safe_imap_value(value: str) -> bool:
    """True when `value` has no CR, LF or NUL (safe to send inline to the server)."""
    return not _UNSAFE_ARG.search(value.encode("utf-8"))


# Errors raised during connect() that mean "the network/upstream failed",
# as opposed to an auth failure. Handled the same way by the pool.
_CONNECT_ERRORS = (OSError, ssl.SSLError, socket.timeout, IMAPClientError)

# Errors raised *inside* a session's `with` block that mean the cached
# connection itself is broken and must be dropped.
_CONNECTION_LEVEL_ERRORS = (OSError, IMAPClientAbortError, ssl.SSLError)


class ImapError(Exception):
    """Base for all IMAP errors raised by this module. Message is safe to log/store."""


class AuthFailed(ImapError):
    """Login/reauth failed. The pool trips the account's circuit breaker on this."""


class AccountUnavailable(ImapError):
    """The account cannot be used right now (disabled, or breaker tripped)."""


class TokenUnavailable(ImapError):
    """The Google access token could not be obtained (network, Google 5xx, bad config).

    Not an auth failure: the pool sets the account to ERROR, not needs_reconnect."""


# email -> Google access token; raises AuthFailed (reconnect needed) or GoogleOAuthError.
TokenSource = Callable[[str], str]


def _safe(e: Exception) -> str:
    """Render an exception as a message that is safe to store/log (no secrets)."""
    return f"{type(e).__name__}: {e}"[:300]


def _close_quietly(client) -> None:
    """Best-effort close: try logout(), fall back to shutdown(), swallow errors."""
    try:
        client.logout()
    except Exception:  # noqa: BLE001 -- closing a possibly-broken socket can fail many ways
        try:
            client.shutdown()
        except Exception:  # noqa: BLE001, S110 -- best-effort cleanup, nothing more to do
            pass


def _shutdown_quietly(client) -> None:
    """Force-close a socket that never finished authenticating.

    Used when STARTTLS itself fails: the connection was never logged in, so
    `logout()` (an authenticated-state command) makes no sense here -- only
    `shutdown()` applies. Swallows its own errors so the caller's real
    exception (the STARTTLS failure) is what propagates.
    """
    try:
        client.shutdown()
    except Exception:  # noqa: BLE001, S110 -- best-effort cleanup; caller re-raises its own error
        pass


class ImapConnector:
    def __init__(
        self,
        google_token: TokenSource | None = None,
        ssl_context: ssl.SSLContext | None = None,
        connect_timeout: float = 15,
        read_timeout: float = 60,
    ):
        self.google_token = google_token
        self.ssl_context = ssl_context
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout

    def connect(self, account: Account, secret: str | None) -> IMAPClient:
        # Credentials first: a token failure must never leave an opened socket behind.
        token = None
        if account.is_gmail:
            if self.google_token is None:
                raise AuthFailed("no google token source configured")
            try:
                token = self.google_token(account.email)
            except AuthFailed:
                raise
            except Exception as e:  # GoogleOAuthError (message is secret-free) or unexpected
                raise TokenUnavailable(_safe(e)) from e
        elif secret is None:
            raise AuthFailed("no password stored")

        ctx = self.ssl_context or ssl.create_default_context()
        timeout = SocketTimeout(self.connect_timeout, self.read_timeout)

        if account.imap_security == "starttls":
            client = SafeIMAPClient(
                account.imap_host, account.imap_port, ssl=False, timeout=timeout
            )
            try:
                client.starttls(ctx)
            except Exception:
                _shutdown_quietly(client)
                raise
        else:
            client = SafeIMAPClient(
                account.imap_host, account.imap_port, ssl=True, ssl_context=ctx, timeout=timeout
            )

        try:
            if token is not None:
                client.oauth2_login(account.login, token)
            else:
                client.login(account.login, secret)
        except LoginError as e:
            _close_quietly(client)
            raise AuthFailed(f"login failed: {e}") from e
        except BaseException:
            _close_quietly(client)
            raise

        return client


class _Entry:
    __slots__ = ("client", "last_used", "lock")

    def __init__(self):
        self.lock = threading.Lock()
        self.client = None
        self.last_used = 0.0


class ImapPool:
    def __init__(
        self,
        repo: AccountRepo,
        connector: ImapConnector,
        idle_seconds: float = 120,
        clock: Callable[[], float] = time.monotonic,
        locks: LoginLocks | None = None,
    ):
        self.repo = repo
        self.connector = connector
        self.idle_seconds = idle_seconds
        self.clock = clock
        # Shared with PimService: IMAP and CalDAV/CardDAV logins to one account are
        # serialised, so a wrong password costs one failed login in total.
        self.locks = locks or LoginLocks()
        self._entries: dict[str, _Entry] = {}
        self._registry_lock = threading.Lock()

    def _entry_for(self, email: str) -> _Entry:
        with self._registry_lock:
            entry = self._entries.get(email)
            if entry is None:
                entry = self._entries[email] = _Entry()
            return entry

    def _check_available(self, account: Account | None, email: str, manual: bool) -> Account:
        """Raise if `email` cannot be connected to right now; otherwise return its account.

        This is rules 1-2 from the pool semantics. It is called twice per
        session: once before `entry.lock` is acquired (a cheap check so an
        obviously-blocked account doesn't even queue on the lock), and once
        again right after the lock is acquired and only when a real
        `connect()` is about to happen. The second check is the authoritative
        one -- without it, N callers that all pass the first (pre-lock) check
        would each queue on the lock and each call `connector.connect()` in
        turn even after the first one trips the breaker, which is exactly the
        burst of real auth failures fail2ban would catch.
        """
        if account is None:
            raise ImapError(f"unknown account: {email}")
        if not account.enabled:
            raise AccountUnavailable("account is disabled")
        if account.status in _BLOCKED_STATUSES and not manual:
            raise AccountUnavailable(f"account needs reconnect: {account.last_error}")
        return account

    def _acquire(self, entry: _Entry, email: str, manual: bool):
        if entry.client is not None:
            idle = self.clock() - entry.last_used
            if idle < self.idle_seconds:
                try:
                    entry.client.noop()
                    return entry.client
                except Exception:  # noqa: BLE001, S110 -- any failure means "reconnect", not a crash
                    pass
            _close_quietly(entry.client)
            entry.client = None

        # Only reached when we're about to make a real connect() call (no live
        # cached client to reuse). The account's login lock is shared with
        # CalDAV/CardDAV calls; re-read the account under it: another caller
        # (IMAP or DAV) may have tripped the breaker while we were waiting, and
        # the snapshot from before we queued is stale.
        login_lock = self.locks.account(email)
        if not login_lock.acquire(timeout=LOGIN_LOCK_TIMEOUT):
            raise ImapError("account busy; try again later")
        try:
            account = self._check_available(self.repo.get(email), email, manual)
            client = self._connect(account)
        finally:
            login_lock.release()

        entry.client = client
        entry.last_used = self.clock()
        return client

    def _connect(self, account: Account):
        secret = self.repo.get_secret(account.email)
        try:
            client = self.connector.connect(account, secret)
        except AuthFailed as e:
            self.repo.set_status(account.email, AccountStatus.NEEDS_RECONNECT, _safe(e))
            raise
        except TokenUnavailable as e:
            self.repo.set_status(account.email, AccountStatus.ERROR, str(e))
            raise
        except _CONNECT_ERRORS as e:
            msg = _safe(e)
            self.repo.set_status(account.email, AccountStatus.ERROR, msg)
            raise ImapError(msg) from e

        if account.status != AccountStatus.CONNECTED:
            # Compare-and-set: never erase a breaker trip recorded meanwhile.
            self.repo.mark_connected(account.email, expected=account.status)
        return client

    @contextmanager
    def session(self, email: str, *, manual: bool = False) -> Iterator[IMAPClient]:
        # Cheap pre-lock check: keeps an already-known-blocked account from
        # queueing on entry.lock at all. Not authoritative -- see _acquire().
        self._check_available(self.repo.get(email), email, manual)

        entry = self._entry_for(email)
        with entry.lock:
            client = self._acquire(entry, email, manual)
            try:
                yield client
            except _CONNECTION_LEVEL_ERRORS as e:
                _close_quietly(entry.client)
                entry.client = None
                raise ImapError(_safe(e)) from e
            else:
                entry.last_used = self.clock()

    def drop(self, email: str) -> None:
        entry = self._entries.get(email)
        if entry is None:
            return
        with entry.lock:
            if entry.client is not None:
                _close_quietly(entry.client)
                entry.client = None

    def close_idle(self) -> None:
        now = self.clock()
        for entry in list(self._entries.values()):
            with entry.lock:
                if entry.client is not None and now - entry.last_used >= self.idle_seconds:
                    _close_quietly(entry.client)
                    entry.client = None

    def close_all(self) -> None:
        for entry in list(self._entries.values()):
            with entry.lock:
                if entry.client is not None:
                    _close_quietly(entry.client)
                    entry.client = None
