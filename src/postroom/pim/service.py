"""PimService: routes calendar/task/contact calls to each account's backend.

Backends: Google accounts use `GoogleApi`; IMAP accounts with a CalDAV/CardDAV server
(mailcow/SOGo, Nextcloud, Radicale, ...) use `CalDavBackend` for calendars and tasks and
`CardDavBackend` for contacts.

fail2ban safety: an account that is disabled or in `needs_reconnect` /
`needs_google_connect` is never contacted. A CalDAV/CardDAV login failure trips the
account's circuit breaker (`needs_reconnect`), which also stops mail access, because
servers such as mailcow run one fail2ban that counts DAV (SOGo) and IMAP logins
together. CalDAV/CardDAV calls hold the account's login lock (shared with the IMAP
pool, see `postroom.login_locks`) and re-read the status after acquiring it, so calls
queued behind a failed login fail fast instead of logging in again: one wrong password
costs one failed login.

Every backend call is synchronous and runs in `asyncio.to_thread` under a timeout;
multi-account calls run concurrently under a semaphore and report per-account failures
as `AccountError`s instead of failing the whole call.
"""

import asyncio
import logging
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from postroom.accounts import Account, AccountRepo, AccountStatus, Provider
from postroom.dav.caldav_backend import CalDavBackend
from postroom.dav.carddav import CardDavBackend
from postroom.dav.urls import require_dav_url
from postroom.google.api import GoogleApi
from postroom.google.oauth import GoogleOAuth
from postroom.login_locks import LoginLocks
from postroom.mail.models import AccountError
from postroom.pim.models import (
    CalendarInfo,
    ContactInfo,
    EventInfo,
    EventInput,
    PimError,
    TaskInfo,
    TaskInput,
    TaskListInfo,
    parse_when,
)

log = logging.getLogger(__name__)

CAPABILITIES = ("calendar", "tasks", "contacts")
DAV_LOGIN_FAILED = "CalDAV/CardDAV login failed"
TIMEOUT_MESSAGE = "the server did not respond in time; try again later"
WRITE_TIMEOUT_MESSAGE = (
    "the server did not respond in time; the change may or may not have been applied; "
    "list/get before retrying"
)
# CalDAV/CardDAV calls running at once per DAV host, across all accounts. The failure
# bound does not depend on it (one per account, see `_queued`); it bounds the burst of
# concurrent SOGo requests and the memory their responses take in a 256 MiB container.
DAV_CALLS_PER_HOST = 2

_BLOCKED_STATUSES = (AccountStatus.NEEDS_RECONNECT, AccountStatus.NEEDS_GOOGLE_CONNECT)

BackendFactory = Callable[[Account, str], object]


def _unavailable(account: Account) -> str | None:
    """Why `account` must not be contacted, or None when it may be."""
    if not account.enabled:
        return "account unavailable: disabled"
    if account.status in _BLOCKED_STATUSES:
        return f"account unavailable: {account.status.value}"
    return None


def _start_key(value: str | None, tz: ZoneInfo) -> datetime:
    """Sort key for an ISO `start` string (all-day dates sort at local midnight in `tz`)."""
    try:
        when = parse_when(value or "", tz)
    except ValueError:
        return datetime.max.replace(tzinfo=tz)
    if isinstance(when, datetime):
        return when
    return datetime.combine(when, time.min, tz)


def _consume(task: asyncio.Task) -> None:
    """Retrieve an abandoned call's outcome so asyncio does not log it as unhandled."""
    if not task.cancelled():
        task.exception()


def _close(backend: object) -> None:
    close = getattr(backend, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 -- closing is best-effort
            log.debug("closing %s failed", type(backend).__name__)


class PimService:
    def __init__(
        self,
        repo: AccountRepo,
        google: GoogleOAuth | None,
        backend_factory: BackendFactory | None = None,
        max_concurrency: int = 4,
        timeout: float = 60,
        locks: LoginLocks | None = None,
        tz: ZoneInfo | None = None,
    ):
        self.repo = repo
        # The server's configured time zone (POSTROOM_TIMEZONE), handed to every backend.
        self.tz = tz or ZoneInfo("UTC")
        self.google = google
        self.backend_factory = backend_factory or self._default_backend
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.locks = locks or LoginLocks()
        self._account_queues: dict[str, asyncio.Lock] = {}
        self._host_slots: dict[str, asyncio.Semaphore] = {}

    # -- backends ---------------------------------------------------------------

    def _trip_breaker(self, email: str) -> Callable[[], None]:
        def on_auth_failure() -> None:
            log.warning("CalDAV/CardDAV login failed for %s; marking needs_reconnect", email)
            self.repo.set_status(email, AccountStatus.NEEDS_RECONNECT, DAV_LOGIN_FAILED)

        return on_auth_failure

    def _default_backend(self, account: Account, capability: str) -> object:
        email = account.email
        if account.provider == Provider.GOOGLE:
            if self.google is None:
                raise PimError("Google is not configured on this server")
            return GoogleApi(email, self.google, tz=self.tz)
        url = account.carddav_url if capability == "contacts" else account.caldav_url
        if not url:
            raise PimError(f"{email} has no {capability}")
        require_dav_url(url)  # before the password is even decrypted
        password = self.repo.get_secret(email)
        if not password:
            raise PimError(f"{email} has no stored password")
        cls = CardDavBackend if capability == "contacts" else CalDavBackend
        on_auth_failure = self._trip_breaker(email)
        if cls is CardDavBackend:
            return cls(email, url, account.login, password, on_auth_failure=on_auth_failure)
        return cls(email, url, account.login, password, on_auth_failure=on_auth_failure, tz=self.tz)

    def backend(self, account: Account, capability: str) -> object:
        return self.backend_factory(account, capability)

    # -- account selection ------------------------------------------------------

    def _accounts_for(
        self, capability: str, email: str | None
    ) -> tuple[list[Account], list[AccountError]]:
        if capability not in CAPABILITIES:
            raise ValueError(f"unknown capability: {capability}")
        if email is not None:
            account = self.repo.get(email)
            if account is None:
                raise PimError(f"unknown account: {email}")
            if capability not in account.capabilities:
                raise PimError(f"{account.email} has no {capability}")
            reason = _unavailable(account)
            if reason:
                raise PimError(reason)
            return [account], []
        accounts: list[Account] = []
        errors: list[AccountError] = []
        for account in self.repo.list(include_disabled=False):
            if capability not in account.capabilities:
                continue
            reason = _unavailable(account)
            if reason:
                errors.append(AccountError(account.email, reason))
            else:
                accounts.append(account)
        return accounts, errors

    # -- running backend calls --------------------------------------------------

    def _current(self, email: str) -> Account:
        """The account as stored now; raises if it must not be contacted."""
        current = self.repo.get(email)
        if current is None:
            raise PimError(f"unknown account: {email}")
        reason = _unavailable(current)
        if reason:
            raise PimError(reason)
        return current

    def _dav_host(self, account: Account, capability: str) -> str:
        url = account.carddav_url if capability == "contacts" else account.caldav_url
        return urlsplit(url or "").hostname or ""

    @asynccontextmanager
    async def _queued(self, account: Account, capability: str) -> AsyncIterator[None]:
        """Wait (without holding a worker thread) for the account's turn and a host slot.

        CalDAV/CardDAV calls to one account run one at a time, and at most
        `DAV_CALLS_PER_HOST` run at once per DAV host. Google accounts have no fail2ban
        behind them and are not queued.
        """
        if account.provider == Provider.GOOGLE:
            yield
            return
        host = self._dav_host(account, capability)
        queue = self._account_queues.setdefault(account.email, asyncio.Lock())
        slots = self._host_slots.setdefault(host, asyncio.Semaphore(DAV_CALLS_PER_HOST))
        async with queue, slots:
            yield

    @contextmanager
    def _login_lock(self, account: Account) -> Iterator[None]:
        """The account's login lock shared with the IMAP pool (DAV accounts only)."""
        if account.provider == Provider.GOOGLE:
            yield
            return
        lock = self.locks.account(account.email)
        if not lock.acquire(timeout=self.timeout):
            raise PimError(TIMEOUT_MESSAGE)
        try:
            yield
        finally:
            lock.release()

    async def _call(
        self,
        account: Account,
        capability: str,
        fn: Callable[[object], object],
        write: bool = False,
    ):
        """Run `fn(backend)` for `account` in a worker thread under the timeout.

        The account is re-read first, and again under its login lock right before the
        backend is built: if it became unavailable meanwhile (e.g. a concurrent call
        tripped the breaker), nothing is contacted. The queue slot is held until the
        worker thread finishes, even when the caller timed out, so an abandoned call
        never overlaps the next one. A call that times out before it started is dropped;
        a write that timed out after it started may still complete on the server, so its
        message says so.
        """
        self._current(account.email)  # cheap pre-check: a blocked account does not queue
        state = threading.Lock()
        flags = {"started": False, "abandoned": False}

        def work():
            with self._login_lock(account):
                current = self._current(account.email)  # authoritative, under the lock
                with state:
                    if flags["abandoned"]:
                        raise PimError(TIMEOUT_MESSAGE)
                    flags["started"] = True
                backend = self.backend(current, capability)
                try:
                    return fn(backend)
                finally:
                    _close(backend)

        async def run():
            async with self._queued(account, capability):
                if flags["abandoned"]:  # timed out while queued: skip the thread entirely
                    raise PimError(TIMEOUT_MESSAGE)
                return await asyncio.to_thread(work)

        task = asyncio.ensure_future(run())
        task.add_done_callback(_consume)
        try:
            return await asyncio.wait_for(asyncio.shield(task), self.timeout)
        except TimeoutError as e:
            with state:
                flags["abandoned"] = True
                started = flags["started"]
            raise PimError(WRITE_TIMEOUT_MESSAGE if write and started else TIMEOUT_MESSAGE) from e

    async def _write(self, capability: str, email: str, fn: Callable[[object], object]):
        accounts, _ = self._accounts_for(capability, email)
        return await self._call(accounts[0], capability, fn, write=True)

    async def _many(
        self, capability: str, email: str | None, fn: Callable[[object], list]
    ) -> tuple[list, list[AccountError]]:
        accounts, errors = self._accounts_for(capability, email)
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run(account: Account):
            async with sem:
                return await self._call(account, capability, fn)

        results = await asyncio.gather(*(run(a) for a in accounts), return_exceptions=True)
        items: list = []
        for account, res in zip(accounts, results, strict=True):
            if isinstance(res, PimError):
                errors.append(AccountError(account.email, str(res)))
            elif isinstance(res, BaseException):
                # Unexpected: report the type only, its text could carry anything.
                log.warning(
                    "%s call failed for %s: %s", capability, account.email, type(res).__name__
                )
                errors.append(
                    AccountError(account.email, f"unexpected error: {type(res).__name__}")
                )
            else:
                items.extend(res)
        return items, errors

    # -- calendars & events -----------------------------------------------------

    async def list_calendars(
        self, email: str | None
    ) -> tuple[list[CalendarInfo], list[AccountError]]:
        return await self._many("calendar", email, lambda b: b.list_calendars())

    async def list_events(
        self,
        email: str | None,
        calendar_id: str | None,
        start: datetime,
        end: datetime,
        query: str | None,
    ) -> tuple[list[EventInfo], list[AccountError]]:
        events, errors = await self._many(
            "calendar", email, lambda b: b.list_events(calendar_id, start, end, query)
        )
        events.sort(key=lambda e: _start_key(e.start, self.tz))
        return events, errors

    async def create_event(
        self, email: str, calendar_id: str | None, data: EventInput
    ) -> EventInfo:
        return await self._write("calendar", email, lambda b: b.create_event(calendar_id, data))

    async def update_event(
        self, email: str, calendar_id: str, event_id: str, data: EventInput
    ) -> EventInfo:
        return await self._write(
            "calendar", email, lambda b: b.update_event(calendar_id, event_id, data)
        )

    async def delete_event(self, email: str, calendar_id: str, event_id: str) -> None:
        await self._write("calendar", email, lambda b: b.delete_event(calendar_id, event_id))

    # -- tasks ------------------------------------------------------------------

    async def list_task_lists(
        self, email: str | None
    ) -> tuple[list[TaskListInfo], list[AccountError]]:
        return await self._many("tasks", email, lambda b: b.list_task_lists())

    async def list_tasks(
        self, email: str | None, list_id: str | None, include_completed: bool
    ) -> tuple[list[TaskInfo], list[AccountError]]:
        return await self._many("tasks", email, lambda b: b.list_tasks(list_id, include_completed))

    async def create_task(self, email: str, list_id: str | None, data: TaskInput) -> TaskInfo:
        return await self._write("tasks", email, lambda b: b.create_task(list_id, data))

    async def update_task(
        self, email: str, list_id: str, task_id: str, data: TaskInput
    ) -> TaskInfo:
        return await self._write("tasks", email, lambda b: b.update_task(list_id, task_id, data))

    async def delete_task(self, email: str, list_id: str, task_id: str) -> None:
        await self._write("tasks", email, lambda b: b.delete_task(list_id, task_id))

    # -- contacts ---------------------------------------------------------------

    async def search_contacts(
        self, query: str, email: str | None, limit: int
    ) -> tuple[list[ContactInfo], list[AccountError]]:
        contacts, errors = await self._many(
            "contacts", email, lambda b: b.search_contacts(query, limit)
        )
        return contacts[:limit], errors
