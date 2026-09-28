"""fail2ban safety across parallel calls: one wrong password costs exactly one failed login.

mailcow's fail2ban counts SOGo (CalDAV/CardDAV) and IMAP failures together, so parallel
calls on one account must be serialised and re-check the breaker before logging in.
"""

import asyncio
import http.server
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.login_locks import LoginLocks
from postroom.mail.imap import AuthFailed, ImapError, ImapPool
from postroom.pim.models import PimError
from postroom.pim.service import PimService


class _Counting401(http.server.BaseHTTPRequestHandler):
    """Answers everything with 401; counts requests that carried credentials."""

    credentialed: list[str]
    lock: threading.Lock

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        if "Authorization" in self.headers:
            with self.lock:
                self.credentialed.append(f"{self.command} {self.path}")
            time.sleep(0.2)  # dovecot/SOGo delay failed logins
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="x"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_PROPFIND = do_REPORT = do_GET = do_PUT = do_DELETE = do_OPTIONS = _any

    def log_message(self, *args):
        pass


@pytest.fixture
def dav_401():
    handler = type("H", (_Counting401,), {"credentialed": [], "lock": threading.Lock()})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", handler.credentialed
    srv.shutdown()
    srv.server_close()


def _account(repo, email, base):
    repo.upsert(
        email=email,
        provider=Provider.IMAP,
        imap_host="127.0.0.1",
        imap_port=993,
        imap_security="ssl",
        caldav_url=f"{base}/SOGo/dav/{email}/Calendar/",
        carddav_url=f"{base}/SOGo/dav/{email}/Contacts/",
        secret="wrong-password",
        status=AccountStatus.CONNECTED,
    )


async def test_parallel_pim_calls_with_a_wrong_password_make_one_failed_login(repo, dav_401):
    base, credentialed = dav_401
    _account(repo, "u@x.cz", base)
    pim = PimService(repo, None)
    now = datetime.now(UTC)
    week = now + timedelta(days=7)
    calls = [
        pim.list_calendars(None),
        pim.list_events(None, None, now, week, None),
        pim.list_task_lists(None),
        pim.list_tasks(None, None, False),
        pim.search_contacts("jan", None, 20),
        pim.list_events("u@x.cz", None, now, week, "x"),
        pim.search_contacts("petr", "u@x.cz", 5),
        pim.list_calendars("u@x.cz"),
    ]
    results = await asyncio.gather(*calls, return_exceptions=True)
    assert len(credentialed) == 1, credentialed
    assert repo.get("u@x.cz").status == AccountStatus.NEEDS_RECONNECT
    # Every call failed; none of them crashed with anything but a clean PimError.
    for res in results:
        if isinstance(res, tuple):
            items, errors = res
            assert items == [] and len(errors) == 1
        else:
            assert isinstance(res, PimError)


async def test_accounts_on_one_dav_host_each_fail_once(repo, dav_401):
    base, credentialed = dav_401
    for i in range(3):
        _account(repo, f"u{i}@x.cz", base)
    pim = PimService(repo, None)
    now = datetime.now(UTC)
    await asyncio.gather(
        pim.list_calendars(None),
        pim.list_tasks(None, None, False),
        pim.search_contacts("jan", None, 20),
    )
    assert len(credentialed) == 3
    assert {a.status for a in repo.list()} == {AccountStatus.NEEDS_RECONNECT}
    await pim.list_events(None, None, now, now + timedelta(days=1), None)
    assert len(credentialed) == 3


async def test_queued_call_fails_fast_once_the_breaker_trips(repo):
    """A call waiting on the account lock re-reads the status and never builds a backend."""
    repo.upsert(
        email="s@example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        caldav_url="https://h/dav/",
        secret="p",
        status=AccountStatus.CONNECTED,
    )
    built = []
    entered = threading.Event()

    class Tripping:
        def list_calendars(self):
            entered.set()
            time.sleep(0.2)
            repo.set_status("s@example.com", AccountStatus.NEEDS_RECONNECT, "tripped")
            raise PimError("CalDAV login failed")

    def factory(account, capability):
        built.append(capability)
        return Tripping()

    pim = PimService(repo, None, backend_factory=factory)
    first = asyncio.create_task(pim.list_calendars("s@example.com"))
    await asyncio.to_thread(entered.wait, 5)
    second = asyncio.create_task(pim.list_tasks("s@example.com", None, False))
    _, errors = await first
    assert [e.error for e in errors] == ["CalDAV login failed"]
    _, errors = await second
    assert [e.error for e in errors] == ["account unavailable: needs_reconnect"]
    assert built == ["calendar"]


async def test_imap_connect_and_dav_call_share_the_account_lock(repo, dav_401):
    """A wrong password seen by IMAP and CalDAV at once still costs a single failure."""
    base, credentialed = dav_401
    _account(repo, "u@x.cz", base)
    imap_logins = []

    class FailingConnector:
        def connect(self, account, secret):
            imap_logins.append(account.email)
            time.sleep(0.2)
            raise AuthFailed("login failed: [AUTHENTICATIONFAILED]")

    locks = LoginLocks()
    pool = ImapPool(repo, FailingConnector(), locks=locks)
    pim = PimService(repo, None, locks=locks)

    def mail():
        try:
            with pool.session("u@x.cz"):
                pass
        except ImapError:
            pass

    await asyncio.gather(
        asyncio.to_thread(mail),
        pim.list_calendars("u@x.cz"),
        asyncio.to_thread(mail),
        pim.search_contacts("jan", "u@x.cz", 5),
        return_exceptions=True,
    )
    assert len(imap_logins) + len(credentialed) == 1, (imap_logins, credentialed)
    assert repo.get("u@x.cz").status == AccountStatus.NEEDS_RECONNECT


async def test_abandoned_call_does_not_run_after_its_timeout(repo):
    """A call that timed out while queued on the account lock never reaches the server."""
    repo.upsert(
        email="s@example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        caldav_url="https://h/dav/",
        secret="p",
        status=AccountStatus.CONNECTED,
    )
    ran = []
    entered = threading.Event()

    class Slow:
        def list_calendars(self):
            ran.append("calendars")
            entered.set()
            time.sleep(0.3)
            return []

        def create_event(self, calendar_id, data):
            ran.append("create")

    pim = PimService(repo, None, backend_factory=lambda a, c: Slow(), timeout=0.1)
    first = asyncio.create_task(pim.list_calendars("s@example.com"))
    await asyncio.to_thread(entered.wait, 5)
    # It never started, so the usual "may have been applied" warning does not apply.
    with pytest.raises(PimError, match="try again later"):
        await pim.create_event("s@example.com", None, object())
    _, errors = await first
    assert "did not respond in time" in errors[0].error
    await asyncio.sleep(0.5)
    assert ran == ["calendars"]


async def test_dav_calls_run_one_per_account_and_two_per_host(repo):
    for email in ("a@example.com", "b@example.com", "c@example.com"):
        repo.upsert(
            email=email,
            provider=Provider.IMAP,
            imap_host="h",
            imap_port=993,
            imap_security="ssl",
            caldav_url="https://dav.example.com/SOGo/dav/",
            secret="p",
            status=AccountStatus.CONNECTED,
        )
    guard = threading.Lock()
    running: dict[str, int] = {}
    peak = {"host": 0, "account": 0}

    class Probe:
        def __init__(self, email):
            self.email = email

        def list_calendars(self):
            with guard:
                running[self.email] = running.get(self.email, 0) + 1
                peak["host"] = max(peak["host"], sum(running.values()))
                peak["account"] = max(peak["account"], running[self.email])
            time.sleep(0.05)
            with guard:
                running[self.email] -= 1
            return []

    pim = PimService(repo, None, backend_factory=lambda a, c: Probe(a.email))
    await asyncio.gather(*(pim.list_calendars(None) for _ in range(4)))
    assert peak == {"host": 2, "account": 1}
