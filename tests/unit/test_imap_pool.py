import ssl
import threading
from typing import ClassVar

import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.mail.imap import AccountUnavailable, AuthFailed, ImapConnector, ImapError, ImapPool


class FakeClient:
    def __init__(self):
        self.noops = 0
        self.closed = False

    def noop(self):
        self.noops += 1

    def logout(self):
        self.closed = True


class FakeConnector:
    def __init__(self, fail=None):
        self.calls = 0
        self.fail = fail
        self.clients = []

    def connect(self, account, secret):
        self.calls += 1
        if self.fail:
            raise self.fail
        c = FakeClient()
        self.clients.append(c)
        return c


@pytest.fixture
def acct(repo):
    repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="pw",
    )
    return "a@x.cz"


def test_connects_and_marks_connected(repo, acct):
    conn = FakeConnector()
    pool = ImapPool(repo, conn)
    with pool.session(acct) as c:
        assert isinstance(c, FakeClient)
    assert repo.get(acct).status == AccountStatus.CONNECTED


def test_reuses_connection_until_idle(repo, acct):
    now = [0.0]
    conn = FakeConnector()
    pool = ImapPool(repo, conn, idle_seconds=100, clock=lambda: now[0])
    with pool.session(acct):
        pass
    now[0] = 50
    with pool.session(acct):
        pass
    assert conn.calls == 1
    now[0] = 500
    with pool.session(acct):
        pass
    assert conn.calls == 2 and conn.clients[0].closed


def test_auth_failure_trips_breaker(repo, acct):
    conn = FakeConnector(fail=AuthFailed("login failed: AUTHENTICATIONFAILED"))
    pool = ImapPool(repo, conn)
    with pytest.raises(AuthFailed), pool.session(acct):
        pass
    assert repo.get(acct).status == AccountStatus.NEEDS_RECONNECT
    for _ in range(5):
        with pytest.raises(AccountUnavailable), pool.session(acct):
            pass
    assert conn.calls == 1  # never retried automatically


def test_manual_attempt_allowed_once(repo, acct):
    repo.set_status(acct, AccountStatus.NEEDS_RECONNECT, "x")
    conn = FakeConnector()
    pool = ImapPool(repo, conn)
    with pool.session(acct, manual=True):
        pass
    assert conn.calls == 1 and repo.get(acct).status == AccountStatus.CONNECTED


def test_network_error_sets_error_status(repo, acct):
    pool = ImapPool(repo, FakeConnector(fail=OSError("connection refused")))
    with pytest.raises(ImapError), pool.session(acct):
        pass
    assert repo.get(acct).status == AccountStatus.ERROR


def test_connection_error_inside_block_drops_connection(repo, acct):
    conn = FakeConnector()
    pool = ImapPool(repo, conn)
    with pytest.raises(ImapError), pool.session(acct):
        raise OSError("reset")
    with pool.session(acct):
        pass
    assert conn.calls == 2


def test_disabled_and_unknown(repo, acct):
    pool = ImapPool(repo, FakeConnector())
    repo.set_enabled(acct, False)
    with pytest.raises(AccountUnavailable), pool.session(acct):
        pass
    with pytest.raises(ImapError), pool.session("nobody@x.cz"):
        pass


def test_google_needs_connect_is_blocked(repo):
    repo.upsert(
        email="g@gmail.com",
        provider=Provider.GOOGLE,
        imap_host="imap.gmail.com",
        imap_port=993,
        imap_security="ssl",
        status=AccountStatus.NEEDS_GOOGLE_CONNECT,
    )
    conn = FakeConnector()
    with pytest.raises(AccountUnavailable), ImapPool(repo, conn).session("g@gmail.com"):
        pass
    assert conn.calls == 0


class _SlowFailConnector:
    """connect() blocks until released, then always trips the breaker.

    Lets a test hold thread A inside `connector.connect()` (i.e. holding
    `entry.lock`) for as long as needed before letting it fail, so a second
    thread can be driven deterministically into the race window.
    """

    def __init__(self):
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def connect(self, account, secret):
        self.calls += 1
        self.started.set()
        assert self.release.wait(timeout=5), "test never released the connector"
        raise AuthFailed("login failed: AUTHENTICATIONFAILED")


class _CountingRepo:
    """Delegates to a real `AccountRepo`, but fires an Event the instant the
    Nth call to `.get()` returns -- a deterministic substitute for a sleep
    when a test needs to know "the other thread has just read the account".
    """

    def __init__(self, inner, fire_on: int):
        self._inner = inner
        self._fire_on = fire_on
        self._count = 0
        self._count_lock = threading.Lock()
        self.reached = threading.Event()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def get(self, email):
        result = self._inner.get(email)
        with self._count_lock:
            self._count += 1
            n = self._count
        if n == self._fire_on:
            self.reached.set()
        return result


def test_breaker_race_blocks_second_caller_after_lock(repo, acct):
    """Regression: thread A holds `entry.lock` inside a slow `connect()` that
    will trip the breaker. Thread B passes the *pre-lock* status check while
    the account still looks healthy, then queues on `entry.lock`. Once A
    fails and releases the lock, B must re-check the account's fresh status
    before calling `connect()` again -- not blindly reuse the stale snapshot
    it read before it queued. Without the post-lock re-check, B also calls
    `connect()` and both callers hit the real server with bad credentials:
    exactly the fail2ban-triggering burst this pool exists to prevent.

    Call-count choreography on `._count_lock`-guarded `.get()`:
      1. thread A's pre-lock check (session())
      2. thread A's post-lock re-check (_acquire(), about to connect)
         -- A then blocks inside connect() on `release`
      3. thread B's pre-lock check (session()) -- still sees the healthy
         status, since A hasn't failed yet; then B queues on entry.lock
      (test releases A here)
      4. thread B's post-lock re-check (_acquire()), now must see
         NEEDS_RECONNECT and raise AccountUnavailable *without* calling
         connect() again.
    """
    conn = _SlowFailConnector()
    counting_repo = _CountingRepo(repo, fire_on=3)
    pool = ImapPool(counting_repo, conn)
    outcomes = {}

    def run_a():
        try:
            with pool.session(acct):
                pass
        except AuthFailed:
            outcomes["a"] = "AuthFailed"
        except Exception as e:  # noqa: BLE001 -- surfaced via outcomes, not swallowed
            outcomes["a"] = repr(e)

    def run_b():
        try:
            with pool.session(acct):
                pass
        except AccountUnavailable:
            outcomes["b"] = "AccountUnavailable"
        except Exception as e:  # noqa: BLE001 -- surfaced via outcomes, not swallowed
            outcomes["b"] = repr(e)

    thread_a = threading.Thread(target=run_a)
    thread_b = threading.Thread(target=run_b)

    thread_a.start()
    assert conn.started.wait(timeout=5), "thread A never reached connect()"

    thread_b.start()
    assert counting_repo.reached.wait(timeout=5), "thread B never reached its pre-lock check"

    conn.release.set()
    thread_a.join(timeout=5)
    thread_b.join(timeout=5)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()

    assert outcomes.get("a") == "AuthFailed"
    assert outcomes.get("b") == "AccountUnavailable"
    assert conn.calls == 1  # B must never have called connect()


def test_starttls_failure_closes_socket_and_sets_error(monkeypatch, repo):
    repo.upsert(
        email="s@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=143,
        imap_security="starttls",
        secret="pw",
    )
    created = []

    class FakeStarttlsFailClient:
        def __init__(self, host, port, ssl=False, ssl_context=None, timeout=None):
            self.shutdown_called = False
            created.append(self)

        def starttls(self, ctx):
            raise ssl.SSLError("starttls failed")

        def shutdown(self):
            self.shutdown_called = True

    monkeypatch.setattr("postroom.mail.imap.SafeIMAPClient", FakeStarttlsFailClient)

    pool = ImapPool(repo, ImapConnector())
    with pytest.raises(ImapError), pool.session("s@x.cz"):
        pass

    assert len(created) == 1
    assert created[0].shutdown_called is True
    assert repo.get("s@x.cz").status == AccountStatus.ERROR


@pytest.fixture
def gmail(repo):
    repo.upsert(
        email="g@gmail.com",
        provider=Provider.GOOGLE,
        imap_host="imap.gmail.com",
        imap_port=993,
        imap_security="ssl",
        status=AccountStatus.CONNECTED,
    )
    return "g@gmail.com"


@pytest.fixture
def no_sockets(monkeypatch):
    created = []

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            created.append(self)

        def oauth2_login(self, user, token):
            pass

        def logout(self):
            pass

    monkeypatch.setattr("postroom.mail.imap.SafeIMAPClient", RecordingClient)
    return created


def test_google_token_error_sets_error_and_opens_no_socket(repo, gmail, no_sockets):
    from postroom.google.oauth import GoogleOAuthError

    def token(email):
        raise GoogleOAuthError("Google token refresh failed: HTTP 503")

    pool = ImapPool(repo, ImapConnector(google_token=token))
    with pytest.raises(ImapError) as err, pool.session(gmail):
        pass
    assert "HTTP 503" in str(err.value)
    assert no_sockets == []
    acc = repo.get(gmail)
    assert acc.status == AccountStatus.ERROR and "HTTP 503" in acc.last_error


class LoginRecorder:
    logins: ClassVar[list[tuple]] = []

    def __init__(self, *args, **kwargs):
        pass

    def login(self, user, password):
        LoginRecorder.logins.append(("login", user, password))

    def oauth2_login(self, user, token):
        LoginRecorder.logins.append(("oauth2_login", user, token))

    def noop(self):
        pass

    def logout(self):
        pass


def _no_google_token(email):
    raise AssertionError("an app-password account must never ask for a Google token")


def test_gmail_app_password_account_logs_in_with_login(repo, monkeypatch):
    monkeypatch.setattr("postroom.mail.imap.SafeIMAPClient", LoginRecorder)
    monkeypatch.setattr(LoginRecorder, "logins", [])
    repo.upsert(
        email="p@gmail.com",
        provider=Provider.IMAP,
        imap_host="imap.gmail.com",
        imap_port=993,
        imap_security="ssl",
        secret="abcd efgh ijkl mnop",
        status=AccountStatus.CONNECTED,
    )
    pool = ImapPool(repo, ImapConnector(google_token=_no_google_token))
    with pool.session("p@gmail.com") as c:
        c.noop()
    assert LoginRecorder.logins == [("login", "p@gmail.com", "abcd efgh ijkl mnop")]
    assert repo.get("p@gmail.com").status == AccountStatus.CONNECTED


def test_google_oauth_account_logs_in_with_xoauth2(repo, gmail, monkeypatch):
    monkeypatch.setattr("postroom.mail.imap.SafeIMAPClient", LoginRecorder)
    monkeypatch.setattr(LoginRecorder, "logins", [])
    pool = ImapPool(repo, ImapConnector(google_token=lambda email: "ya29.token"))
    with pool.session(gmail) as c:
        c.noop()
    assert LoginRecorder.logins == [("oauth2_login", gmail, "ya29.token")]


def test_google_token_auth_failure_trips_breaker_without_socket(repo, gmail, no_sockets):
    def token(email):
        raise AuthFailed("Google access was revoked")

    pool = ImapPool(repo, ImapConnector(google_token=token))
    with pytest.raises(AuthFailed), pool.session(gmail):
        pass
    assert no_sockets == []
    assert repo.get(gmail).status == AccountStatus.NEEDS_RECONNECT


def test_google_token_fetched_before_socket(repo, gmail, no_sockets):
    order = []

    def token(email):
        order.append(("token", len(no_sockets)))
        return "tok"

    pool = ImapPool(repo, ImapConnector(google_token=token))
    with pool.session(gmail):
        pass
    assert order == [("token", 0)] and len(no_sockets) == 1


def test_successful_login_does_not_clobber_a_concurrent_breaker_trip(repo, acct):
    """A CalDAV/CardDAV 401 (or a revoked Google grant) recorded while an IMAP login was
    in flight must survive that login's success: the connected status is compare-and-set.
    """

    class TrippedMeanwhile(FakeConnector):
        def connect(self, account, secret):
            client = super().connect(account, secret)
            repo.set_status(account.email, AccountStatus.NEEDS_RECONNECT, "dav 401")
            return client

    pool = ImapPool(repo, TrippedMeanwhile())
    with pool.session(acct):
        pass
    acc = repo.get(acct)
    assert acc.status == AccountStatus.NEEDS_RECONNECT and acc.last_error == "dav 401"


def test_connect_waits_for_the_shared_account_login_lock(repo, acct):
    """The pool's connect() takes the same per-account lock as CalDAV/CardDAV calls and
    re-reads the status under it, so a DAV login that failed meanwhile stops it.
    """
    from postroom.login_locks import LoginLocks

    locks = LoginLocks()
    conn = FakeConnector()
    pool = ImapPool(repo, conn, locks=locks)
    lock = locks.account(acct)
    lock.acquire()
    errors = []

    def mail():
        try:
            with pool.session(acct):
                pass
        except ImapError as e:
            errors.append(e)

    t = threading.Thread(target=mail)
    t.start()
    t.join(0.2)
    assert t.is_alive() and conn.calls == 0  # queued on the account lock
    repo.set_status(acct, AccountStatus.NEEDS_RECONNECT, "CalDAV/CardDAV login failed")
    lock.release()
    t.join(5)
    assert conn.calls == 0 and isinstance(errors[0], AccountUnavailable)
