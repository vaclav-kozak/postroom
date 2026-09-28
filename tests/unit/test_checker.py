import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.checker import AccountChecker
from postroom.mail.imap import AuthFailed, ImapPool


class Conn:
    def __init__(self, bad=()):
        self.bad = set(bad)
        self.calls = []

    def connect(self, account, secret):
        self.calls.append(account.email)
        if account.email in self.bad:
            raise AuthFailed("login failed")

        class C:
            def noop(self):
                pass

            def logout(self):
                pass

        return C()


@pytest.fixture
def accounts(repo):
    for e, st in [
        ("ok@x.cz", AccountStatus.PENDING),
        ("bad@x.cz", AccountStatus.CONNECTED),
        ("locked@x.cz", AccountStatus.NEEDS_RECONNECT),
    ]:
        repo.upsert(
            email=e,
            provider=Provider.IMAP,
            imap_host="h",
            imap_port=993,
            imap_security="ssl",
            secret="p",
            status=st,
        )
    repo.upsert(
        email="off@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="p",
    )
    repo.set_enabled("off@x.cz", False)


async def test_check_all_respects_breaker(repo, accounts):
    conn = Conn(bad={"bad@x.cz"})
    res = await AccountChecker(repo, ImapPool(repo, conn)).check_all()
    assert res == {"ok@x.cz": AccountStatus.CONNECTED, "bad@x.cz": AccountStatus.NEEDS_RECONNECT}
    assert sorted(conn.calls) == ["bad@x.cz", "ok@x.cz"]
    # second run: bad account is now needs_reconnect → not retried
    conn.calls.clear()
    await AccountChecker(repo, ImapPool(repo, conn)).check_all()
    assert conn.calls == ["ok@x.cz"]


async def test_manual_check_retries_locked(repo, accounts):
    conn = Conn()
    st = await AccountChecker(repo, ImapPool(repo, conn)).check_account("locked@x.cz", manual=True)
    assert st == AccountStatus.CONNECTED


async def test_error_backoff(repo, accounts):
    now = [5000.0]
    repo.set_status("ok@x.cz", AccountStatus.ERROR, "timeout")
    conn = Conn()
    checker = AccountChecker(repo, ImapPool(repo, conn), clock=lambda: now[0])
    # last_check_at was just set by set_status (real time) → within 300 s of real now
    import time

    now[0] = time.time() + 10
    await checker.check_all()
    assert "ok@x.cz" not in conn.calls
    now[0] = time.time() + 400
    await checker.check_all()
    assert "ok@x.cz" in conn.calls


# --- maintenance loop and lifespan wiring (beyond the brief) -------------------------------


class Provider_:
    def __init__(self, fail=False):
        self.purges = 0
        self.fail = fail

    def purge(self):
        self.purges += 1
        if self.fail:
            raise RuntimeError("db locked")


async def _run_ticks(checker, provider, interval, ticks):
    import asyncio

    stop = asyncio.Event()
    task = asyncio.create_task(checker.run_maintenance(provider, interval, stop))
    for _ in range(200):
        await asyncio.sleep(0.01)
        if checker.ticks_seen >= ticks:
            break
    stop.set()
    await asyncio.wait_for(task, 2)


class CountingChecker(AccountChecker):
    tick_seconds = 0.01

    def __init__(self, *a, fail_checks=False, **kw):
        super().__init__(*a, **kw)
        self.ticks_seen = 0
        self.checks = 0
        self.fail_checks = fail_checks
        orig = self.pool.close_idle

        def close_idle():
            self.ticks_seen += 1
            orig()

        self.pool.close_idle = close_idle

    async def check_all(self, background=True):
        self.checks += 1
        if self.fail_checks:
            raise RuntimeError("boom")
        return await super().check_all(background)


async def test_maintenance_schedule(repo, accounts):
    # interval = 3 ticks → full checks on ticks 1, 4, 7; idle cleanup on every tick
    checker = CountingChecker(repo, ImapPool(repo, Conn()))
    provider = Provider_()
    await _run_ticks(checker, provider, 0.03, 7)
    assert checker.ticks_seen >= 7
    assert checker.checks == provider.purges == len(range(0, checker.ticks_seen, 3))
    assert repo.get("ok@x.cz").status == AccountStatus.CONNECTED


async def test_maintenance_survives_errors(repo, accounts):
    checker = CountingChecker(repo, ImapPool(repo, Conn()), fail_checks=True)
    provider = Provider_(fail=True)
    await _run_ticks(checker, provider, 0.01, 3)
    assert checker.checks >= 3 and provider.purges >= 3


async def test_maintenance_stops_promptly(repo, accounts):
    import asyncio

    checker = AccountChecker(repo, ImapPool(repo, Conn()))  # 60 s tick
    stop = asyncio.Event()
    task = asyncio.create_task(checker.run_maintenance(Provider_(), 21600, stop))
    await asyncio.sleep(0.01)
    stop.set()
    await asyncio.wait_for(task, 1)


@pytest.mark.parametrize("interval", [0, 3600])
async def test_app_lifespan_runs_maintenance(settings, monkeypatch, interval):
    import asyncio

    from postroom.app import build_services, create_app

    settings.public_url = "http://localhost"
    settings.check_interval_seconds = interval
    services = build_services(settings)
    started, closed = asyncio.Event(), []

    async def fake_run(provider, iv, stop):
        assert provider is services.provider and iv == interval
        started.set()
        await stop.wait()

    monkeypatch.setattr(services.checker, "run_maintenance", fake_run)
    monkeypatch.setattr(services.pool, "close_all", lambda: closed.append(True))
    app = create_app(settings, services)
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.05)
        assert started.is_set() == (interval > 0)
    assert closed == [True]


async def test_services_check_account_delegates_to_checker(settings, repo, accounts):
    from postroom.app import build_services

    services = build_services(settings)
    assert services.check_account == services.checker.check_account
