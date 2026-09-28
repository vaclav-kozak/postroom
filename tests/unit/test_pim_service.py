import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx

from postroom.accounts import AccountStatus, Provider
from postroom.dav.caldav_backend import CalDavBackend
from postroom.dav.carddav import CardDavBackend
from postroom.google.api import GoogleApi
from postroom.pim.models import CalendarInfo, ContactInfo, EventInfo, EventInput, PimError
from postroom.pim.service import PimService

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")


class FakeBackend:
    def __init__(self, email, fail=False):
        self.email, self.fail = email, fail
        self.created = []

    def list_calendars(self):
        if self.fail:
            raise PimError("CalDAV login failed")
        return [CalendarInfo(self.email, f"{self.email}/cal", "Personal", False, True)]

    def list_events(self, calendar_id, start, end, query):
        return [
            EventInfo(
                self.email,
                "c",
                f"{self.email}-e",
                "E",
                start.isoformat(),
                None,
                False,
                None,
                None,
                False,
                False,
            )
        ]

    def create_event(self, calendar_id, data):
        self.created.append((calendar_id, data))
        return EventInfo(
            self.email,
            "c",
            "new",
            data.title,
            data.start.isoformat(),
            data.end.isoformat(),
            False,
            None,
            None,
            False,
            False,
        )


@pytest.fixture
def setup(repo):
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
    repo.upsert(
        email="bad@example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        caldav_url="https://h/dav/",
        secret="p",
        status=AccountStatus.CONNECTED,
    )
    repo.upsert(
        email="g@gmail.com", provider=Provider.GOOGLE, status=AccountStatus.NEEDS_GOOGLE_CONNECT
    )
    repo.upsert(
        email="f@example.org",
        provider=Provider.IMAP,
        imap_host="imap.example.org",
        imap_port=143,
        imap_security="starttls",
        secret="p",
        status=AccountStatus.CONNECTED,
    )
    backends = {}

    def factory(account, capability):
        return backends.setdefault(
            account.email, FakeBackend(account.email, fail=account.email.startswith("bad"))
        )

    return PimService(repo, None, backend_factory=factory), backends


async def test_list_calendars_all_accounts(setup):
    svc, _ = setup
    cals, errors = await svc.list_calendars(None)
    assert [c.account for c in cals] == ["s@example.com"]
    assert sorted(e.account for e in errors) == ["bad@example.com", "g@gmail.com"]


async def test_capability_checks(setup):
    svc, _ = setup
    with pytest.raises(PimError, match="has no calendar"):
        await svc.list_calendars("f@example.org")
    with pytest.raises(PimError, match="unavailable"):
        await svc.list_calendars("g@gmail.com")
    with pytest.raises(PimError, match="unknown"):
        await svc.list_calendars("nobody@x.example.com")


async def test_create_event_routes_to_account(setup):
    svc, backends = setup
    start = datetime(2026, 10, 1, 9, tzinfo=TZ)
    ev = await svc.create_event(
        "s@example.com", None, EventInput(title="T", start=start, end=start + timedelta(hours=1))
    )
    assert ev.account == "s@example.com" and backends["s@example.com"].created


# -- extra tests: fail2ban safety, breaker wiring, error hygiene ----------------------

DAV = "https://dav.example.com/SOGo/dav/s@example.com/"


def _imap(repo, email, status=AccountStatus.CONNECTED, **kw):
    repo.upsert(
        email=email,
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="hunter2-secret",
        status=status,
        **kw,
    )


class CountingFactory:
    def __init__(self, backend=None):
        self.calls = []
        self.backend = backend

    def __call__(self, account, capability):
        self.calls.append((account.email, capability))
        return self.backend or FakeBackend(account.email)


@pytest.mark.parametrize(
    "status", [AccountStatus.NEEDS_RECONNECT, AccountStatus.NEEDS_GOOGLE_CONNECT]
)
async def test_blocked_account_builds_no_backend(repo, status):
    _imap(repo, "s@example.com", status=status, caldav_url=DAV, carddav_url=DAV)
    factory = CountingFactory()
    svc = PimService(repo, None, backend_factory=factory)
    start = datetime(2026, 10, 1, 9, tzinfo=TZ)
    data = EventInput(title="T", start=start, end=start + timedelta(hours=1))
    for call in (
        svc.list_calendars("s@example.com"),
        svc.create_event("s@example.com", None, data),
        svc.delete_event("s@example.com", "c", "e"),
        svc.list_tasks("s@example.com", None, False),
        svc.search_contacts("jan", "s@example.com", 5),
    ):
        with pytest.raises(PimError, match=f"account unavailable: {status.value}"):
            await call
    cals, errors = await svc.list_calendars(None)
    assert cals == []
    assert [(e.account, e.error) for e in errors] == [
        ("s@example.com", f"account unavailable: {status.value}")
    ]
    assert factory.calls == []


async def test_disabled_account_is_skipped_and_refused(repo):
    _imap(repo, "s@example.com", caldav_url=DAV)
    repo.set_enabled("s@example.com", False)
    factory = CountingFactory()
    svc = PimService(repo, None, backend_factory=factory)
    with pytest.raises(PimError, match="account unavailable: disabled"):
        await svc.list_calendars("s@example.com")
    assert await svc.list_calendars(None) == ([], [])
    assert factory.calls == []


async def test_account_blocked_after_selection_is_not_contacted(repo):
    _imap(repo, "a@example.com", caldav_url=DAV)
    _imap(repo, "b@example.com", caldav_url=DAV)

    class Tripping(FakeBackend):
        def list_calendars(self):
            repo.set_status("b@example.com", AccountStatus.NEEDS_RECONNECT, "tripped")
            return super().list_calendars()

    factory = CountingFactory(Tripping("a@example.com"))
    svc = PimService(repo, None, backend_factory=factory, max_concurrency=1)
    cals, errors = await svc.list_calendars(None)
    assert [c.account for c in cals] == ["a@example.com"]
    assert [(e.account, e.error) for e in errors] == [
        ("b@example.com", "account unavailable: needs_reconnect")
    ]
    assert factory.calls == [("a@example.com", "calendar")]


def test_default_factory_wires_caldav_breaker(repo):
    _imap(repo, "s@example.com", caldav_url=DAV, imap_username="login-name")
    svc = PimService(repo, None)
    backend = svc.backend(repo.get("s@example.com"), "calendar")
    assert isinstance(backend, CalDavBackend) and backend.account == "s@example.com"
    assert backend._client.username == "login-name"
    backend._on_auth_failure()
    acc = repo.get("s@example.com")
    assert acc.status == AccountStatus.NEEDS_RECONNECT
    assert acc.last_error == "CalDAV/CardDAV login failed"
    assert isinstance(svc.backend(acc, "tasks"), CalDavBackend)


def test_default_factory_routes_contacts_and_google(repo):
    _imap(repo, "s@example.com", caldav_url=DAV, carddav_url=DAV + "card/")
    repo.upsert(email="g@gmail.com", provider=Provider.GOOGLE, status=AccountStatus.CONNECTED)
    card = PimService(repo, None).backend(repo.get("s@example.com"), "contacts")
    assert isinstance(card, CardDavBackend)
    with pytest.raises(PimError, match="Google is not configured"):
        PimService(repo, None).backend(repo.get("g@gmail.com"), "calendar")
    oauth = object()
    api = PimService(repo, oauth).backend(repo.get("g@gmail.com"), "calendar")
    assert isinstance(api, GoogleApi) and api._oauth is oauth
    assert api.tz.key == "UTC"


def test_backends_get_the_configured_time_zone(repo):
    _imap(repo, "s@example.com", caldav_url=DAV)
    repo.upsert(email="g@gmail.com", provider=Provider.GOOGLE, status=AccountStatus.CONNECTED)
    svc = PimService(repo, object(), tz=TZ)
    assert svc.backend(repo.get("s@example.com"), "calendar").tz is TZ
    assert svc.backend(repo.get("g@gmail.com"), "calendar").tz is TZ


@respx.mock
async def test_carddav_401_trips_breaker_once_and_never_retries(repo):
    _imap(repo, "s@example.com", carddav_url=DAV)
    route = respx.route(url__startswith="https://dav.example.com/").mock(
        return_value=httpx.Response(401)
    )
    svc = PimService(repo, None)
    contacts, errors = await svc.search_contacts("jan", None, 10)
    assert contacts == []
    assert [(e.account, e.error) for e in errors] == [("s@example.com", "CardDAV login failed")]
    acc = repo.get("s@example.com")
    assert acc.status == AccountStatus.NEEDS_RECONNECT
    assert acc.last_error == "CalDAV/CardDAV login failed"
    assert route.call_count == 1
    with pytest.raises(PimError, match="needs_reconnect"):
        await svc.search_contacts("jan", "s@example.com", 10)
    _, errors = await svc.search_contacts("jan", None, 10)
    assert errors[0].error == "account unavailable: needs_reconnect"
    assert route.call_count == 1


async def test_unexpected_errors_are_reported_without_their_text(repo):
    _imap(repo, "s@example.com", caldav_url=DAV)

    class Leaky(FakeBackend):
        def list_calendars(self):
            raise RuntimeError("password=hunter2-secret")

    svc = PimService(repo, None, backend_factory=lambda a, c: Leaky(a.email))
    cals, errors = await svc.list_calendars(None)
    assert cals == [] and errors[0].error == "unexpected error: RuntimeError"
    assert "hunter2" not in str([e.to_dict() for e in errors])


async def test_timeout_becomes_pim_error(repo):
    _imap(repo, "s@example.com", caldav_url=DAV)

    class Slow(FakeBackend):
        def list_calendars(self):
            time.sleep(0.3)
            return []

        def create_event(self, calendar_id, data):
            time.sleep(0.3)

    svc = PimService(repo, None, backend_factory=lambda a, c: Slow(a.email), timeout=0.05)
    with pytest.raises(PimError, match="did not respond in time"):
        await svc.create_event("s@example.com", None, EventInput())
    _, errors = await svc.list_calendars(None)
    assert "did not respond in time" in errors[0].error


async def test_write_timeout_says_the_change_may_have_been_applied(repo):
    _imap(repo, "s@example.com", caldav_url=DAV)

    class Slow(FakeBackend):
        def list_calendars(self):
            time.sleep(0.3)
            return []

        def delete_event(self, calendar_id, event_id):
            time.sleep(0.3)

    svc = PimService(repo, None, backend_factory=lambda a, c: Slow(a.email), timeout=0.05)
    with pytest.raises(PimError, match="may or may not have been applied; list/get before"):
        await svc.delete_event("s@example.com", "c", "e")
    _, errors = await svc.list_calendars(None)
    assert "applied" not in errors[0].error and "try again later" in errors[0].error


async def test_events_are_merged_by_start_and_backends_closed(repo):
    _imap(repo, "a@example.com", caldav_url=DAV)
    _imap(repo, "b@example.com", caldav_url=DAV)
    closed = []

    class Dated(FakeBackend):
        def list_events(self, calendar_id, start, end, query):
            items = {
                "a@example.com": [("a-late", "2026-10-02T10:00:00+02:00", False)],
                "b@example.com": [
                    ("b-allday", "2026-10-02", True),
                    ("b-early", "2026-10-01T23:30:00+00:00", False),
                ],
            }[self.email]
            return [
                EventInfo(self.email, "c", i, i, s, None, ad, None, None, False, False)
                for i, s, ad in items
            ]

        def close(self):
            closed.append(self.email)

    svc = PimService(repo, None, backend_factory=lambda a, c: Dated(a.email), tz=TZ)
    start = datetime(2026, 10, 1, tzinfo=TZ)
    events, errors = await svc.list_events(None, None, start, start + timedelta(days=3), None)
    # 23:30 UTC on 1 Oct is 01:30 on 2 Oct in Berlin: after the all-day event's midnight.
    assert [e.id for e in events] == ["b-allday", "b-early", "a-late"] and errors == []
    assert sorted(closed) == ["a@example.com", "b@example.com"]

    # In UTC (the default zone) the all-day event starts at 00:00 UTC on 2 Oct: after it.
    closed.clear()
    svc = PimService(repo, None, backend_factory=lambda a, c: Dated(a.email))
    events, _ = await svc.list_events(None, None, start, start + timedelta(days=3), None)
    assert [e.id for e in events] == ["b-early", "b-allday", "a-late"]


async def test_search_contacts_caps_merged_results(repo):
    _imap(repo, "a@example.com", carddav_url=DAV)
    _imap(repo, "b@example.com", carddav_url=DAV)

    class Contacts(FakeBackend):
        def search_contacts(self, query, limit):
            return [ContactInfo(self.email, f"{query}{i}", [], [], None) for i in range(limit)]

    svc = PimService(repo, None, backend_factory=lambda a, c: Contacts(a.email))
    contacts, errors = await svc.search_contacts("jan", None, 3)
    assert len(contacts) == 3 and errors == []


async def test_missing_task_and_contact_capability(repo):
    _imap(repo, "f@example.org")
    factory = CountingFactory()
    svc = PimService(repo, None, backend_factory=factory)
    with pytest.raises(PimError, match="has no tasks"):
        await svc.list_tasks("f@example.org", None, False)
    with pytest.raises(PimError, match="has no contacts"):
        await svc.search_contacts("x", "f@example.org", 5)
    assert factory.calls == []
