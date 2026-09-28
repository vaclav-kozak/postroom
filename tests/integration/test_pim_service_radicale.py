from datetime import datetime, timedelta

import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.pim.models import TZ, EventInput, PimError, TaskInput
from postroom.pim.service import PimService
from tests.integration.conftest import DAV_PASS, DAV_USER

pytestmark = pytest.mark.integration


def _account(repo, radicale, email, password):
    repo.upsert(
        email=email,
        provider=Provider.IMAP,
        imap_host="127.0.0.1",
        imap_port=1,
        imap_security="ssl",
        imap_username=DAV_USER,
        caldav_url=radicale,
        carddav_url=radicale,
        secret=password,
        status=AccountStatus.CONNECTED,
    )


async def test_service_round_trip(repo, radicale):
    _account(repo, radicale, "alice@example.com", DAV_PASS)
    svc = PimService(repo, None)
    cals, errors = await svc.list_calendars(None)
    assert [c.name for c in cals] == ["Personal"] and errors == []

    start = datetime(2026, 11, 3, 9, 0, tzinfo=TZ)
    ev = await svc.create_event(
        "alice@example.com",
        None,
        EventInput(title="Svc", start=start, end=start + timedelta(hours=1)),
    )
    events, _ = await svc.list_events(
        None, None, start - timedelta(days=1), start + timedelta(days=1), "svc"
    )
    assert [e.id for e in events] == [ev.id]
    await svc.delete_event("alice@example.com", ev.calendar_id, ev.id)

    task = await svc.create_task("alice@example.com", None, TaskInput(title="Svc task"))
    tasks, _ = await svc.list_tasks("alice@example.com", None, False)
    assert task.id in [t.id for t in tasks]
    await svc.delete_task("alice@example.com", task.list_id, task.id)

    contacts, errors = await svc.search_contacts("jan", None, 5)
    assert [c.name for c in contacts] == ["Jan Novák"] and errors == []
    assert repo.get("alice@example.com").status == AccountStatus.CONNECTED


@pytest.mark.parametrize("capability", ["calendar", "contacts"])
async def test_wrong_password_trips_breaker_and_stops_contact(repo, radicale, capability):
    _account(repo, radicale, "mallory@example.com", "wrong-password")
    svc = PimService(repo, None)
    if capability == "calendar":
        items, errors = await svc.list_calendars(None)
    else:
        items, errors = await svc.search_contacts("jan", None, 5)
    assert items == [] and "login failed" in errors[0].error
    assert "wrong-password" not in errors[0].error
    acc = repo.get("mallory@example.com")
    assert acc.status == AccountStatus.NEEDS_RECONNECT
    assert acc.last_error == "CalDAV/CardDAV login failed"

    built = []
    svc.backend_factory = lambda account, cap: built.append(account)
    with pytest.raises(PimError, match="needs_reconnect"):
        await svc.list_calendars("mallory@example.com")
    assert built == []
