import re
from datetime import UTC, date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import caldav
import httpx
import pytest
from caldav.calendarobjectresource import CalendarObjectResource

from postroom.dav.caldav_backend import CalDavBackend
from postroom.dav.carddav import CardDavBackend
from postroom.pim.models import EventInput, PimError, TaskInput
from tests.integration.conftest import DAV_PASS, DAV_USER

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")

pytestmark = pytest.mark.integration


@pytest.fixture
def cal(radicale):
    return CalDavBackend("alice@example.com", radicale, DAV_USER, DAV_PASS, tz=TZ)


def test_calendars(cal):
    cals = cal.list_calendars()
    assert [c.name for c in cals] == ["Personal"] and cals[0].primary
    assert [t.name for t in cal.list_task_lists()] == ["Personal"]


def test_event_lifecycle(cal):
    start = datetime(2026, 10, 1, 9, 0, tzinfo=TZ)
    ev = cal.create_event(
        None,
        EventInput(title="Dentist", start=start, end=start + timedelta(hours=1), location="Brno"),
    )
    assert ev.title == "Dentist" and not ev.has_attendees
    found = cal.list_events(None, start - timedelta(days=1), start + timedelta(days=1), "dent")
    assert [e.id for e in found] == [ev.id]
    upd = cal.update_event(ev.calendar_id, ev.id, EventInput(title="Dentist (moved)"))
    assert upd.title == "Dentist (moved)" and upd.location == "Brno"
    cal.delete_event(ev.calendar_id, ev.id)
    assert cal.list_events(None, start - timedelta(days=1), start + timedelta(days=1), None) == []


def test_all_day_event(cal):
    ev = cal.create_event(
        None, EventInput(title="Holiday", start=date(2026, 10, 5), end=date(2026, 10, 6))
    )
    assert ev.all_day and ev.start == "2026-10-05"
    cal.delete_event(ev.calendar_id, ev.id)


def test_event_with_attendees_is_read_only(cal):
    c = cal.list_calendars()[0]
    import caldav

    raw = caldav.DAVClient(url=c.id, username=DAV_USER, password=DAV_PASS).calendar(url=c.id)
    raw.save_event(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\n"
        "UID:meet-1\r\nDTSTAMP:20260901T000000Z\r\nDTSTART:20261002T090000Z\r\n"
        "DTEND:20261002T100000Z\r\nSUMMARY:Meeting\r\n"
        "ORGANIZER:mailto:alice@example.com\r\nATTENDEE:mailto:bob@example.com\r\n"
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    with pytest.raises(PimError, match="read-only"):
        cal.update_event(c.id, "meet-1", EventInput(title="x"))
    with pytest.raises(PimError, match="read-only"):
        cal.delete_event(c.id, "meet-1")


def test_task_lifecycle(cal):
    t = cal.create_task(
        None, TaskInput(title="Pay invoice", due=date(2026, 10, 10), notes="FA-123")
    )
    assert not t.completed and t.due == "2026-10-10"
    assert t.id in [x.id for x in cal.list_tasks(None, include_completed=False)]
    done = cal.update_task(t.list_id, t.id, TaskInput(completed=True))
    assert done.completed and done.completed_at
    assert t.id not in [x.id for x in cal.list_tasks(None, include_completed=False)]
    assert t.id in [x.id for x in cal.list_tasks(None, include_completed=True)]
    cal.delete_task(t.list_id, t.id)


def test_wrong_password_calls_breaker(radicale):
    hits = []
    bad = CalDavBackend(
        "alice@example.com", radicale, DAV_USER, "wrong", on_auth_failure=lambda: hits.append(1)
    )
    with pytest.raises(PimError, match="login failed"):
        bad.list_calendars()
    assert hits == [1]


def test_forbidden_is_not_a_login_failure(radicale):
    # Radicale's owner_only rights answer 403 for another user's collections.
    hits = []
    other = CalDavBackend(
        "alice@example.com",
        radicale.replace(f"/{DAV_USER}/", "/bob/"),
        DAV_USER,
        DAV_PASS,
        on_auth_failure=lambda: hits.append(1),
    )
    with pytest.raises(PimError, match="access denied"):
        other.list_calendars()
    assert hits == []


def test_move_keeps_duration_and_foreign_calendar_id_is_refused(cal):
    start = datetime(2026, 11, 1, 9, 0, tzinfo=TZ)
    ev = cal.create_event(
        None, EventInput(title="Call", start=start, end=start + timedelta(hours=1))
    )
    moved = cal.update_event(ev.calendar_id, ev.id, EventInput(start=start + timedelta(hours=2)))
    assert moved.start == "2026-11-01T11:00:00+01:00" and moved.end == "2026-11-01T12:00:00+01:00"
    with pytest.raises(PimError, match="not found"):
        cal.update_event("http://evil.example/cal/", ev.id, EventInput(title="x"))
    cal.delete_event(ev.calendar_id, ev.id)


def test_carddav_search(radicale):
    cd = CardDavBackend("alice@example.com", radicale, DAV_USER, DAV_PASS)
    res = cd.search_contacts("novák")
    assert [c.name for c in res] == ["Jan Novák"] and res[0].emails == ["jan@example.com"]
    assert cd.search_contacts("nobody-matches") == []


# -- fix round ---------------------------------------------------------------------------


def _stored(c_id: str, uid: str) -> str:
    raw = caldav.DAVClient(url=c_id, username=DAV_USER, password=DAV_PASS).calendar(url=c_id)
    return raw.get_object_by_uid(uid).data


def test_dot_ids_cannot_escape_the_collection(cal, radicale):
    c = cal.list_calendars()[0]
    for bad in (c.id + "../", c.id.rstrip("/") + "/..", "..", ".", radicale):
        with pytest.raises(PimError, match="not found"):
            cal.delete_event(bad, "x")
        with pytest.raises(PimError, match="not found"):
            cal.delete_task(bad, "x")
    for bad in ("..", ".", "../personal", "/"):
        with pytest.raises(PimError, match="not found"):
            cal.delete_event(c.id, bad)
        with pytest.raises(PimError, match="not found"):
            cal.delete_task(c.id, bad)
    assert [x.name for x in cal.list_calendars()] == ["Personal"]
    # CardDAV takes no caller-supplied ids or paths; a dotted query is only a text filter.
    assert (
        CardDavBackend("alice@example.com", radicale, DAV_USER, DAV_PASS).search_contacts("..")
        == []
    )


def test_offset_datetimes_are_stored_in_the_configured_zone_with_vtimezone(cal):
    plus2 = timezone(timedelta(hours=2))
    start = datetime(2026, 10, 7, 10, 0, tzinfo=plus2)
    ev = cal.create_event(
        None, EventInput(title="Offset", start=start, end=start + timedelta(hours=1))
    )
    assert ev.start == "2026-10-07T10:00:00+02:00"
    raw = _stored(ev.calendar_id, ev.id)
    assert "UTC+02:00" not in raw
    assert re.search(r'DTSTART;TZID="?Europe/Berlin"?:20261007T100000', raw)
    assert "BEGIN:VTIMEZONE" in raw and "TZID:Europe/Berlin" in raw

    cal.update_event(ev.calendar_id, ev.id, EventInput(start=datetime(2026, 10, 8, 8, tzinfo=UTC)))
    raw = _stored(ev.calendar_id, ev.id)
    assert re.search(r'DTSTART;TZID="?Europe/Berlin"?:20261008T100000', raw)
    assert re.search(r'DTEND;TZID="?Europe/Berlin"?:20261008T110000', raw)
    assert "BEGIN:VTIMEZONE" in raw and "UTC" not in raw.split("BEGIN:VEVENT")[1]
    cal.delete_event(ev.calendar_id, ev.id)


def test_default_zone_is_utc(radicale):
    utc = CalDavBackend("alice@example.com", radicale, DAV_USER, DAV_PASS)
    ev = utc.create_event(
        None,
        EventInput(
            title="Naive",
            start=datetime(2026, 10, 7, 10, 0, tzinfo=TZ),
            end=datetime(2026, 10, 7, 11, 0, tzinfo=TZ),
        ),
    )
    assert ev.start == "2026-10-07T08:00:00+00:00"
    raw = _stored(ev.calendar_id, ev.id)
    assert "DTSTART:20261007T080000Z" in raw and "Europe/" not in raw
    utc.delete_event(ev.calendar_id, ev.id)


def test_update_adds_vtimezone_to_an_event_that_had_none(cal):
    c = cal.list_calendars()[0]
    raw_cal = caldav.DAVClient(url=c.id, username=DAV_USER, password=DAV_PASS).calendar(url=c.id)
    raw_cal.add_event(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\n"
        "UID:utc-1\r\nDTSTAMP:20260901T000000Z\r\nDTSTART:20261009T090000Z\r\n"
        "DTEND:20261009T100000Z\r\nSUMMARY:UTC event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    plus2 = timezone(timedelta(hours=2))
    cal.update_event(c.id, "utc-1", EventInput(start=datetime(2026, 10, 9, 14, tzinfo=plus2)))
    raw = _stored(c.id, "utc-1")
    assert re.search(r'DTSTART;TZID="?Europe/Berlin"?:20261009T140000', raw)
    assert "BEGIN:VTIMEZONE" in raw and "TZID:Europe/Berlin" in raw
    cal.delete_event(c.id, "utc-1")


def _change_after_fetch(monkeypatch) -> None:
    """Make the server copy change right after the backend has fetched it (a race)."""
    orig = CalendarObjectResource.load
    counter = iter(range(1000))

    def load_then_change(self, *args, **kwargs):
        out = orig(self, *args, **kwargs)
        changed = re.sub(
            r"SUMMARY:[^\r\n]*", f"SUMMARY:Changed elsewhere {next(counter)}", self.data
        )
        httpx.put(
            str(self.client.url.join(self.url)),
            content=changed,
            auth=(DAV_USER, DAV_PASS),
            headers={"Content-Type": "text/calendar"},
        ).raise_for_status()
        return out

    monkeypatch.setattr(CalendarObjectResource, "load", load_then_change)


def test_writes_are_refused_when_the_item_changed_on_the_server(cal, monkeypatch):
    start = datetime(2026, 10, 12, 9, 0, tzinfo=TZ)
    ev = cal.create_event(
        None, EventInput(title="Race", start=start, end=start + timedelta(hours=1))
    )
    task = cal.create_task(None, TaskInput(title="Race"))
    _change_after_fetch(monkeypatch)
    for write in (
        lambda: cal.delete_event(ev.calendar_id, ev.id),
        lambda: cal.update_event(ev.calendar_id, ev.id, EventInput(title="Mine")),
        lambda: cal.delete_task(task.list_id, task.id),
        lambda: cal.update_task(task.list_id, task.id, TaskInput(title="Mine")),
    ):
        with pytest.raises(PimError, match="item changed on the server; fetch it again"):
            write()
    monkeypatch.undo()
    assert "SUMMARY:Changed elsewhere" in _stored(ev.calendar_id, ev.id)
    assert "SUMMARY:Changed elsewhere" in _stored(task.list_id, task.id)
    cal.delete_event(ev.calendar_id, ev.id)
    cal.delete_task(task.list_id, task.id)


def test_recurring_series_is_expanded_and_capped(cal, monkeypatch):
    from postroom.dav import caldav_backend

    c = cal.list_calendars()[0]
    raw = caldav.DAVClient(url=c.id, username=DAV_USER, password=DAV_PASS).calendar(url=c.id)
    raw.save_event(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\n"
        "UID:water-1\r\nDTSTAMP:20260901T000000Z\r\nDTSTART:20261110T080000Z\r\n"
        "DTEND:20261110T081500Z\r\nRRULE:FREQ=HOURLY\r\nSUMMARY:Drink water\r\n"
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    raw.save_event(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\nBEGIN:VEVENT\r\n"
        "UID:once-1\r\nDTSTAMP:20260901T000000Z\r\nDTSTART:20261110T083000Z\r\n"
        "DTEND:20261110T090000Z\r\nSUMMARY:Once\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    monkeypatch.setattr(caldav_backend, "MAX_ITEMS", 5)
    try:
        start = datetime(2026, 11, 1, tzinfo=TZ)
        events = cal.list_events(None, start, start + timedelta(days=14), None)
        assert [(e.title, e.start, e.recurring) for e in events] == [
            ("Drink water", "2026-11-10T09:00:00+01:00", True),
            ("Once", "2026-11-10T09:30:00+01:00", False),
            ("Drink water", "2026-11-10T10:00:00+01:00", True),
            ("Drink water", "2026-11-10T11:00:00+01:00", True),
            ("Drink water", "2026-11-10T12:00:00+01:00", True),
        ]
        with pytest.raises(PimError, match="read-only"):
            cal.delete_event(c.id, "water-1")
    finally:
        raw.event_by_uid("water-1").delete()
        raw.event_by_uid("once-1").delete()
