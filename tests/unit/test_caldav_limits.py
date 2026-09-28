"""CalDAV listings are bounded: recurrences are expanded lazily and at most MAX_ITEMS kept.

caldav's own `expand=True` materialises every instance of every series in the range on
the client, so one `FREQ=MINUTELY` event (about 527k instances a year) would exhaust the
container's memory. The backend now asks for unexpanded objects and expands each series
itself, stopping as soon as an instance can no longer make the first MAX_ITEMS.
"""

import time
from datetime import datetime, timedelta

import icalendar

from postroom.dav import caldav_backend
from postroom.dav.caldav_backend import MAX_ITEMS, CalDavBackend
from postroom.pim.models import TZ

HEAD = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\n"
TAIL = "END:VCALENDAR\r\n"
BASE = "https://dav.example.com/SOGo/dav/me/Calendar/personal/"


def _event(uid, start, rule=None, summary="E", minutes=15):
    lines = [
        "BEGIN:VEVENT",
        f"UID:{uid}",
        "DTSTAMP:20260101T000000Z",
        f"DTSTART:{start}",
        f"DURATION:PT{minutes}M",
        f"SUMMARY:{summary}",
    ]
    if rule:
        lines.append(f"RRULE:{rule}")
    return "\r\n".join([*lines, "END:VEVENT"]) + "\r\n"


class FakeObj:
    def __init__(self, body: str, name: str):
        self.data = HEAD + body + TAIL
        self.url = f"{BASE}{name}.ics"

    def get_icalendar_instance(self):
        return icalendar.Calendar.from_ical(self.data)

    def get_icalendar_component(self):
        cal = self.get_icalendar_instance()
        return next(c for c in cal.subcomponents if c.name != "VTIMEZONE")


class FakeCal:
    url = BASE

    def __init__(self, objs):
        self.objs = objs
        self.searches = []

    def get_display_name(self):
        return "Personal"

    def search(self, **kw):
        self.searches.append(kw)
        return list(self.objs)

    def get_todos(self, include_completed=False):
        return list(self.objs)


def _backend(cal) -> CalDavBackend:
    backend = CalDavBackend("me@example.com", "https://dav.example.com/SOGo/dav/me/", "me", "pw")
    backend._collections = lambda component: [cal]
    return backend


START = datetime(2026, 1, 1, tzinfo=TZ)


def test_minutely_series_is_expanded_lazily_and_capped():
    cal = FakeCal([FakeObj(_event("m", "20260101T080000Z", "FREQ=MINUTELY"), "m")])
    t = time.monotonic()
    events = _backend(cal).list_events(None, START, START + timedelta(days=366), None)
    assert time.monotonic() - t < 10
    assert len(events) == MAX_ITEMS
    assert events[0].start == "2026-01-01T09:00:00+01:00"
    assert all(e.recurring for e in events)
    assert all(s.get("expand") is False for s in cal.searches)  # never caldav's expansion


def test_first_items_by_start_are_kept_across_series():
    objs = [
        FakeObj(_event("hourly", "20260101T000000Z", "FREQ=HOURLY", "H"), "hourly"),
        FakeObj(_event("early", "20251231T233000Z", summary="Early"), "early"),
        FakeObj(_event("daily", "20260101T001000Z", "FREQ=DAILY", "D"), "daily"),
    ]
    events = _backend(FakeCal(objs)).list_events(None, START, START + timedelta(days=366), None)
    assert len(events) == MAX_ITEMS
    starts = [e.start for e in events]
    assert starts == sorted(starts, key=lambda s: datetime.fromisoformat(s))
    assert events[0].title == "Early" and not events[0].recurring
    # 500 items span about 20 days: hourly (24/day) + daily (1/day) instances.
    assert sum(e.title == "D" for e in events) in (19, 20, 21)


def test_instances_outside_the_range_are_dropped():
    objs = [FakeObj(_event("w", "20260105T090000Z", "FREQ=WEEKLY;COUNT=10", "W"), "w")]
    begin = datetime(2026, 1, 10, tzinfo=TZ)
    events = _backend(FakeCal(objs)).list_events(None, begin, begin + timedelta(days=14), None)
    assert [e.start for e in events] == [
        "2026-01-12T10:00:00+01:00",
        "2026-01-19T10:00:00+01:00",
    ]


def test_query_still_filters_expanded_instances():
    objs = [
        FakeObj(_event("a", "20260101T080000Z", "FREQ=DAILY", "Standup"), "a"),
        FakeObj(_event("b", "20260102T080000Z", summary="Dentist"), "b"),
    ]
    events = _backend(FakeCal(objs)).list_events(None, START, START + timedelta(days=7), "dentist")
    assert [e.title for e in events] == ["Dentist"]


def test_task_listing_is_capped(monkeypatch):
    monkeypatch.setattr(caldav_backend, "MAX_ITEMS", 5)
    todos = [
        FakeObj(
            f"BEGIN:VTODO\r\nUID:t{i}\r\nDTSTAMP:20260101T000000Z\r\nSUMMARY:T{i:02}\r\n"
            "END:VTODO\r\n",
            f"t{i}",
        )
        for i in range(12)
    ]
    tasks = _backend(FakeCal(todos)).list_tasks(None, True)
    assert [t.title for t in tasks] == ["T00", "T01", "T02", "T03", "T04"]
