"""One malformed calendar object must not break an account's whole event/task list.

Radicale refuses such objects on upload, but SOGo stores what clients send, so these
tests feed the backend fake caldav objects directly.
"""

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import icalendar

from postroom.dav.caldav_backend import CalDavBackend

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")

HEAD = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//t//t//EN\r\n"
TAIL = "END:VCALENDAR\r\n"

GOOD_EVENT = (
    "BEGIN:VEVENT\r\nUID:good\r\nDTSTAMP:20260901T000000Z\r\nDTSTART:20261002T110000Z\r\n"
    "DTEND:20261002T120000Z\r\nSUMMARY:Good\r\nEND:VEVENT\r\n"
)
BROKEN_DTEND = (
    "BEGIN:VEVENT\r\nUID:broken-dtend\r\nDTSTAMP:20260901T000000Z\r\n"
    "DTSTART:20261002T090000Z\r\nDTEND:garbage\r\nSUMMARY:Secret title\r\nEND:VEVENT\r\n"
)
PERIOD_START = (
    "BEGIN:VEVENT\r\nUID:period\r\nDTSTAMP:20260901T000000Z\r\n"
    "DTSTART;VALUE=PERIOD:20261002T090000Z/20261002T100000Z\r\nSUMMARY:Secret title\r\n"
    "END:VEVENT\r\n"
)
GOOD_TODO = (
    "BEGIN:VTODO\r\nUID:good-todo\r\nDTSTAMP:20260901T000000Z\r\nSUMMARY:Pay\r\nEND:VTODO\r\n"
)
BROKEN_TODO = (
    "BEGIN:VTODO\r\nUID:broken-todo\r\nDTSTAMP:20260901T000000Z\r\nDUE:garbage\r\n"
    "SUMMARY:Secret title\r\nEND:VTODO\r\n"
)
BASE = "https://dav.example.com/SOGo/dav/me/Calendar/personal/"


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

    def get_display_name(self):
        return "Personal"

    def search(self, **kw):
        return list(self.objs)

    def get_todos(self, include_completed=False):
        return list(self.objs)


def _backend(objs) -> CalDavBackend:
    backend = CalDavBackend(
        "me@example.com", "https://dav.example.com/SOGo/dav/me/", "me", "pw", tz=TZ
    )
    cal = FakeCal(objs)
    backend._collections = lambda component: [cal]
    return backend


def test_broken_events_are_skipped_and_logged_without_content(caplog):
    objs = [
        FakeObj(BROKEN_DTEND, "broken-dtend"),
        FakeObj(GOOD_EVENT, "good"),
        FakeObj(PERIOD_START, "period"),
    ]
    start = datetime(2026, 10, 1, tzinfo=TZ)
    with caplog.at_level(logging.WARNING):
        events = _backend(objs).list_events(None, start, start + timedelta(days=3), None)
    assert [e.id for e in events] == ["good"]
    assert "Secret title" not in caplog.text and "garbage" not in caplog.text
    assert "broken-dtend.ics" in caplog.text and "period.ics" in caplog.text


def test_broken_tasks_are_skipped():
    objs = [FakeObj(BROKEN_TODO, "broken-todo"), FakeObj(GOOD_TODO, "good-todo")]
    tasks = _backend(objs).list_tasks(None, True)
    assert [t.id for t in tasks] == ["good-todo"]
