"""Google event writes go only to the account's own calendars (exfiltration guard).

Google authorises writes by the calendar's ACL, so any calendar a third party shared with
the account (writer, or even owner role) would otherwise be writable by id. Writes are
allowed to the primary calendar and to secondary calendars whose `dataOwner` is the
account itself, as listed in the account's own calendarList.
"""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx

from postroom.google.api import CAL, GoogleApi
from postroom.pim.models import EventInput, PimError

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")

ME = "me@gmail.com"
OWN = "own123@group.calendar.google.com"
CALENDARS = [
    {"id": ME, "summary": "Me", "accessRole": "owner", "primary": True},
    {"id": OWN, "summary": "Family", "accessRole": "owner", "dataOwner": ME},
    {"id": "attacker@gmail.com", "summary": "Shared", "accessRole": "writer"},
    {
        "id": "theirs@group.calendar.google.com",
        "summary": "Team",
        "accessRole": "owner",
        "dataOwner": "boss@example.com",
    },
    {"id": "cz#holiday@group.v.calendar.google.com", "summary": "Svátky", "accessRole": "reader"},
]
EVENT = {
    "id": "e1",
    "etag": '"v1"',
    "summary": "Lunch",
    "start": {"dateTime": "2026-10-01T12:00:00+02:00"},
    "end": {"dateTime": "2026-10-01T13:00:00+02:00"},
}
FOREIGN = [
    "attacker@gmail.com",  # writer: shared by a third party
    "theirs@group.calendar.google.com",  # owner role, but owned by someone else
    "cz#holiday@group.v.calendar.google.com",  # reader
    "unlisted@gmail.com",  # not in the account's calendarList at all
]


class FakeOAuth:
    def access_token(self, email):
        return "tok"

    def invalidate(self, email):
        pass


def _api():
    return GoogleApi(ME, FakeOAuth(), http=httpx.Client(), tz=TZ)


def _data():
    start = datetime(2026, 10, 1, 12, tzinfo=TZ)
    return EventInput(title="x", start=start, end=start + timedelta(hours=1))


@respx.mock
@pytest.mark.parametrize("cal_id", FOREIGN)
def test_writes_to_calendars_the_account_does_not_own_are_refused(cal_id):
    respx.get(f"{CAL}/users/me/calendarList").respond(json={"items": CALENDARS})
    event_routes = respx.route(url__startswith=f"{CAL}/calendars/").respond(json=EVENT)
    api = _api()
    for call in (
        lambda: api.create_event(cal_id, _data()),
        lambda: api.update_event(cal_id, "e1", EventInput(title="y")),
        lambda: api.delete_event(cal_id, "e1"),
    ):
        with pytest.raises(PimError, match="not one of this account's own calendars"):
            call()
    assert not event_routes.called  # refused before the event is even read


@respx.mock
@pytest.mark.parametrize("cal_id", [ME, OWN])
def test_writes_to_own_calendars_are_allowed(cal_id):
    respx.get(f"{CAL}/users/me/calendarList").respond(json={"items": CALENDARS})
    post = respx.post(url__startswith=f"{CAL}/calendars/").respond(json=EVENT)
    respx.get(url__startswith=f"{CAL}/calendars/").respond(json=EVENT)
    patch = respx.patch(url__startswith=f"{CAL}/calendars/").respond(json=EVENT)
    delete = respx.delete(url__startswith=f"{CAL}/calendars/").respond(204)
    api = _api()
    api.create_event(cal_id, _data())
    api.update_event(cal_id, "e1", EventInput(title="y"))
    api.delete_event(cal_id, "e1")
    assert post.call_count == patch.call_count == delete.call_count == 1


@respx.mock
def test_primary_alias_needs_no_calendar_list():
    cal_list = respx.get(f"{CAL}/users/me/calendarList").respond(json={"items": CALENDARS})
    post = respx.post(f"{CAL}/calendars/primary/events").respond(json=EVENT)
    api = _api()
    api.create_event(None, _data())
    api.create_event("primary", _data())
    assert post.call_count == 2 and not cal_list.called


@respx.mock
def test_list_calendars_marks_foreign_calendars_read_only():
    respx.get(f"{CAL}/users/me/calendarList").respond(json={"items": CALENDARS})
    cals = {c.id: c.read_only for c in _api().list_calendars()}
    assert cals == {
        ME: False,
        OWN: False,
        "attacker@gmail.com": True,
        "theirs@group.calendar.google.com": True,
        "cz#holiday@group.v.calendar.google.com": True,
    }
