import json
from datetime import date, datetime, timedelta
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx

from postroom.google.api import CAL, TASKS, GoogleApi
from postroom.mail.imap import AuthFailed
from postroom.pim.models import EventInput, PimError, TaskInput

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")

EVENT = {
    "id": "e1",
    "summary": "Lunch",
    "start": {"dateTime": "2026-10-01T12:00:00+02:00"},
    "end": {"dateTime": "2026-10-01T13:00:00+02:00"},
}


class FakeOAuth:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = 0
        self.invalidated = 0

    def access_token(self, email):
        self.calls += 1
        if self.fail:
            raise AuthFailed("revoked")
        return "tok"

    def invalidate(self, email):
        self.invalidated += 1


def _api(oauth=None):
    return GoogleApi("me@gmail.com", oauth or FakeOAuth(), http=httpx.Client(), tz=TZ)


def _query(req) -> dict:
    return parse_qs(urlparse(str(req.url)).query)


@respx.mock
def test_recurring_event_cannot_be_deleted_or_updated():
    respx.get(f"{CAL}/calendars/primary/events/r1").respond(
        json={**EVENT, "id": "r1", "recurringEventId": "base"}
    )
    writes = respx.route(method__in=["PATCH", "DELETE", "PUT", "POST"])
    api = _api()
    with pytest.raises(PimError, match="read-only"):
        api.delete_event("primary", "r1")
    with pytest.raises(PimError, match="read-only"):
        api.update_event("primary", "r1", EventInput(title="x"))
    assert not writes.called


@respx.mock
def test_update_and_delete_never_notify_and_move_keeps_duration():
    respx.get(f"{CAL}/users/me/calendarList").respond(
        json={"items": [{"id": "me@gmail.com", "accessRole": "owner", "primary": True}]}
    )
    respx.get(f"{CAL}/calendars/me%40gmail.com/events/e1").respond(json=EVENT)
    patch = respx.patch(f"{CAL}/calendars/me%40gmail.com/events/e1").respond(json=EVENT)
    delete = respx.delete(f"{CAL}/calendars/me%40gmail.com/events/e1").respond(204)
    api = _api()
    new_start = datetime(2026, 10, 1, 15, tzinfo=TZ)
    api.update_event("me@gmail.com", "e1", EventInput(start=new_start))
    req = patch.calls[0].request
    assert _query(req)["sendUpdates"] == ["none"]
    body = json.loads(req.read())
    assert "attendees" not in body and "conferenceData" not in body
    assert body["start"]["dateTime"] == new_start.isoformat()
    assert body["end"]["dateTime"] == (new_start + timedelta(hours=1)).isoformat()
    api.delete_event("me@gmail.com", "e1")
    assert _query(delete.calls[0].request)["sendUpdates"] == ["none"]


@respx.mock
def test_needs_reconnect_is_sticky_and_contacts_nothing():
    anything = respx.route()
    oauth = FakeOAuth(fail=True)
    api = _api(oauth)
    for _ in range(2):
        with pytest.raises(PimError, match="needs reconnect"):
            api.list_calendars()
    assert oauth.calls == 1 and not anything.called


@respx.mock
def test_persistent_401_retries_only_once_and_reports_google_message():
    route = respx.get(f"{CAL}/users/me/calendarList").respond(
        401, json={"error": {"code": 401, "message": "Invalid Credentials"}}
    )
    api = _api()
    with pytest.raises(PimError, match="Google API error 401: Invalid Credentials"):
        api.list_calendars()
    assert route.call_count == 2 and api._oauth.invalidated == 1
    assert "tok" not in str(route.calls[0].request.url)


@respx.mock
def test_list_events_reads_visible_calendars_merged_by_start():
    respx.get(f"{CAL}/users/me/calendarList").respond(
        json={
            "items": [
                {"id": "me@gmail.com", "accessRole": "owner", "primary": True},
                {"id": "work", "accessRole": "writer", "selected": True},
                {"id": "hidden", "accessRole": "reader"},
                {"id": "busy", "accessRole": "freeBusyReader", "selected": True},
            ]
        }
    )
    mine = respx.get(f"{CAL}/calendars/me%40gmail.com/events").respond(json={"items": [EVENT]})
    work = respx.get(f"{CAL}/calendars/work/events").respond(
        json={"items": [{"id": "w1", "summary": "Early", "start": {"date": "2026-10-01"}}]}
    )
    others = respx.get(url__regex=r".*/calendars/(hidden|busy)/events.*")
    start = datetime(2026, 10, 1, tzinfo=TZ)
    events = _api().list_events(None, start, start + timedelta(days=1), "lu")
    assert [(e.id, e.calendar_id, e.all_day) for e in events] == [
        ("w1", "work", True),
        ("e1", "me@gmail.com", False),
    ]
    q = _query(mine.calls[0].request)
    assert q["singleEvents"] == ["true"] and q["orderBy"] == ["startTime"] and q["q"] == ["lu"]
    # Event times come back in the server's configured zone.
    assert q["timeZone"] == ["Europe/Berlin"] and q["timeMin"] == [start.isoformat()]
    assert work.called and not others.called


@respx.mock
def test_reopen_task_clears_completion():
    route = respx.patch(f"{TASKS}/lists/L1/tasks/T1").respond(
        json={"id": "T1", "title": "Pay", "status": "needsAction"}
    )
    t = _api().update_task("L1", "T1", TaskInput(completed=False))
    assert json.loads(route.calls[0].request.read()) == {"status": "needsAction", "completed": None}
    assert not t.completed and t.completed_at is None


# -- fix round: id validation, If-Match, all-day <-> timed ---------------------------

BAD_IDS = ["..", ".", "", "a/b", "a\\b", "a?b", "a%2e", "a\x00b", "a\nb"]


@respx.mock
@pytest.mark.parametrize("bad", BAD_IDS)
def test_bad_ids_are_rejected_before_any_request(bad):
    anything = respx.route().respond(json=EVENT)
    api = _api()
    start = datetime(2026, 10, 1, 9, tzinfo=TZ)
    calls = [
        lambda: api.delete_event("primary", bad),
        lambda: api.update_event("primary", bad, EventInput(title="x")),
        lambda: api.delete_task("L1", bad),
        lambda: api.update_task("L1", bad, TaskInput(title="x")),
    ]
    if bad:  # an empty calendar/list id means the default one
        calls += [
            lambda: api.delete_event(bad, "e1"),
            lambda: api.update_event(bad, "e1", EventInput(title="x")),
            lambda: api.list_events(bad, start, start + timedelta(days=1), None),
            lambda: api.create_event(
                bad, EventInput(title="x", start=start, end=start + timedelta(hours=1))
            ),
            lambda: api.list_tasks(bad, False),
            lambda: api.create_task(bad, TaskInput(title="x")),
            lambda: api.delete_task(bad, "T1"),
        ]
    for call in calls:
        with pytest.raises(PimError, match="invalid"):
            call()
    assert not anything.called


@respx.mock
def test_hash_is_only_allowed_in_calendar_ids():
    anything = respx.route().respond(json=EVENT)
    api = _api()
    for call in (
        lambda: api.delete_event("primary", "a#b"),
        lambda: api.delete_task("L1", "a#b"),
        lambda: api.list_tasks("a#b", False),
    ):
        with pytest.raises(PimError, match="invalid"):
            call()
    assert not anything.called


@respx.mock
def test_final_request_urls_for_normal_ids():
    # A calendar id with "#" (percent-encoded), owned by the account so it is writable.
    own = {
        "id": "cs.czech#holiday@group.v.calendar.google.com",
        "accessRole": "owner",
        "dataOwner": "me@gmail.com",
    }
    respx.get(f"{CAL}/users/me/calendarList").respond(json={"items": [own]})
    gets = respx.get(url__startswith=f"{CAL}/calendars/").respond(json={**EVENT, "etag": '"v1"'})
    deletes = respx.delete(url__startswith=CAL).respond(204)
    task_delete = respx.delete(url__startswith=TASKS).respond(204)
    api = _api()
    api.delete_event("cs.czech#holiday@group.v.calendar.google.com", "abc_123-x")
    want = f"{CAL}/calendars/cs.czech%23holiday@group.v.calendar.google.com/events/abc_123-x"
    assert str(gets.calls[0].request.url) == want
    assert str(deletes.calls[0].request.url) == want + "?sendUpdates=none"
    api.delete_task("MDk2_x-Y", "dGFzaw")
    assert str(task_delete.calls[0].request.url) == f"{TASKS}/lists/MDk2_x-Y/tasks/dGFzaw"


@respx.mock
def test_event_writes_are_conditional_on_the_fetched_etag():
    url = f"{CAL}/calendars/primary/events/e1"
    respx.get(url).respond(json={**EVENT, "etag": '"v1"'})
    patch = respx.patch(url).respond(json=EVENT)
    delete = respx.delete(url).respond(204)
    api = _api()
    api.update_event("primary", "e1", EventInput(title="New"))
    api.delete_event("primary", "e1")
    assert patch.calls[0].request.headers["If-Match"] == '"v1"'
    assert delete.calls[0].request.headers["If-Match"] == '"v1"'


@respx.mock
def test_precondition_failed_is_a_clean_error():
    url = f"{CAL}/calendars/primary/events/e1"
    respx.get(url).respond(json={**EVENT, "etag": '"v1"'})
    respx.patch(url).respond(412, json={"error": {"message": "Precondition Failed"}})
    respx.delete(url).respond(412)
    api = _api()
    with pytest.raises(PimError, match="item changed on the server; fetch it again"):
        api.update_event("primary", "e1", EventInput(title="New"))
    with pytest.raises(PimError, match="item changed on the server; fetch it again"):
        api.delete_event("primary", "e1")


@respx.mock
def test_switching_all_day_and_timed_nulls_the_other_keys():
    url = f"{CAL}/calendars/primary/events/e1"
    all_day = {**EVENT, "start": {"date": "2026-10-05"}, "end": {"date": "2026-10-06"}}
    get = respx.get(url).respond(json=EVENT)
    patch = respx.patch(url).respond(json=EVENT)
    api = _api()
    api.update_event("primary", "e1", EventInput(start=date(2026, 10, 5), end=date(2026, 10, 6)))
    body = json.loads(patch.calls[0].request.read())
    assert body["start"] == {"date": "2026-10-05", "dateTime": None, "timeZone": None}
    assert body["end"] == {"date": "2026-10-06", "dateTime": None, "timeZone": None}

    get.respond(json=all_day)
    start = datetime(2026, 10, 5, 9, tzinfo=TZ)
    api.update_event("primary", "e1", EventInput(start=start, end=start + timedelta(hours=1)))
    body = json.loads(patch.calls[1].request.read())
    assert body["start"] == {
        "date": None,
        "dateTime": start.isoformat(),
        "timeZone": "Europe/Berlin",
    }
    assert body["end"]["date"] is None
