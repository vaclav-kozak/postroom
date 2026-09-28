from datetime import date, datetime, timedelta
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx

from postroom.google.api import CAL, PEOPLE, TASKS, GoogleApi
from postroom.pim.models import EventInput, PimError, TaskInput

# Any zone with a UTC offset and DST works; the server default is UTC.
TZ = ZoneInfo("Europe/Berlin")


class FakeOAuth:
    def __init__(self):
        self.invalidated = 0
        self.n = 0

    def access_token(self, email):
        self.n += 1
        return f"tok{self.n}"

    def invalidate(self, email):
        self.invalidated += 1


@pytest.fixture
def api():
    return GoogleApi("me@gmail.com", FakeOAuth(), http=httpx.Client(), tz=TZ)


@respx.mock
def test_list_calendars(api):
    respx.get(f"{CAL}/users/me/calendarList").respond(
        json={
            "items": [
                {"id": "me@gmail.com", "summary": "Me", "accessRole": "owner", "primary": True},
                {"id": "cz#holiday", "summary": "Svátky", "accessRole": "reader"},
            ]
        }
    )
    cals = api.list_calendars()
    assert [(c.id, c.primary, c.read_only) for c in cals] == [
        ("me@gmail.com", True, False),
        ("cz#holiday", False, True),
    ]


@respx.mock
def test_create_event_never_sends_invites(api):
    route = respx.post(f"{CAL}/calendars/primary/events").respond(
        json={
            "id": "e1",
            "summary": "Lunch",
            "start": {"dateTime": "2026-10-01T12:00:00+02:00"},
            "end": {"dateTime": "2026-10-01T13:00:00+02:00"},
        }
    )
    start = datetime(2026, 10, 1, 12, tzinfo=TZ)
    ev = api.create_event(
        None, EventInput(title="Lunch", start=start, end=start + timedelta(hours=1))
    )
    req = route.calls[0].request
    assert parse_qs(urlparse(str(req.url)).query)["sendUpdates"] == ["none"]
    body = req.read().decode()
    assert "attendees" not in body and '"timeZone":"Europe/Berlin"' in body.replace(" ", "")
    assert ev.id == "e1" and not ev.all_day


@respx.mock
def test_update_refuses_event_with_attendees(api):
    respx.get(f"{CAL}/calendars/primary/events/e1").respond(
        json={
            "id": "e1",
            "summary": "Meet",
            "attendees": [{"email": "bob@x.example.com"}],
            "start": {"dateTime": "2026-10-01T12:00:00+02:00"},
            "end": {"dateTime": "2026-10-01T13:00:00+02:00"},
        }
    )
    patch = respx.patch(f"{CAL}/calendars/primary/events/e1")
    with pytest.raises(PimError, match="read-only"):
        api.update_event("primary", "e1", EventInput(title="x"))
    assert not patch.called


@respx.mock
def test_retry_once_on_401(api):
    route = respx.get(f"{CAL}/users/me/calendarList")
    route.side_effect = [httpx.Response(401), httpx.Response(200, json={"items": []})]
    assert api.list_calendars() == []
    assert api._oauth.invalidated == 1


@respx.mock
def test_tasks_complete(api):
    respx.patch(f"{TASKS}/lists/L1/tasks/T1").respond(
        json={
            "id": "T1",
            "title": "Pay",
            "status": "completed",
            "completed": "2026-09-25T10:00:00.000Z",
            "due": "2026-10-10T00:00:00.000Z",
        }
    )
    t = api.update_task("L1", "T1", TaskInput(completed=True))
    assert t.completed and t.due == "2026-10-10"


@respx.mock
def test_create_task_due_format(api):
    route = respx.post(f"{TASKS}/lists/@default/tasks").respond(
        json={"id": "T2", "title": "X", "status": "needsAction"}
    )
    api.create_task(None, TaskInput(title="X", due=date(2026, 10, 10)))
    assert '"due":"2026-10-10T00:00:00.000Z"' in route.calls[0].request.read().decode().replace(
        " ", ""
    )


@respx.mock
def test_search_contacts_merges_and_warms_up(api):
    def query_of(req):
        return parse_qs(urlparse(str(req.url)).query, keep_blank_values=True)["query"][0]

    def contacts(req):
        if query_of(req) == "":
            return httpx.Response(200, json={})
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "person": {
                            "names": [{"displayName": "Jan Novák"}],
                            "emailAddresses": [{"value": "jan@example.com"}],
                        }
                    }
                ]
            },
        )

    def other(req):
        if query_of(req) == "":
            return httpx.Response(200, json={})
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "person": {
                            "names": [{"displayName": "Jan N."}],
                            "emailAddresses": [{"value": "jan@example.com"}],
                        }
                    },
                    {"person": {"emailAddresses": [{"value": "jana@y.example.org"}]}},
                ]
            },
        )

    sc = respx.get(f"{PEOPLE}/people:searchContacts")
    sc.side_effect = contacts
    oc = respx.get(f"{PEOPLE}/otherContacts:search")
    oc.side_effect = other
    res = api.search_contacts("jan", limit=10)
    assert [c.emails[0] for c in res] == ["jan@example.com", "jana@y.example.org"]
    assert sc.call_count == 2 and oc.call_count == 2  # warm-up + real
