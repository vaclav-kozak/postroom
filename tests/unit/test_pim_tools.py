from datetime import date, datetime

import pytest
from fastmcp import Client, FastMCP

from postroom.mail.models import AccountError
from postroom.pim.models import TZ, CalendarInfo, EventInfo, PimError, TaskInfo
from postroom.tools.pim_tools import register_pim_tools


class FakePim:
    def __init__(self):
        self.calls = []

    async def list_events(self, email, calendar_id, start, end, query):
        self.calls.append((email, calendar_id, start, end, query))
        return [], []

    async def create_event(self, email, calendar_id, data):
        self.calls.append(("create", email, data))
        return EventInfo(
            email,
            "c",
            "e1",
            data.title,
            str(data.start),
            str(data.end),
            True,
            None,
            None,
            False,
            False,
        )


@pytest.fixture
def server():
    mcp, pim = FastMCP("t"), FakePim()
    register_pim_tools(mcp, pim)
    return mcp, pim


async def test_tool_names(server):
    mcp, _ = server
    async with Client(mcp) as c:
        names = {t.name for t in await c.list_tools()}
    assert names == {
        "list_calendars",
        "list_events",
        "create_event",
        "update_event",
        "delete_event",
        "list_task_lists",
        "list_tasks",
        "create_task",
        "update_task",
        "delete_task",
        "search_contacts",
    }


async def test_no_attendee_parameters(server):
    mcp, _ = server
    async with Client(mcp) as c:
        for t in await c.list_tools():
            assert "attendee" not in str(t.input_schema).lower()


async def test_list_events_range_validation(server):
    mcp, _ = server
    async with Client(mcp) as c:
        bad = await c.call_tool(
            "list_events", {"start": "2026-10-02", "end": "2026-10-01"}, raise_on_error=False
        )
        assert bad.is_error
        huge = await c.call_tool(
            "list_events", {"start": "2026-01-01", "end": "2027-06-01"}, raise_on_error=False
        )
        assert huge.is_error


async def test_create_all_day_event(server):
    mcp, pim = server
    async with Client(mcp) as c:
        res = await c.call_tool(
            "create_event",
            {
                "account": "s@example.com",
                "title": "Holiday",
                "start": "2026-10-05",
                "end": "2026-10-06",
            },
        )
    assert res.structured_content["all_day"] is True
    assert pim.calls[0][2].title == "Holiday"


# -- extra tests -----------------------------------------------------------------------


class MorePim(FakePim):
    async def list_calendars(self, email):
        self.calls.append(("list_calendars", email))
        return [CalendarInfo("s@example.com", "cal-1", "Personal", False, True)], [
            AccountError("g@gmail.com", "account unavailable: needs_google_connect")
        ]

    async def delete_event(self, email, calendar_id, event_id):
        raise PimError("event e1 is read-only for this server (has attendees / is recurring)")

    async def update_event(self, email, calendar_id, event_id, data):
        self.calls.append(("update_event", email, calendar_id, event_id, data))
        return EventInfo(
            email, calendar_id, event_id, "x", "", None, False, None, None, False, False
        )

    async def create_task(self, email, list_id, data):
        self.calls.append(("create_task", email, list_id, data))
        return TaskInfo(email, "l", "t1", data.title, None, str(data.due), False, None)

    async def search_contacts(self, query, email, limit):
        self.calls.append(("search_contacts", query, email, limit))
        return [], []


@pytest.fixture
def more():
    mcp, pim = FastMCP("t"), MorePim()
    register_pim_tools(mcp, pim)
    return mcp, pim


async def test_annotations_and_safety_descriptions(more):
    mcp, _ = more
    async with Client(mcp) as c:
        tools = {t.name: t for t in await c.list_tools()}
    for name in (
        "list_calendars",
        "list_events",
        "list_task_lists",
        "list_tasks",
        "search_contacts",
    ):
        assert tools[name].annotations.read_only_hint is True
    for name in ("create_event", "update_event", "create_task", "update_task"):
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.destructive_hint is False
    for name in ("delete_event", "delete_task"):
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.destructive_hint is True
    assert "invit" in tools["create_event"].description
    assert "Europe/Prague" in tools["create_event"].description
    assert "Europe/Prague" in tools["list_events"].description
    for name in ("update_event", "delete_event"):
        assert "attendees" in tools[name].description and "recurring" in tools[name].description


async def test_list_calendars_shape_and_account_normalised(more):
    mcp, pim = more
    async with Client(mcp) as c:
        res = await c.call_tool("list_calendars", {"account": "  S@Example.COM "})
    assert pim.calls == [("list_calendars", "s@example.com")]
    assert res.structured_content == {
        "calendars": [
            {
                "account": "s@example.com",
                "id": "cal-1",
                "name": "Personal",
                "read_only": False,
                "primary": True,
            }
        ],
        "errors": [
            {"account": "g@gmail.com", "error": "account unavailable: needs_google_connect"}
        ],
    }


async def test_list_events_converts_dates_to_prague_midnight(server):
    mcp, pim = server
    async with Client(mcp) as c:
        await c.call_tool(
            "list_events", {"start": "2026-10-01", "end": "2026-10-02T12:00", "query": ""}
        )
    email, cal, start, end, query = pim.calls[0]
    assert (email, cal, query) == (None, None, None)
    assert start == datetime(2026, 10, 1, 0, 0, tzinfo=TZ)
    assert end == datetime(2026, 10, 2, 12, 0, tzinfo=TZ)


async def test_list_events_calendar_id_needs_account(server):
    mcp, pim = server
    async with Client(mcp) as c:
        res = await c.call_tool(
            "list_events",
            {"start": "2026-10-01", "end": "2026-10-02", "calendar_id": "cal-1"},
            raise_on_error=False,
        )
    assert res.is_error and "needs the account" in res.content[0].text and pim.calls == []


async def test_pim_error_becomes_clean_tool_error(more):
    mcp, _ = more
    async with Client(mcp) as c:
        res = await c.call_tool(
            "delete_event",
            {"account": "s@example.com", "calendar_id": "c", "event_id": "e1"},
            raise_on_error=False,
        )
    assert res.is_error and "read-only" in res.content[0].text


async def test_create_event_rejects_bad_times(server):
    mcp, pim = server
    async with Client(mcp) as c:
        for start, end in (
            ("2026-10-05", "2026-10-05T10:00"),
            ("2026-10-05T10:00", "2026-10-05T09:00"),
            ("tomorrow", "2026-10-06"),
        ):
            res = await c.call_tool(
                "create_event",
                {"account": "s@example.com", "title": "X", "start": start, "end": end},
                raise_on_error=False,
            )
            assert res.is_error
    assert pim.calls == []


async def test_update_event_passes_only_given_fields(more):
    mcp, pim = more
    async with Client(mcp) as c:
        empty = await c.call_tool(
            "update_event",
            {"account": "s@example.com", "calendar_id": "c", "event_id": "e"},
            raise_on_error=False,
        )
        assert empty.is_error and "nothing to change" in empty.content[0].text
        await c.call_tool(
            "update_event",
            {
                "account": "s@example.com",
                "calendar_id": "c",
                "event_id": "e",
                "start": "2026-10-05T09:00",
                "location": "",
            },
        )
    _, email, cal, eid, data = pim.calls[0]
    assert (email, cal, eid) == ("s@example.com", "c", "e")
    assert data.start == datetime(2026, 10, 5, 9, 0, tzinfo=TZ)
    assert data.end is None and data.title is None and data.location == ""


async def test_create_task_due_must_be_a_date(more):
    mcp, pim = more
    async with Client(mcp) as c:
        bad = await c.call_tool(
            "create_task",
            {"account": "s@example.com", "title": "T", "due": "2026-10-05T10:00"},
            raise_on_error=False,
        )
        assert bad.is_error
        await c.call_tool(
            "create_task", {"account": "s@example.com", "title": "T", "due": "2026-10-05"}
        )
    assert pim.calls == [("create_task", "s@example.com", None, pim.calls[0][3])]
    assert pim.calls[0][3].due == date(2026, 10, 5)


async def test_search_contacts_limit_bounds(more):
    mcp, pim = more
    async with Client(mcp) as c:
        for limit in (0, 51):
            res = await c.call_tool(
                "search_contacts", {"query": "jan", "limit": limit}, raise_on_error=False
            )
            assert res.is_error
        await c.call_tool("search_contacts", {"query": "jan", "limit": 50})
    assert pim.calls == [("search_contacts", "jan", None, 50)]


def _event(i, description=None):
    return EventInfo(
        "s@example.com",
        "c",
        f"e{i}",
        "E",
        "2026-10-01",
        None,
        True,
        None,
        description,
        False,
        False,
    )


class ManyPim(FakePim):
    def __init__(self, events=(), tasks=()):
        super().__init__()
        self.events, self.tasks = list(events), list(tasks)

    async def list_events(self, email, calendar_id, start, end, query):
        return self.events, []

    async def list_tasks(self, email, list_id, include_completed):
        return self.tasks, []


async def _call(pim, tool, args):
    mcp = FastMCP("t")
    register_pim_tools(mcp, pim)
    async with Client(mcp) as c:
        return (await c.call_tool(tool, args)).structured_content


RANGE = {"start": "2026-10-01", "end": "2026-10-02"}


async def test_listings_are_capped_and_flag_truncation():
    from postroom.tools.pim_tools import MAX_LIST_ITEMS

    few = await _call(ManyPim(events=[_event(i) for i in range(3)]), "list_events", RANGE)
    assert len(few["events"]) == 3 and few["truncated"] is False
    # Merged over accounts: more than the cap is cut and flagged.
    events = [_event(i) for i in range(MAX_LIST_ITEMS + 20)]
    many = await _call(ManyPim(events=events), "list_events", RANGE)
    assert len(many["events"]) == MAX_LIST_ITEMS and many["truncated"] is True
    assert "narrow" in many["note"]
    tasks = [
        TaskInfo("s@example.com", "l", f"t{i}", "T", None, None, False, None)
        for i in range(MAX_LIST_ITEMS)
    ]
    # Exactly the cap: a backend may have cut there, so it is flagged too.
    res = await _call(ManyPim(tasks=tasks), "list_tasks", {})
    assert len(res["tasks"]) == MAX_LIST_ITEMS and res["truncated"] is True


async def test_listing_response_size_is_bounded():
    from postroom.tools.pim_tools import MAX_LIST_CHARS

    big = [_event(i, description="x" * 50_000) for i in range(40)]
    res = await _call(ManyPim(events=big), "list_events", RANGE)
    assert res["truncated"] is True and 0 < len(res["events"]) < 40
    assert sum(len(e["description"]) for e in res["events"]) <= MAX_LIST_CHARS
