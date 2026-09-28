"""MCP calendar, task and contact tools for Google accounts and CalDAV/CardDAV accounts.

Safety: no tool accepts attendees, so nothing here can send an invitation. Events and
tasks that already have attendees or are recurring are read-only (the backends refuse
to change or delete them), and Google writes always pass `sendUpdates=none`.

`PimError` and `ValueError` messages are secret-free and are passed to the client as
`ToolError`s; anything unexpected is left for FastMCP to report (masked by `build_mcp`).
"""

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from postroom.pim.models import EventInput, PimError, TaskInput, parse_when, validate_range
from postroom.pim.service import PimService

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}
WRITES = {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}
DELETES = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}

MAX_RANGE = timedelta(days=366)
MAX_CONTACTS = 50
# Event/task listings: at most this many items (the backends' own per-account cap too)
# and about this many characters of JSON, so one answer cannot flood the context.
MAX_LIST_ITEMS = 500
MAX_LIST_CHARS = 400_000
TRUNCATED_NOTE = "more items than fit in one answer; narrow the range, account or list"

_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


@contextmanager
def _tool_errors() -> Iterator[None]:
    """Turn expected PIM errors into clean `ToolError`s (message only)."""
    try:
        yield
    except TimeoutError as e:
        raise ToolError("the server did not respond in time; try again later") from e
    except (PimError, ValueError) as e:
        raise ToolError(str(e) or type(e).__name__) from e


def _norm(account: str | None) -> str | None:
    if account is None:
        return None
    account = account.strip().lower()
    return account or None


def _required(name: str, value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _when(name: str, value: str | None, tz: ZoneInfo) -> datetime | date | None:
    if value is None:
        return None
    try:
        return parse_when(value, tz)
    except ValueError:
        raise ValueError(
            f"{name} must be YYYY-MM-DD or an ISO date-time, got {str(value)[:100]!r}"
        ) from None


def _instant(name: str, value: str, tz: ZoneInfo) -> datetime:
    """A range bound as an aware datetime; a plain date means local midnight in `tz`."""
    when = _when(name, value, tz)
    if isinstance(when, datetime):
        return when
    return datetime.combine(when, time.min, tz)


def _due(value: str | None) -> date | None:
    if value is None:
        return None
    if not _ISO_DATE.fullmatch(value.strip()):
        raise ValueError(f"due must be a date in YYYY-MM-DD format, got {value[:100]!r}")
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        raise ValueError(f"due is not a valid date: {value[:100]!r}") from None


def _lists(key: str, items: list, errors: list) -> dict:
    return {key: [i.to_dict() for i in items], "errors": [e.to_dict() for e in errors]}


def _capped(key: str, items: list, errors: list) -> dict:
    """`_lists` for event/task listings, cut to MAX_LIST_ITEMS items and MAX_LIST_CHARS.

    `truncated` is also set when exactly MAX_LIST_ITEMS came back, since a backend may
    have cut its own listing there.
    """
    out: list[dict] = []
    size = 0
    for item in items[:MAX_LIST_ITEMS]:
        d = item.to_dict()
        size += len(json.dumps(d, ensure_ascii=False))
        if size > MAX_LIST_CHARS:
            break
        out.append(d)
    result = {key: out, "errors": [e.to_dict() for e in errors]}
    result["truncated"] = len(out) < len(items) or len(items) >= MAX_LIST_ITEMS
    if result["truncated"]:
        result["note"] = TRUNCATED_NOTE
    return result


def register_pim_tools(mcp: FastMCP, pim: PimService, tz: ZoneInfo) -> None:
    """Register the tools. `tz` is the server's configured time zone (POSTROOM_TIMEZONE);
    the docstrings below must not name a zone, since it is a per-server setting."""
    # -- calendars & events -----------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_calendars(account: str | None = None) -> dict:
        """List calendars of one account, or of every account with a calendar.

        Returns {"calendars": [...], "errors": [...], "time_zone": ...}: accounts that
        fail are listed in `errors`; `time_zone` is the server's configured time zone.
        Pass a calendar's `account` and `id` (as calendar_id) to the event tools.
        """
        with _tool_errors():
            calendars, errors = await pim.list_calendars(_norm(account))
        return {**_lists("calendars", calendars, errors), "time_zone": tz.key}

    @mcp.tool(annotations=READ_ONLY)
    async def list_events(
        start: str,
        end: str,
        account: str | None = None,
        calendar_id: str | None = None,
        query: str | None = None,
    ) -> dict:
        """List events between start and end (at most 366 days), merged and sorted by start.

        start / end: YYYY-MM-DD (local midnight) or an ISO date-time; naive times are in
        the server's configured time zone (POSTROOM_TIMEZONE), and event times come back
        in it. account: omit to read every account with a calendar.
        calendar_id: one calendar from list_calendars (needs `account`); omit to read the
        account's calendars. query: free text matched against title/location/description.
        Events with `has_attendees` or `recurring` set are read-only for this server.
        Returns {"events": [...], "errors": [...], "truncated": bool}: at most 500 events,
        the earliest first; when `truncated` is true, narrow the range.
        """
        with _tool_errors():
            begin, finish = _instant("start", start, tz), _instant("end", end, tz)
            if finish <= begin:
                raise ValueError("end must be after start")
            if finish - begin > MAX_RANGE:
                raise ValueError("the range from start to end can be at most 366 days")
            email = _norm(account)
            if calendar_id and email is None:
                raise ValueError("calendar_id needs the account it belongs to")
            events, errors = await pim.list_events(
                email, calendar_id or None, begin, finish, query or None
            )
        return _capped("events", events, errors)

    @mcp.tool(annotations=WRITES)
    async def create_event(
        account: str,
        title: str,
        start: str,
        end: str,
        calendar_id: str | None = None,
        location: str | None = None,
        description: str | None = None,
    ) -> dict:
        """Create an event in the account's calendar (its primary calendar by default).

        start / end: both YYYY-MM-DD for an all-day event (end is exclusive: a one-day
        event on 5 Oct is start=2026-10-05, end=2026-10-06), or both ISO date-times;
        naive times are in the server's configured time zone (POSTROOM_TIMEZONE), and a
        timed event is stored in that zone. calendar_id: one of the account's own calendars
        (read_only=false in list_calendars); calendars shared by others are refused.
        The event has no attendees: this server never invites anyone or sends invitations.
        """
        with _tool_errors():
            data = EventInput(
                title=_required("title", title),
                start=_when("start", start, tz),
                end=_when("end", end, tz),
                location=location or None,
                description=description or None,
            )
            validate_range(data.start, data.end, tz)
            event = await pim.create_event(
                _required("account", account).lower(), calendar_id or None, data
            )
        return event.to_dict()

    @mcp.tool(annotations=WRITES)
    async def update_event(
        account: str,
        calendar_id: str,
        event_id: str,
        title: str | None = None,
        start: str | None = None,
        end: str | None = None,
        location: str | None = None,
        description: str | None = None,
    ) -> dict:
        """Change an event's title, time, location or description; omitted fields stay.

        start / end as in create_event (naive times are in the server's configured time
        zone, POSTROOM_TIMEZONE). A new start
        without a new end moves the event and keeps its duration. An empty location or
        description removes it. Events that have attendees or are recurring are
        read-only for this server and are refused; attendees can never be added.
        """
        with _tool_errors():
            if title is not None and not title.strip():
                raise ValueError("title cannot be empty")
            data = EventInput(
                title=title.strip() if title is not None else None,
                start=_when("start", start, tz),
                end=_when("end", end, tz),
                location=location,
                description=description,
            )
            if all(v is None for v in data.to_dict().values()):
                raise ValueError("nothing to change: give at least one field to update")
            event = await pim.update_event(
                _required("account", account).lower(),
                _required("calendar_id", calendar_id),
                _required("event_id", event_id),
                data,
            )
        return event.to_dict()

    @mcp.tool(annotations=DELETES)
    async def delete_event(account: str, calendar_id: str, event_id: str) -> dict:
        """Delete an event. Events that have attendees or are recurring are read-only for
        this server and are refused, so no cancellation is ever sent to anyone.
        """
        with _tool_errors():
            email = _required("account", account).lower()
            cal = _required("calendar_id", calendar_id)
            eid = _required("event_id", event_id)
            await pim.delete_event(email, cal, eid)
        return {"deleted": True, "account": email, "calendar_id": cal, "event_id": eid}

    # -- tasks ------------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def list_task_lists(account: str | None = None) -> dict:
        """List task lists of one account, or of every account with tasks.

        Returns {"task_lists": [...], "errors": [...]}.
        """
        with _tool_errors():
            lists, errors = await pim.list_task_lists(_norm(account))
        return _lists("task_lists", lists, errors)

    @mcp.tool(annotations=READ_ONLY)
    async def list_tasks(
        account: str | None = None, list_id: str | None = None, include_completed: bool = False
    ) -> dict:
        """List tasks of one account, or of every account with tasks.

        list_id: one task list from list_task_lists (needs `account`); omit for all lists.
        Completed tasks are left out unless include_completed=true.
        Returns {"tasks": [...], "errors": [...], "truncated": bool} (at most 500 tasks).
        """
        with _tool_errors():
            email = _norm(account)
            if list_id and email is None:
                raise ValueError("list_id needs the account it belongs to")
            tasks, errors = await pim.list_tasks(email, list_id or None, include_completed)
        return _capped("tasks", tasks, errors)

    @mcp.tool(annotations=WRITES)
    async def create_task(
        account: str,
        title: str,
        list_id: str | None = None,
        notes: str | None = None,
        due: str | None = None,
    ) -> dict:
        """Create a task (in the account's default task list unless list_id is given).

        due: a date as YYYY-MM-DD.
        """
        with _tool_errors():
            data = TaskInput(title=_required("title", title), notes=notes or None, due=_due(due))
            task = await pim.create_task(
                _required("account", account).lower(), list_id or None, data
            )
        return task.to_dict()

    @mcp.tool(annotations=WRITES)
    async def update_task(
        account: str,
        list_id: str,
        task_id: str,
        title: str | None = None,
        notes: str | None = None,
        due: str | None = None,
        completed: bool | None = None,
    ) -> dict:
        """Change a task's title, notes or due date (YYYY-MM-DD), or mark it completed
        (completed=true) or open again (completed=false); omitted fields stay.

        Tasks that have attendees or are recurring are read-only for this server.
        """
        with _tool_errors():
            if title is not None and not title.strip():
                raise ValueError("title cannot be empty")
            data = TaskInput(
                title=title.strip() if title is not None else None,
                notes=notes,
                due=_due(due),
                completed=completed,
            )
            if all(v is None for v in data.to_dict().values()):
                raise ValueError("nothing to change: give at least one field to update")
            task = await pim.update_task(
                _required("account", account).lower(),
                _required("list_id", list_id),
                _required("task_id", task_id),
                data,
            )
        return task.to_dict()

    @mcp.tool(annotations=DELETES)
    async def delete_task(account: str, list_id: str, task_id: str) -> dict:
        """Delete a task. Tasks that have attendees or are recurring are refused."""
        with _tool_errors():
            email = _required("account", account).lower()
            lid = _required("list_id", list_id)
            tid = _required("task_id", task_id)
            await pim.delete_task(email, lid, tid)
        return {"deleted": True, "account": email, "list_id": lid, "task_id": tid}

    # -- contacts ---------------------------------------------------------------

    @mcp.tool(annotations=READ_ONLY)
    async def search_contacts(query: str, account: str | None = None, limit: int = 20) -> dict:
        """Search contacts by name, email, phone or organization.

        account: omit to search every account with contacts. limit: 1-50 (default 20).
        Returns {"contacts": [...], "errors": [...]}.
        """
        with _tool_errors():
            if not 1 <= limit <= MAX_CONTACTS:
                raise ValueError(f"limit must be between 1 and {MAX_CONTACTS}")
            contacts, errors = await pim.search_contacts(
                _required("query", query), _norm(account), limit
            )
        return _lists("contacts", contacts, errors)
