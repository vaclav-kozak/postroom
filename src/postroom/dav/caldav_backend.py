"""CalDAV calendars (VEVENT) and task lists (VTODO) for IMAP accounts with a CalDAV server.

Safety rules (see the PIM safety rules in the plan):
- Nothing written here ever carries ATTENDEE or ORGANIZER, so the server never has a
  reason to send invitations (SOGo does implicit scheduling).
- Events and tasks that already have attendees or are recurring are read-only:
  update/delete refuse them before touching the server object.
- HTTP 401 calls `on_auth_failure()` (trips the account's circuit breaker; mailcow's
  fail2ban also watches SOGo logins) and this instance never contacts the server again.
- Calendar ids are the calendar URLs; a caller-supplied id is only used after it has
  been matched against the account's own discovered calendars, so credentials are never
  sent to an arbitrary URL.
- Listings are bounded: recurring events are expanded lazily per series (caldav's own
  `expand=True` would materialise every instance in the range, e.g. ~527k for one
  `FREQ=MINUTELY` event over a year), and only the first `MAX_ITEMS` instances by start
  are ever kept.
"""

import heapq
import itertools
import logging
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from urllib.parse import unquote
from zoneinfo import ZoneInfo

import caldav
import icalendar
import recurring_ical_events
from caldav.lib import error as dav_error

from postroom.dav.urls import require_dav_url
from postroom.pim.models import (
    CalendarInfo,
    EventInfo,
    EventInput,
    PimError,
    TaskInfo,
    TaskInput,
    TaskListInfo,
    aware,
    is_all_day,
    iso,
    rescheduled,
    validate_range,
)

MAX_ITEMS = 500
PRODID = "-//Postroom//EN"
UID_DOMAIN = "postroom"
READ_ONLY = "is read-only for this server (has attendees / is recurring)"
CHANGED = "item changed on the server; fetch it again"

_RECURRENCE_PROPS = ("RRULE", "RDATE", "RECURRENCE-ID")
# What a malformed calendar object raises while being converted (icalendar's
# BrokenCalendarProperty is a ValueError; a PERIOD-valued DTSTART gives a tuple).
_MALFORMED = (ValueError, TypeError, AttributeError, KeyError, IndexError)

log = logging.getLogger(__name__)


class _DAVClient(caldav.DAVClient):
    """DAVClient that remembers the HTTP status behind its last `AuthorizationError`.

    caldav raises the same `AuthorizationError` for 401 (bad credentials) and 403
    (permission denied, e.g. writing to a read-only shared calendar). Only a login
    failure may trip the account's circuit breaker; an unknown status is treated as one.
    """

    auth_error_status: int | None = None

    def _raise_authorization_error(self, url_str, reason_source):
        self.auth_error_status = getattr(reason_source, "status_code", None)
        super()._raise_authorization_error(url_str, reason_source)


def _text(comp, name: str) -> str | None:
    value = comp.get(name)
    if value is None:
        return None
    s = str(value)
    return s if s else None


def _occurrences(obj, start: datetime) -> tuple[bool, Iterator]:
    """Whether `obj` is recurring, and its VEVENT instances that end after `start`.

    The instances come in start order, lazily: a recurring series is expanded one
    instance at a time, so the caller can stop early.
    """
    ical = obj.get_icalendar_instance()
    recurring = any(p in c for c in ical.walk() if c.name == "VEVENT" for p in _RECURRENCE_PROPS)
    return recurring, recurring_ical_events.of(ical, components=["VEVENT"]).after(start)


def _as_local(value: date | datetime, tz: tzinfo) -> date | datetime:
    """Date-times in `tz` (floating ones are taken as local time in `tz`)."""
    if isinstance(value, datetime):
        return aware(value, tz).astimezone(tz)
    return value


def _sort_instant(value: date | datetime | None, tz: tzinfo) -> datetime:
    if value is None:
        return datetime.max.replace(tzinfo=UTC)
    if isinstance(value, datetime):
        return aware(value, tz)
    return datetime.combine(value, time(), tzinfo=tz)


def _prop_dt(comp, name: str) -> date | datetime | None:
    prop = comp.get(name)
    return getattr(prop, "dt", None) if prop is not None else None


def _set(comp, name: str, value, **params) -> None:
    comp.pop(name, None)
    if value is not None and value != "":
        comp.add(name, value, parameters=params or None)


def _components(obj) -> list:
    cal = obj.get_icalendar_instance()
    return [c for c in cal.walk() if c.name in ("VEVENT", "VTODO", "VJOURNAL")]


def _is_read_only(obj) -> bool:
    comps = _components(obj)
    has_attendees = any("ATTENDEE" in c for c in comps)
    recurring = any(p in c for c in comps for p in _RECURRENCE_PROPS)
    return has_attendees or recurring


def _vcalendar(component) -> str:
    cal = icalendar.Calendar()
    cal.add("PRODID", PRODID)
    cal.add("VERSION", "2.0")
    cal.add_component(component)
    cal.add_missing_timezones()
    return cal.to_ical().decode("utf-8")


def _new_uid() -> str:
    return f"{uuid.uuid4()}@{UID_DOMAIN}"


def _to_ical_when(value: date | datetime, tz: tzinfo) -> date | datetime:
    """Date-times are stored in `tz` (with its VTIMEZONE), never as a bare offset.

    icalendar would write an offset-only tzinfo as `TZID="UTC+02:00"` without any
    VTIMEZONE, which is invalid iCalendar.
    """
    return aware(value, tz).astimezone(tz) if isinstance(value, datetime) else value


def _main_component(ical):
    return next(c for c in ical.subcomponents if c.name != "VTIMEZONE")


def _href(obj) -> str:
    return str(getattr(obj, "url", "") or "?")


def _task_due(value: date) -> date:
    return value.date() if isinstance(value, datetime) else value


def _mark_completed(comp, completed: bool) -> None:
    if completed:
        _set(comp, "STATUS", "COMPLETED")
        _set(comp, "COMPLETED", datetime.now(UTC).replace(microsecond=0))
        _set(comp, "PERCENT-COMPLETE", 100)
    else:
        _set(comp, "STATUS", "NEEDS-ACTION")
        comp.pop("COMPLETED", None)
        _set(comp, "PERCENT-COMPLETE", 0)


def _task_order(t: TaskInfo) -> tuple:
    return (t.completed, t.due is None, t.due or "", t.title.casefold())


class CalDavBackend:
    def __init__(
        self,
        account: str,
        url: str,
        username: str,
        password: str,
        timeout: int = 30,
        on_auth_failure: Callable[[], None] = lambda: None,
        tz: ZoneInfo | None = None,
    ):
        self.account = account
        # The server's configured time zone: floating times are read in it, new and moved
        # events are stored in it and listings are returned in it.
        self.tz = tz or ZoneInfo("UTC")
        require_dav_url(url)  # the password goes out as Basic auth: never in cleartext
        self._client = _DAVClient(url=url, username=username, password=password, timeout=timeout)
        self._on_auth_failure = on_auth_failure
        self._principal = None
        self._auth_failed = False

    def close(self) -> None:
        self._client.close()

    # -- plumbing ---------------------------------------------------------------

    @contextmanager
    def _dav(self) -> Iterator[None]:
        if self._auth_failed:
            raise PimError("CalDAV login failed")
        try:
            yield
        except PimError:
            raise
        except (dav_error.ETagMismatchError, dav_error.ScheduleTagMismatchError) as e:
            raise PimError(CHANGED) from e
        except dav_error.AuthorizationError as e:
            status = self._client.auth_error_status
            self._client.auth_error_status = None
            if status == 403:
                raise PimError("CalDAV access denied") from e
            self._auth_failed = True
            self._on_auth_failure()
            raise PimError("CalDAV login failed") from e
        except dav_error.NotFoundError as e:
            raise PimError("not found") from e
        except (dav_error.DAVError, OSError) as e:  # niquests/requests errors are OSErrors
            raise PimError(f"CalDAV error: {type(e).__name__}") from e

    def _delete(self, obj) -> None:
        """DELETE conditional on the ETag of the copy just fetched (412 if it changed)."""
        headers = {"If-Match": obj.etag} if obj.etag else {}
        resp = self._client.request(str(obj.url), "DELETE", "", headers=headers)
        if resp.status == 412:
            raise PimError(CHANGED)
        if resp.status not in (200, 204, 404):
            raise PimError(f"CalDAV error {resp.status}")

    def _get_principal(self):
        if self._principal is None:
            self._principal = self._client.principal()
        return self._principal

    def _collections(self, component: str) -> list:
        """The account's calendar collections that support `component` (VEVENT/VTODO)."""
        out = []
        for cal in self._get_principal().get_calendars():
            supported = {str(c).upper() for c in cal.get_supported_components()}
            if component in supported:
                out.append(cal)
        return out

    @staticmethod
    def _id(cal) -> str:
        return str(cal.url)

    @staticmethod
    def _name(cal) -> str:
        name = cal.get_display_name()
        if name:
            return str(name)
        return unquote(str(cal.url).rstrip("/").rsplit("/", 1)[-1])

    @staticmethod
    def _primary(cals: list):
        if not cals:
            return None
        return next((c for c in cals if str(c.url).endswith("/personal/")), cals[0])

    def _find(self, cal_id: str | None, component: str):
        cals = self._collections(component)
        if cal_id is None:
            cal = self._primary(cals)
            if cal is None:
                kind = "calendar" if component == "VEVENT" else "task list"
                raise PimError(f"no {kind} found for this account")
            return cal
        wanted = cal_id.rstrip("/")
        for cal in cals:
            if self._id(cal).rstrip("/") == wanted:
                return cal
        kind = "calendar" if component == "VEVENT" else "task list"
        raise PimError(f"{kind} not found: {cal_id}")

    # -- events -----------------------------------------------------------------

    def _event_info(self, cal, obj) -> EventInfo:
        return self._event_info_from(cal, obj.get_icalendar_component())

    def _event_info_from(self, cal, comp, recurring: bool | None = None) -> EventInfo:
        start = _prop_dt(comp, "DTSTART")
        end = _prop_dt(comp, "DTEND")
        if end is None and start is not None:
            duration = _prop_dt(comp, "DURATION")
            if isinstance(duration, timedelta):
                end = start + duration
        return EventInfo(
            account=self.account,
            calendar_id=self._id(cal),
            id=str(comp.get("UID", "")),
            title=_text(comp, "SUMMARY") or "",
            start=iso(_as_local(start, self.tz)) if start is not None else "",
            end=iso(_as_local(end, self.tz)) if end is not None else None,
            all_day=start is not None and is_all_day(start),
            location=_text(comp, "LOCATION"),
            description=_text(comp, "DESCRIPTION"),
            recurring=any(p in comp for p in _RECURRENCE_PROPS) if recurring is None else recurring,
            has_attendees="ATTENDEE" in comp,
            status=_text(comp, "STATUS"),
        )

    def list_calendars(self) -> list[CalendarInfo]:
        with self._dav():
            cals = self._collections("VEVENT")
            primary = self._primary(cals)
            return [
                CalendarInfo(
                    account=self.account,
                    id=self._id(c),
                    name=self._name(c),
                    read_only=False,
                    primary=c is primary,
                )
                for c in cals
            ]

    def list_events(
        self, calendar_id: str | None, start: datetime, end: datetime, query: str | None
    ) -> list[EventInfo]:
        """The first `MAX_ITEMS` event instances overlapping [start, end), by start.

        The server returns the objects that overlap the range, unexpanded; each series is
        expanded here and abandoned as soon as its next instance starts at or after
        `end`, or can no longer be among the first `MAX_ITEMS` found so far. So memory
        and time are bounded by the number of objects, not by how often they recur.
        """
        start, end = _sort_instant(start, self.tz), _sort_instant(end, self.tz)
        needle = (query or "").strip().casefold()
        # The first MAX_ITEMS so far, as a heap whose top is the latest of them
        # (negated timestamps; `seq` keeps the earlier-found one first on a tie).
        best: list[tuple[float, int, EventInfo]] = []
        seq = itertools.count()
        with self._dav():
            cals = (
                [self._find(calendar_id, "VEVENT")] if calendar_id else self._collections("VEVENT")
            )
            for cal in cals:
                for obj in cal.search(start=start, end=end, event=True, expand=False):
                    try:
                        recurring, instances = _occurrences(obj, start)
                        for comp in instances:
                            key = _sort_instant(_prop_dt(comp, "DTSTART"), self.tz)
                            if key >= end or (
                                len(best) >= MAX_ITEMS and key.timestamp() >= -best[0][0]
                            ):
                                break  # this and every later instance are out
                            info = self._event_info_from(cal, comp, recurring)
                            if needle and not any(
                                needle in (v or "").casefold()
                                for v in (info.title, info.location, info.description)
                            ):
                                continue
                            item = (-key.timestamp(), -next(seq), info)
                            if len(best) < MAX_ITEMS:
                                heapq.heappush(best, item)
                            else:
                                heapq.heapreplace(best, item)
                    except _MALFORMED as e:
                        log.warning(
                            "skipping malformed event %s (%s)", _href(obj), type(e).__name__
                        )
        found = sorted(best, key=lambda it: (-it[0], -it[1]))
        return [info for _, _, info in found]

    def create_event(self, calendar_id: str | None, data: EventInput) -> EventInfo:
        if not data.title or data.start is None or data.end is None:
            raise PimError("title, start and end are required")
        try:
            validate_range(data.start, data.end, self.tz)
        except ValueError as e:
            raise PimError(str(e)) from e
        ev = icalendar.Event()
        ev.add("UID", _new_uid())
        ev.add("DTSTAMP", datetime.now(UTC).replace(microsecond=0))
        ev.add("SUMMARY", data.title)
        ev.add("DTSTART", _to_ical_when(data.start, self.tz))
        ev.add("DTEND", _to_ical_when(data.end, self.tz))
        if data.location:
            ev.add("LOCATION", data.location)
        if data.description:
            ev.add("DESCRIPTION", data.description)
        with self._dav():
            cal = self._find(calendar_id, "VEVENT")
            obj = cal.add_event(_vcalendar(ev))
            return self._event_info(cal, obj)

    def _writable_event(self, calendar_id: str, event_id: str):
        cal = self._find(calendar_id, "VEVENT")
        obj = cal.get_event_by_uid(event_id)
        obj.load()  # fresh copy and its ETag: the write below is conditional on it
        if _is_read_only(obj):
            raise PimError(f"event {event_id!r} {READ_ONLY}")
        return cal, obj

    def update_event(self, calendar_id: str, event_id: str, data: EventInput) -> EventInfo:
        with self._dav():
            cal, obj = self._writable_event(calendar_id, event_id)
            with obj.edit_icalendar_instance() as ical:
                comp = _main_component(ical)
                if data.start is not None or data.end is not None:
                    self._move(comp, data.start, data.end)
                if data.title is not None:
                    if not data.title:
                        raise PimError("title must not be empty")
                    _set(comp, "SUMMARY", data.title)
                if data.location is not None:
                    _set(comp, "LOCATION", data.location)
                if data.description is not None:
                    _set(comp, "DESCRIPTION", data.description)
                _set(comp, "DTSTAMP", datetime.now(UTC).replace(microsecond=0))
                ical.add_missing_timezones()
            obj.save()
            return self._event_info(cal, obj)

    def _move(self, comp, new_start, new_end) -> None:
        old_start = _prop_dt(comp, "DTSTART")
        old_end = _prop_dt(comp, "DTEND")
        duration = _prop_dt(comp, "DURATION")
        if old_end is None and old_start is not None and isinstance(duration, timedelta):
            old_end = old_start + duration
        try:
            start, end = rescheduled(old_start, old_end, new_start, new_end, self.tz)
        except ValueError as e:
            raise PimError(str(e)) from e
        comp.pop("DURATION", None)
        _set(comp, "DTSTART", _to_ical_when(start, self.tz))
        _set(comp, "DTEND", _to_ical_when(end, self.tz))

    def delete_event(self, calendar_id: str, event_id: str) -> None:
        with self._dav():
            _, obj = self._writable_event(calendar_id, event_id)
            self._delete(obj)

    # -- tasks ------------------------------------------------------------------

    def _task_info(self, cal, obj) -> TaskInfo:
        comp = obj.get_icalendar_component()
        due = _prop_dt(comp, "DUE")
        completed_at = _prop_dt(comp, "COMPLETED")
        status = (_text(comp, "STATUS") or "").upper()
        return TaskInfo(
            account=self.account,
            list_id=self._id(cal),
            id=str(comp.get("UID", "")),
            title=_text(comp, "SUMMARY") or "",
            notes=_text(comp, "DESCRIPTION"),
            due=iso(_as_local(due, self.tz)) if due is not None else None,
            completed=status == "COMPLETED" or completed_at is not None,
            completed_at=(
                iso(_as_local(completed_at, self.tz)) if completed_at is not None else None
            ),
        )

    def list_task_lists(self) -> list[TaskListInfo]:
        with self._dav():
            return [
                TaskListInfo(account=self.account, id=self._id(c), name=self._name(c))
                for c in self._collections("VTODO")
            ]

    def list_tasks(self, list_id: str | None, include_completed: bool) -> list[TaskInfo]:
        """The first `MAX_ITEMS` tasks: open before completed, then by due date and title.

        Each list's objects are converted and dropped before the next list is fetched,
        and at most `MAX_ITEMS` tasks are kept between lists.
        """
        tasks: list[TaskInfo] = []
        with self._dav():
            cals = [self._find(list_id, "VTODO")] if list_id else self._collections("VTODO")
            for cal in cals:
                for obj in cal.get_todos(include_completed=include_completed):
                    try:
                        tasks.append(self._task_info(cal, obj))
                    except _MALFORMED as e:
                        log.warning("skipping malformed task %s (%s)", _href(obj), type(e).__name__)
                tasks = heapq.nsmallest(MAX_ITEMS, tasks, key=_task_order)
        return tasks

    def create_task(self, list_id: str | None, data: TaskInput) -> TaskInfo:
        if not data.title:
            raise PimError("title is required")
        todo = icalendar.Todo()
        todo.add("UID", _new_uid())
        todo.add("DTSTAMP", datetime.now(UTC).replace(microsecond=0))
        todo.add("SUMMARY", data.title)
        if data.notes:
            todo.add("DESCRIPTION", data.notes)
        if data.due is not None:
            todo.add("DUE", _task_due(data.due))
        todo.add("STATUS", "NEEDS-ACTION")
        if data.completed:
            _mark_completed(todo, True)
        with self._dav():
            cal = self._find(list_id, "VTODO")
            obj = cal.add_todo(_vcalendar(todo))
            return self._task_info(cal, obj)

    def _writable_task(self, list_id: str, task_id: str):
        cal = self._find(list_id, "VTODO")
        obj = cal.get_todo_by_uid(task_id)
        obj.load()  # fresh copy and its ETag: the write below is conditional on it
        if _is_read_only(obj):
            raise PimError(f"task {task_id!r} {READ_ONLY}")
        return cal, obj

    def update_task(self, list_id: str, task_id: str, data: TaskInput) -> TaskInfo:
        with self._dav():
            cal, obj = self._writable_task(list_id, task_id)
            with obj.edit_icalendar_instance() as ical:
                comp = _main_component(ical)
                if data.title is not None:
                    if not data.title:
                        raise PimError("title must not be empty")
                    _set(comp, "SUMMARY", data.title)
                if data.notes is not None:
                    _set(comp, "DESCRIPTION", data.notes)
                if data.due is not None:
                    comp.pop("DURATION", None)
                    _set(comp, "DUE", _task_due(data.due))
                if data.completed is not None:
                    _mark_completed(comp, data.completed)
                _set(comp, "DTSTAMP", datetime.now(UTC).replace(microsecond=0))
                ical.add_missing_timezones()
            obj.save()
            return self._task_info(cal, obj)

    def delete_task(self, list_id: str, task_id: str) -> None:
        with self._dav():
            _, obj = self._writable_task(list_id, task_id)
            self._delete(obj)
