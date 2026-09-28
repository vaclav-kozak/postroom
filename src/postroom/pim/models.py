"""Calendar, task and contact models shared by the CalDAV/CardDAV and Google backends.

Dates and times cross the MCP boundary as ISO 8601 strings: `YYYY-MM-DD` for all-day
values, full date-times with a UTC offset otherwise. Naive date-times are read in the
server's configured time zone (`POSTROOM_TIMEZONE`), which callers pass in as `tz`.
"""

import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, tzinfo

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


class PimError(Exception):
    """A calendar/task/contact operation failed. The message is safe to show (no secrets)."""


class _ToDict:
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CalendarInfo(_ToDict):
    account: str
    id: str
    name: str
    read_only: bool
    primary: bool = False


@dataclass
class EventInfo(_ToDict):
    account: str
    calendar_id: str
    id: str
    title: str
    start: str
    end: str | None
    all_day: bool
    location: str | None
    description: str | None
    recurring: bool
    has_attendees: bool
    status: str | None = None


@dataclass
class EventInput(_ToDict):
    title: str | None = None
    start: datetime | date | None = None
    end: datetime | date | None = None
    location: str | None = None
    description: str | None = None


@dataclass
class TaskListInfo(_ToDict):
    account: str
    id: str
    name: str


@dataclass
class TaskInfo(_ToDict):
    account: str
    list_id: str
    id: str
    title: str
    notes: str | None
    due: str | None
    completed: bool
    completed_at: str | None


@dataclass
class TaskInput(_ToDict):
    title: str | None = None
    notes: str | None = None
    due: date | None = None
    completed: bool | None = None


@dataclass
class ContactInfo(_ToDict):
    account: str
    name: str
    emails: list[str]
    phones: list[str]
    organization: str | None


def parse_when(value: str, tz: tzinfo) -> datetime | date:
    """Parse `YYYY-MM-DD` into a `date`, an ISO date-time into an aware `datetime`.

    Naive date-times are taken as local time in `tz`.
    """
    s = value.strip() if isinstance(value, str) else ""
    try:
        if _DATE_RE.match(s):
            return date.fromisoformat(s)
        if _DATETIME_RE.match(s):
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=tz)
    except ValueError:
        pass
    raise ValueError(f"invalid date/time: {str(value)[:100]!r}")


def iso(value: datetime | date | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    return value.isoformat()


def aware(value: datetime, tz: tzinfo) -> datetime:
    """Attach `tz` to a naive datetime; leave aware ones alone."""
    return value if value.tzinfo is not None else value.replace(tzinfo=tz)


def is_all_day(value: datetime | date) -> bool:
    return isinstance(value, date) and not isinstance(value, datetime)


def validate_range(start: datetime | date, end: datetime | date, tz: tzinfo) -> None:
    """Require `end` after `start`, both dates (all-day) or both date-times.

    A naive date-time is compared as local time in `tz`.
    """
    for v in (start, end):
        if not isinstance(v, date):
            raise TypeError("start and end must be dates or date-times")
    if is_all_day(start) != is_all_day(end):
        raise ValueError("start and end must both be dates (all-day) or both date-times")
    if isinstance(start, datetime):
        start, end = aware(start, tz), aware(end, tz)
    if end <= start:
        raise ValueError("end must be after start")


def rescheduled(
    old_start: datetime | date | None,
    old_end: datetime | date | None,
    new_start: datetime | date | None,
    new_end: datetime | date | None,
    tz: tzinfo,
) -> tuple[datetime | date, datetime | date]:
    """The (start, end) of an event after an update that sets `new_start`/`new_end`.

    A new start without a new end moves the event and keeps its duration. Naive
    date-times are local time in `tz`. Raises `ValueError` when the result is not a
    valid range.
    """
    start = new_start if new_start is not None else old_start
    end = new_end
    if end is None:
        if new_start is None or old_start is None or old_end is None:
            end = old_end
        elif is_all_day(new_start) != is_all_day(old_start):
            raise ValueError("give both start and end when switching between all-day and timed")
        elif is_all_day(old_start):
            end = new_start + (old_end - old_start)
        else:
            end = new_start + (aware(old_end, tz) - aware(old_start, tz))
    if start is None or end is None:
        raise ValueError("the event needs both a start and an end")
    validate_range(start, end, tz)
    return start, end
