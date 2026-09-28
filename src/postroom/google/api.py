"""Google Calendar, Tasks and People (contacts) REST backends for Google accounts.

`GoogleApi` offers the same method set as `CalDavBackend` plus `search_contacts`.

Safety rules (see the PIM safety rules in the plan):
- Every Calendar write passes `sendUpdates=none`, and no request body ever carries
  `attendees` or `conferenceData`, so Google never emails anyone.
- Events that have attendees or are recurring (`recurrence` / `recurringEventId`) are
  read-only: update/delete fetch the event first and refuse before writing.
- Events are written only to the account's own calendars (`_own_calendar`): the primary
  calendar, or a secondary calendar in the account's calendarList whose `dataOwner` is
  the account. Google authorises writes by ACL, so without this check any calendar a
  third party shared with the account (writer or owner role) would be writable by id,
  a channel to exfiltrate data into someone else's calendar.
- Access tokens come from `GoogleOAuth` and are sent only in the Authorization header;
  error messages carry Google's status and error message, never tokens.
"""

import re
from datetime import UTC, date, datetime, time
from urllib.parse import quote

import httpx

from postroom.google.oauth import GoogleOAuth, GoogleOAuthError
from postroom.mail.imap import AuthFailed
from postroom.pim.models import (
    TZ,
    CalendarInfo,
    ContactInfo,
    EventInfo,
    EventInput,
    PimError,
    TaskInfo,
    TaskInput,
    TaskListInfo,
    aware,
    is_all_day,
    rescheduled,
    validate_range,
)

CAL = "https://www.googleapis.com/calendar/v3"
TASKS = "https://tasks.googleapis.com/tasks/v1"
PEOPLE = "https://people.googleapis.com/v1"

MAX_ITEMS = 500
MAX_PAGES = 20
NO_INVITES = {"sendUpdates": "none"}
READ_ONLY = "is read-only for this server (has attendees / is recurring)"
NOT_OWN_CALENDAR = (
    "is not one of this account's own calendars; events can only be written to the "
    "primary calendar or to calendars the account owns"
)
RECONNECT = "Google account needs reconnect"
CHANGED = "item changed on the server; fetch it again"

_CONTACT_MASK = "names,emailAddresses,phoneNumbers,organizations"
_OTHER_CONTACT_MASK = "names,emailAddresses,phoneNumbers"


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _seg(value: str, what: str = "id", allow_hash: bool = False) -> str:
    """One validated, percent-encoded URL path segment.

    httpx normalises `.` and `..` segments away, so `event_id=".."` would turn
    `calendars/<cal>/events/..` into `calendars/<cal>` and a DELETE would remove the
    whole calendar. Ids that are empty, dot segments, or contain a path, query or
    escape character or a control character are refused before any request. Only
    calendar ids may contain `#` (Google's holiday/birthday calendars do); it is
    percent-encoded.
    """
    forbidden = "/\\?%" if allow_hash else "/\\?%#"
    if (
        not isinstance(value, str)
        or value in ("", ".", "..")
        or any(c in forbidden for c in value)
        or _CONTROL.search(value)
    ):
        raise PimError(f"invalid {what}: {str(value)[:100]!r}")
    return quote(value, safe="@")


def _cal(value: str) -> str:
    return _seg(value, "calendar_id", allow_hash=True)


def _error_message(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error")
    except (ValueError, AttributeError):
        return ""
    msg = err.get("message") if isinstance(err, dict) else None
    return msg[:300] if isinstance(msg, str) else ""


def _rfc3339(value: datetime | date) -> str:
    if isinstance(value, datetime):
        return aware(value).isoformat()
    return datetime.combine(value, time(), tzinfo=TZ).isoformat()


def _when(value: datetime | date) -> dict:
    if is_all_day(value):
        return {"date": value.isoformat()}
    return {"dateTime": aware(value).isoformat(), "timeZone": "Europe/Prague"}


def _patch_when(value: datetime | date) -> dict:
    """`_when` for a PATCH: the other keys are nulled so all-day <-> timed switches work."""
    return {"date": None, "dateTime": None, "timeZone": None, **_when(value)}


def _parse_when(when: dict | None) -> datetime | date | None:
    when = when or {}
    try:
        if when.get("date"):
            return date.fromisoformat(when["date"])
        if when.get("dateTime"):
            return aware(datetime.fromisoformat(when["dateTime"]))
    except (TypeError, ValueError):
        return None
    return None


def _sort_instant(when: dict | None) -> datetime:
    value = _parse_when(when)
    if value is None:
        return datetime.max.replace(tzinfo=UTC)
    if isinstance(value, datetime):
        return value
    return datetime.combine(value, time(), tzinfo=TZ)


def _if_match(item: dict) -> dict:
    """Make a write conditional on the copy just fetched (412 if it changed since)."""
    etag = item.get("etag")
    return {"If-Match": etag} if isinstance(etag, str) and etag else {}


def _is_read_only(item: dict) -> bool:
    return bool(item.get("attendees") or item.get("recurrence") or item.get("recurringEventId"))


def _due(value: str | None) -> str | None:
    """Google Tasks' RFC 3339 `due` back to `YYYY-MM-DD` (only the date is meaningful)."""
    return value[:10] if isinstance(value, str) and value else None


def _task_due(value: date) -> str:
    day = value.date() if isinstance(value, datetime) else value
    return f"{day.isoformat()}T00:00:00.000Z"


class GoogleApi:
    def __init__(self, account: str, oauth: GoogleOAuth, http: httpx.Client | None = None):
        self.account = account
        self._oauth = oauth
        self._owns_http = http is None
        self._http = http or httpx.Client(timeout=30)
        self._needs_reconnect = False
        self._contacts_warmed_up = False

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    # -- plumbing ---------------------------------------------------------------

    def _token(self) -> str:
        if self._needs_reconnect:
            raise PimError(RECONNECT)
        try:
            return self._oauth.access_token(self.account)
        except AuthFailed as e:
            self._needs_reconnect = True
            raise PimError(RECONNECT) from e
        except GoogleOAuthError as e:
            raise PimError(str(e)) from e

    def _request(self, method: str, url: str, **kw) -> dict:
        headers = dict(kw.pop("headers", None) or {})
        for attempt in range(2):
            headers["Authorization"] = f"Bearer {self._token()}"
            try:
                resp = self._http.request(method, url, headers=headers, **kw)
            except httpx.HTTPError as e:
                raise PimError(f"Google API error: {type(e).__name__}") from e
            if resp.status_code == 401 and attempt == 0:
                self._oauth.invalidate(self.account)
                continue
            break
        if resp.status_code == 412:
            raise PimError(CHANGED)
        if resp.status_code >= 400:
            msg = _error_message(resp)
            raise PimError(f"Google API error {resp.status_code}" + (f": {msg}" if msg else ""))
        if not resp.content:
            return {}
        try:
            data = resp.json()
        except ValueError as e:
            raise PimError("Google API returned an invalid response") from e
        return data if isinstance(data, dict) else {}

    def _paged(self, url: str, params: dict, cap: int = MAX_ITEMS) -> list[dict]:
        items: list[dict] = []
        params = dict(params)
        for _ in range(MAX_PAGES):
            data = self._request("GET", url, params=params)
            items.extend(i for i in data.get("items", []) if isinstance(i, dict))
            token = data.get("nextPageToken")
            if not token or len(items) >= cap:
                break
            params["pageToken"] = token
        return items[:cap]

    # -- calendars & events -----------------------------------------------------

    def _calendar_items(self) -> list[dict]:
        return self._paged(f"{CAL}/users/me/calendarList", {"maxResults": 250})

    def _owners(self, items: list[dict]) -> set[str]:
        """Who "the account" is in `dataOwner`: its address and its primary calendar id."""
        me = {self.account.lower()}
        me.update(str(it["id"]).lower() for it in items if it.get("primary") and it.get("id"))
        return me

    @staticmethod
    def _is_own(item: dict, owners: set[str]) -> bool:
        if item.get("primary"):
            return True
        owner = item.get("dataOwner")
        return (
            item.get("accessRole") == "owner" and isinstance(owner, str) and owner.lower() in owners
        )

    def _own_calendar(self, calendar_id: str | None) -> str:
        """`calendar_id` (default: primary) after checking the account owns it.

        Rule: the primary calendar, or a calendar in the account's own calendarList with
        accessRole `owner` and `dataOwner` equal to the account. Calendars shared into the
        account by someone else (writer, or owner role granted by a third party), read-only
        ones and ids not in the calendarList are refused before any event request.
        """
        if not calendar_id or calendar_id == "primary":
            return "primary"
        _cal(calendar_id)  # validate before the calendarList request
        items = self._calendar_items()
        owners = self._owners(items)
        if any(it.get("id") == calendar_id and self._is_own(it, owners) for it in items):
            return calendar_id
        raise PimError(f"calendar {calendar_id[:100]!r} {NOT_OWN_CALENDAR}")

    def list_calendars(self) -> list[CalendarInfo]:
        items = [it for it in self._calendar_items() if it.get("id")]
        owners = self._owners(items)
        return [
            CalendarInfo(
                account=self.account,
                id=it["id"],
                name=it.get("summaryOverride") or it.get("summary") or it["id"],
                read_only=not self._is_own(it, owners),
                primary=bool(it.get("primary")),
            )
            for it in items
        ]

    def _event_info(self, calendar_id: str, item: dict) -> EventInfo:
        start, end = item.get("start") or {}, item.get("end") or {}
        return EventInfo(
            account=self.account,
            calendar_id=calendar_id,
            id=item.get("id", ""),
            title=item.get("summary") or "",
            start=start.get("date") or start.get("dateTime") or "",
            end=end.get("date") or end.get("dateTime"),
            all_day="date" in start,
            location=item.get("location") or None,
            description=item.get("description") or None,
            recurring=bool(item.get("recurringEventId") or item.get("recurrence")),
            has_attendees=bool(item.get("attendees")),
            status=item.get("status"),
        )

    def list_events(
        self, calendar_id: str | None, start: datetime, end: datetime, query: str | None
    ) -> list[EventInfo]:
        if calendar_id:
            cal_ids = [calendar_id]
        else:
            cal_ids = [
                it["id"]
                for it in self._calendar_items()
                if it.get("id")
                and (it.get("selected") or it.get("primary"))
                and it.get("accessRole") != "freeBusyReader"
            ]
        params = {
            "timeMin": _rfc3339(start),
            "timeMax": _rfc3339(end),
            "singleEvents": "true",
            "orderBy": "startTime",
            "maxResults": 250,
        }
        if query:
            params["q"] = query
        found: list[tuple[datetime, EventInfo]] = []
        for cal_id in cal_ids:
            for item in self._paged(f"{CAL}/calendars/{_cal(cal_id)}/events", params):
                found.append((_sort_instant(item.get("start")), self._event_info(cal_id, item)))
        found.sort(key=lambda kv: kv[0])
        return [info for _, info in found[:MAX_ITEMS]]

    def create_event(self, calendar_id: str | None, data: EventInput) -> EventInfo:
        if not data.title or data.start is None or data.end is None:
            raise PimError("title, start and end are required")
        try:
            validate_range(data.start, data.end)
        except ValueError as e:
            raise PimError(str(e)) from e
        body: dict = {"summary": data.title, "start": _when(data.start), "end": _when(data.end)}
        if data.location:
            body["location"] = data.location
        if data.description:
            body["description"] = data.description
        target = self._own_calendar(calendar_id)
        item = self._request(
            "POST", f"{CAL}/calendars/{_cal(target)}/events", params=NO_INVITES, json=body
        )
        return self._event_info(calendar_id or "primary", item)

    def _writable_event(self, cal_id: str, event_id: str) -> tuple[str, dict]:
        """The event's URL and fresh copy; refuses read-only events before any write.

        Only events in the account's own calendars can be changed or deleted.
        """
        event_seg = _seg(event_id, "event_id")
        url = f"{CAL}/calendars/{_cal(self._own_calendar(cal_id))}/events/{event_seg}"
        item = self._request("GET", url)
        if _is_read_only(item):
            raise PimError(f"event {event_id!r} {READ_ONLY}")
        return url, item

    def update_event(self, calendar_id: str, event_id: str, data: EventInput) -> EventInfo:
        cal_id = calendar_id or "primary"
        url, item = self._writable_event(cal_id, event_id)
        patch: dict = {}
        if data.title is not None:
            if not data.title:
                raise PimError("title must not be empty")
            patch["summary"] = data.title
        if data.location is not None:
            patch["location"] = data.location
        if data.description is not None:
            patch["description"] = data.description
        if data.start is not None or data.end is not None:
            try:
                start, end = rescheduled(
                    _parse_when(item.get("start")),
                    _parse_when(item.get("end")),
                    data.start,
                    data.end,
                )
            except ValueError as e:
                raise PimError(str(e)) from e
            patch["start"], patch["end"] = _patch_when(start), _patch_when(end)
        if not patch:
            return self._event_info(cal_id, item)
        updated = self._request(
            "PATCH", url, params=NO_INVITES, json=patch, headers=_if_match(item)
        )
        return self._event_info(cal_id, updated)

    def delete_event(self, calendar_id: str, event_id: str) -> None:
        url, item = self._writable_event(calendar_id or "primary", event_id)
        self._request("DELETE", url, params=NO_INVITES, headers=_if_match(item))

    # -- tasks ------------------------------------------------------------------

    def _task_info(self, list_id: str, item: dict) -> TaskInfo:
        return TaskInfo(
            account=self.account,
            list_id=list_id,
            id=item.get("id", ""),
            title=item.get("title") or "",
            notes=item.get("notes") or None,
            due=_due(item.get("due")),
            completed=item.get("status") == "completed",
            completed_at=item.get("completed") or None,
        )

    def _task_list_items(self) -> list[dict]:
        return self._paged(f"{TASKS}/users/@me/lists", {"maxResults": 100})

    def list_task_lists(self) -> list[TaskListInfo]:
        return [
            TaskListInfo(account=self.account, id=it["id"], name=it.get("title") or it["id"])
            for it in self._task_list_items()
            if it.get("id")
        ]

    def list_tasks(self, list_id: str | None, include_completed: bool) -> list[TaskInfo]:
        list_ids = [list_id] if list_id else [it["id"] for it in self._task_list_items()]
        flag = "true" if include_completed else "false"
        params = {"showCompleted": flag, "showHidden": flag, "maxResults": 100}
        tasks = [
            self._task_info(lid, item)
            for lid in list_ids
            for item in self._paged(f"{TASKS}/lists/{_seg(lid, 'list_id')}/tasks", params)
            if not item.get("deleted")
        ]
        tasks.sort(key=lambda t: (t.completed, t.due is None, t.due or "", t.title.casefold()))
        return tasks[:MAX_ITEMS]

    def create_task(self, list_id: str | None, data: TaskInput) -> TaskInfo:
        if not data.title:
            raise PimError("title is required")
        body: dict = {"title": data.title}
        if data.notes:
            body["notes"] = data.notes
        if data.due is not None:
            body["due"] = _task_due(data.due)
        if data.completed:
            body["status"] = "completed"
        lid = list_id or "@default"
        url = f"{TASKS}/lists/{_seg(lid, 'list_id')}/tasks"
        item = self._request("POST", url, json=body)
        return self._task_info(lid, item)

    def update_task(self, list_id: str, task_id: str, data: TaskInput) -> TaskInfo:
        body: dict = {}
        if data.title is not None:
            if not data.title:
                raise PimError("title must not be empty")
            body["title"] = data.title
        if data.notes is not None:
            body["notes"] = data.notes
        if data.due is not None:
            body["due"] = _task_due(data.due)
        if data.completed is True:
            body["status"] = "completed"
        elif data.completed is False:
            body["status"] = "needsAction"
            body["completed"] = None
        lid = list_id or "@default"
        url = f"{TASKS}/lists/{_seg(lid, 'list_id')}/tasks/{_seg(task_id, 'task_id')}"
        item = self._request("PATCH", url, json=body)
        return self._task_info(lid, item)

    def delete_task(self, list_id: str, task_id: str) -> None:
        lid = list_id or "@default"
        url = f"{TASKS}/lists/{_seg(lid, 'list_id')}/tasks/{_seg(task_id, 'task_id')}"
        self._request("DELETE", url)

    # -- contacts ---------------------------------------------------------------

    def _warm_up_contacts(self) -> None:
        """Google's contact search needs an empty warm-up query to refresh its cache."""
        if self._contacts_warmed_up:
            return
        self._contacts_warmed_up = True
        for url in (f"{PEOPLE}/people:searchContacts", f"{PEOPLE}/otherContacts:search"):
            try:
                self._request("GET", url, params={"query": "", "readMask": "names"})
            except PimError:
                if self._needs_reconnect:
                    raise

    @staticmethod
    def _person(result: dict) -> dict:
        person = result.get("person") if isinstance(result, dict) else None
        return person if isinstance(person, dict) else {}

    def _contact(self, person: dict) -> ContactInfo:
        def values(key: str, field: str) -> list[str]:
            return [
                str(v[field]).strip()
                for v in person.get(key) or []
                if isinstance(v, dict) and str(v.get(field) or "").strip()
            ]

        names = values("names", "displayName")
        orgs = values("organizations", "name")
        return ContactInfo(
            account=self.account,
            name=names[0] if names else "",
            emails=values("emailAddresses", "value"),
            phones=values("phoneNumbers", "value"),
            organization=orgs[0] if orgs else None,
        )

    def search_contacts(self, query: str, limit: int = 20) -> list[ContactInfo]:
        if limit <= 0:
            return []
        self._warm_up_contacts()
        page = min(limit, 30)
        sources = [
            (f"{PEOPLE}/people:searchContacts", _CONTACT_MASK),
            (f"{PEOPLE}/otherContacts:search", _OTHER_CONTACT_MASK),
        ]
        out: list[ContactInfo] = []
        seen: set[str] = set()
        for url, mask in sources:
            data = self._request(
                "GET", url, params={"query": query, "readMask": mask, "pageSize": page}
            )
            for result in data.get("results") or []:
                contact = self._contact(self._person(result))
                key = contact.emails[0].casefold() if contact.emails else contact.name.casefold()
                if not key or key in seen:
                    continue
                seen.add(key)
                out.append(contact)
                if len(out) >= limit:
                    return out
        return out
