"""Dataclasses for parsed mail, folder/message summaries, search and drafts.

All models are plain `@dataclass` types with a `to_dict()` that returns a
JSON-safe dict (built on top of `dataclasses.asdict`). Fields named `from_`
(a trailing underscore to dodge the `from` keyword) are renamed back to
`from` in `to_dict()`.
"""

import dataclasses
from datetime import date


def _json_safe(value):
    """Recursively coerce a value into something `json.dumps` can handle.

    `dataclasses.asdict` leaves non-dataclass leaves (like `datetime.date`) untouched,
    so every `to_dict()` below routes its result through this to turn dates into
    ISO-8601 strings.
    """
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


@dataclasses.dataclass
class AttachmentInfo:
    index: int
    filename: str | None
    content_type: str
    size: int
    inline: bool
    # Declared charset of a text part (used to decode it); not part of the public dict.
    charset: str | None = None

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        del data["charset"]
        return _json_safe(data)


@dataclasses.dataclass
class ParsedMessage:
    subject: str
    from_: str
    to: list[str]
    cc: list[str]
    reply_to: list[str]
    date: str | None
    message_id: str | None
    in_reply_to: str | None
    references: list[str]
    body_text: str
    body_source: str  # "plain" | "html" | "none"
    attachments: list[AttachmentInfo]

    def to_dict(self) -> dict:
        d = _json_safe(dataclasses.asdict(self))
        d["from"] = d.pop("from_")
        return d


@dataclasses.dataclass
class FolderInfo:
    name: str
    special_use: str | None
    flags: list[str]
    messages: int | None = None
    unseen: int | None = None

    def to_dict(self) -> dict:
        return _json_safe(dataclasses.asdict(self))


@dataclasses.dataclass
class MessageSummary:
    account: str
    folder: str
    uid: int
    date: str | None
    from_: str
    to: list[str]
    subject: str
    seen: bool
    size: int | None
    has_attachments: bool
    thread_id: str | None = None

    def to_dict(self) -> dict:
        d = _json_safe(dataclasses.asdict(self))
        d["from"] = d.pop("from_")
        return d


@dataclasses.dataclass
class MessageDetail:
    summary: MessageSummary
    message: ParsedMessage
    truncated: bool

    def to_dict(self) -> dict:
        d = self.summary.to_dict()
        d.update(self.message.to_dict())
        d["truncated"] = self.truncated
        return d


@dataclasses.dataclass
class SearchCriteria:
    query: str | None = None
    sender: str | None = None
    recipient: str | None = None
    subject: str | None = None
    since: date | None = None
    before: date | None = None
    unread_only: bool = False
    has_attachment: bool = False

    def to_dict(self) -> dict:
        return _json_safe(dataclasses.asdict(self))


@dataclasses.dataclass
class AccountError:
    account: str
    error: str

    def to_dict(self) -> dict:
        return _json_safe(dataclasses.asdict(self))


@dataclasses.dataclass
class SearchResult:
    results: list[MessageSummary]
    errors: list[AccountError]

    def to_dict(self) -> dict:
        return _json_safe(
            {
                "results": [r.to_dict() for r in self.results],
                "errors": [e.to_dict() for e in self.errors],
            }
        )


@dataclasses.dataclass
class DraftResult:
    account: str
    folder: str
    message_id: str

    def to_dict(self) -> dict:
        return _json_safe(dataclasses.asdict(self))
