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
class OutgoingFile:
    """An attachment of an email being sent (already validated)."""

    filename: str
    content_type: str
    data: bytes


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


@dataclasses.dataclass
class SendResult:
    """Outcome of a send: the email went out; the rest is bookkeeping around it."""

    account: str
    message_id: str
    recipients: int
    saved_to_sent: bool
    sent_folder: str | None
    warnings: list[str] = dataclasses.field(default_factory=list)
    draft_removed: bool | None = None  # send_draft only

    def to_dict(self) -> dict:
        d = _json_safe(dataclasses.asdict(self))
        if self.draft_removed is None:
            del d["draft_removed"]
        return d


@dataclasses.dataclass(frozen=True)
class MessageRef:
    """One email, as search_emails returns it: account, folder (name or alias) and UID."""

    account: str
    folder: str
    uid: int


@dataclasses.dataclass
class RefGroup:
    """Emails of one account and folder that share an outcome (why skipped / failed)."""

    account: str
    folder: str
    uids: list[int]
    message: str


@dataclasses.dataclass
class BatchResult:
    """Outcome of one change over many emails: how many were changed, which were left as
    they were and why, and which failed and why (grouped per account, folder and reason)."""

    updated: int = 0
    skipped: list[RefGroup] = dataclasses.field(default_factory=list)
    failed: list[RefGroup] = dataclasses.field(default_factory=list)
    # account -> the folder its emails were moved to (move / trash only)
    destinations: dict[str, str] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict:
        def group(g: RefGroup, key: str) -> dict:
            return {"account": g.account, "folder": g.folder, "uids": g.uids, key: g.message}

        d: dict = {
            "updated": self.updated,
            "skipped": [group(g, "reason") for g in self.skipped],
            "failed": [group(g, "error") for g in self.failed],
        }
        if self.destinations:
            d["moved_to"] = dict(self.destinations)
        return _json_safe(d)
