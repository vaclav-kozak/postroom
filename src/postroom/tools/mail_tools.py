"""MCP mail tools: accounts, folders, search, read, thread, attachment, draft, organising
(mark read / flagged, move, trash, create folder) and sending (send, forward, send a draft).

The read tools never change anything (an email is not even marked read). `create_draft`
only saves a draft in the Drafts folder. The organising tools work only on accounts whose
mail access level is "organize" or "full" (set by the owner per account); trash moves to
the Trash folder. No tool deletes mail permanently: send_draft removes only the draft it
has just sent. The sending tools work only on
accounts with access level "full" and an outgoing (SMTP) server; they send immediately and
are never retried automatically, so a send is never duplicated by the server.

Errors the model can act on (unknown account, missing folder or message, bad argument,
unreachable server) are raised as `ToolError` carrying only the exception's message.
Those messages are built to be secret-free; anything unexpected is left for FastMCP to
report (masked by `build_mcp`).
"""

import asyncio
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.utilities.types import Image
from pydantic import BaseModel, ConfigDict, Field

from postroom.accounts import AccountRepo, MailAccessDenied, SendingDisabled
from postroom.google.oauth import GoogleOAuthError
from postroom.mail.folders import FolderNotFound
from postroom.mail.heavy import ServerBusy, heavy_work
from postroom.mail.imap import ImapError
from postroom.mail.models import AttachmentInfo, MessageRef, SearchCriteria
from postroom.mail.outgoing import (
    MAX_ATTACHMENTS,
    MAX_RECIPIENTS,
    DuplicateSend,
    SendLimitExceeded,
    SendTimeout,
)
from postroom.mail.parse import truncate
from postroom.mail.pdf import PdfTooComplex, extract_text_isolated
from postroom.mail.service import MAX_BATCH_REFS, MAX_SEARCH_OFFSET, PARTIAL_TIMEOUT, MailService
from postroom.mail.smtp import SmtpError

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}
WRITES_DRAFT = {"readOnlyHint": False, "destructiveHint": False}
MODIFIES = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True}
MOVES = {"readOnlyHint": False, "destructiveHint": True}
CREATES = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False}
SENDS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}

MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # spec §4 size cap: bigger → metadata only
MAX_IMAGE_BYTES = 5 * 1024 * 1024
# PDF text extraction runs pypdf on untrusted input: bound its size, pages and time (its
# memory is bounded by the child process in postroom.mail.pdf).
MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PDF_PAGES = 50
PDF_TIMEOUT_SECONDS = 20
IMAGE_FORMATS = {"png": "png", "jpeg": "jpeg", "jpg": "jpeg", "gif": "gif", "webp": "webp"}
# Most text one call returns: more only bloats the JSON reply and the model's context.
MAX_CHARS = 200_000

_CLIENT_ERRORS = (
    ImapError,
    FolderNotFound,
    LookupError,
    ValueError,
    GoogleOAuthError,
    ServerBusy,
    MailAccessDenied,
    SendingDisabled,
    SendLimitExceeded,
    DuplicateSend,
    SmtpError,
)
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _message(e: Exception) -> str:
    if isinstance(e, KeyError):  # str(KeyError) is the repr of the key, not a message
        arg = e.args[0] if e.args else None
        return arg if isinstance(arg, str) and arg else "not found"
    return str(e) or type(e).__name__


TIMEOUT_MESSAGE = "the mail server did not respond in time; try again later"
# A write that timed out may still have landed: "try again" would make a duplicate draft.
DRAFT_TIMEOUT_MESSAGE = (
    "the mail server did not respond in time; the draft may or may not have been saved; "
    "check the Drafts folder before trying again"
)

# A batch change that timed out may have been applied to some of the emails.
ORGANIZE_TIMEOUT_MESSAGE = PARTIAL_TIMEOUT
CREATE_FOLDER_TIMEOUT_MESSAGE = (
    "the mail server did not respond in time; the folder may or may not have been created; "
    "check list_folders before trying again"
)


# A send that timed out after it started may already be out: retrying could send it twice.
SEND_TIMEOUT_MESSAGE = (
    "the mail server did not respond in time; the email may already have been sent. Do not "
    "retry automatically; check the Sent folder (search_emails folder='sent'), and ask the "
    "owner if it's not there"
)
# A timeout before the send started (e.g. reading the email being answered).
PRESEND_TIMEOUT_MESSAGE = "the mail server did not respond in time; nothing was sent"


class Attachment(BaseModel):
    """A file to attach to an email being sent."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(max_length=1000, description="The file name, e.g. report.pdf.")
    content_type: str | None = Field(
        default=None,
        max_length=255,
        description="MIME type such as application/pdf; default application/octet-stream.",
    )
    content_base64: str = Field(description="The file's content, base64-encoded.")


Recipients = Annotated[list[str], Field(max_length=MAX_RECIPIENTS)]
Attachments = Annotated[list[Attachment], Field(max_length=MAX_ATTACHMENTS)]


class EmailRef(BaseModel):
    """One email, as search_emails / get_thread return it (other fields are ignored)."""

    model_config = ConfigDict(extra="ignore")

    account: str = Field(description="The account's email address.")
    folder: str = Field(description="The folder the email is in, as returned by search_emails.")
    uid: int = Field(ge=1, description="The email's uid in that folder.")


# The batch cap is part of the input schema (maxItems), so a client knows it up front.
EmailRefs = Annotated[list[EmailRef], Field(min_length=1, max_length=MAX_BATCH_REFS)]


def _refs(emails: list[EmailRef]) -> list[MessageRef]:
    return [MessageRef(_norm(e.account), e.folder, e.uid) for e in emails]


@contextmanager
def _tool_errors(timeout_message: str = TIMEOUT_MESSAGE) -> Iterator[None]:
    """Turn expected mail errors into clean `ToolError`s (message only, no traceback)."""
    try:
        yield
    except SendTimeout as e:
        raise ToolError(SEND_TIMEOUT_MESSAGE) from e
    except TimeoutError as e:
        raise ToolError(timeout_message) from e
    except _CLIENT_ERRORS as e:
        raise ToolError(_message(e)) from e


def _norm(account: str) -> str:
    return account.strip().lower()


def _check_max_chars(max_chars: int) -> None:
    if not 1 <= max_chars <= MAX_CHARS:
        raise ValueError(f"max_chars must be between 1 and {MAX_CHARS}")


def _parse_date(name: str, value: str | None) -> date | None:
    if value is None or value == "":
        return None
    if not _ISO_DATE.fullmatch(value):
        raise ValueError(f"{name} must be a date in YYYY-MM-DD format, got {value!r}")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{name} is not a valid date: {value!r}") from None


def _pdf_text(data: bytes, max_chars: int) -> tuple[str, int | None]:
    """Extracted text, plus the total page count when pages beyond MAX_PDF_PAGES were skipped.

    pypdf runs in a memory-limited child process that is killed after PDF_TIMEOUT_SECONDS
    (see `postroom.mail.pdf`), one extraction at a time. Blocks: run it in a thread.
    """
    with heavy_work():
        return extract_text_isolated(data, max_chars, MAX_PDF_PAGES, PDF_TIMEOUT_SECONDS)


def _decode_text(data: bytes, charset: str | None) -> str:
    """Decode a text attachment with its declared charset (unknown or missing: UTF-8)."""
    try:
        return data.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _metadata(info: AttachmentInfo, note: str) -> dict:
    return {**info.to_dict(), "note": note}


async def _render_attachment(info: AttachmentInfo, data: bytes | None, max_chars: int):
    if data is None:  # a part of a big message beyond the service's fetch cap
        return _metadata(
            info, "Attachment is too large to download; only its metadata is returned."
        )
    size = len(data)
    content_type = info.content_type.lower()
    maintype, _, subtype = content_type.partition("/")

    if size > MAX_ATTACHMENT_BYTES:
        return _metadata(info, "Attachment is larger than 10 MB; only its metadata is returned.")

    if maintype == "text":
        text, _ = truncate(_decode_text(data, info.charset), max_chars)
        return {"filename": info.filename, "content_type": info.content_type, "text": text}

    if content_type == "application/pdf":
        if size > MAX_PDF_BYTES:
            return _metadata(
                info, "PDF is larger than 5 MB; its text is not extracted, only metadata returned."
            )
        try:
            raw_text, page_count = await asyncio.to_thread(_pdf_text, data, max_chars)
        except TimeoutError:
            return _metadata(info, "PDF text extraction timed out; only metadata is returned.")
        except ServerBusy:
            raise  # a clean "try again" error, not a verdict on the file
        except PdfTooComplex:
            return _metadata(
                info, "This PDF is too complex to extract text from; only metadata is returned."
            )
        except Exception:  # noqa: BLE001 -- PdfError, or anything unexpected around the child
            return _metadata(info, "Could not extract text from this PDF (encrypted or damaged).")
        if not raw_text.strip():
            return _metadata(info, "This PDF has no extractable text (it may be a scan).")
        text, _ = truncate(raw_text, max_chars)
        result = {"filename": info.filename, "content_type": info.content_type, "text": text}
        if page_count is not None:
            result["note"] = f"Text of the first {MAX_PDF_PAGES} of {page_count} pages only."
        return result

    if maintype == "image" and subtype in IMAGE_FORMATS:
        if size > MAX_IMAGE_BYTES:
            return _metadata(info, "Image is larger than 5 MB; only its metadata is returned.")
        return Image(data=data, format=IMAGE_FORMATS[subtype])

    return _metadata(
        info, f"Attachments of type {info.content_type} can't be displayed; metadata only."
    )


def register_mail_tools(mcp: FastMCP, repo: AccountRepo, mail: MailService) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def list_accounts() -> list[dict]:
        """List the owner's mail accounts.

        Use an account's `email` as the `account` argument of the other tools. `status`
        other than "connected" (e.g. "needs_reconnect") means the account can't be read
        until the owner fixes it in the admin UI; disabled accounts are never searched.
        `mail_access` is what the owner allows on the account's mail: "read" (read and
        create drafts), "organize" (also mark, move, trash, create folders) or "full"
        (also send). `capabilities` lists "mail.organize" / "mail.send" accordingly.
        """
        return [
            {
                "email": a.email,
                "name": a.display_name,
                "provider": a.provider.value,
                "status": a.status.value,
                "enabled": a.enabled,
                "capabilities": a.capabilities,
                "mail_access": a.mail_access.value,
                "last_error": a.last_error,
            }
            for a in repo.list()
        ]

    @mcp.tool(annotations=READ_ONLY)
    async def list_folders(account: str, with_counts: bool = False) -> list[dict]:
        """List an account's folders with their special use (sent, drafts, junk, …).

        with_counts=true adds total and unread message counts (slower on big mailboxes).
        """
        with _tool_errors():
            folders = await mail.list_folders(_norm(account), with_counts=with_counts)
        return [f.to_dict() for f in folders]

    @mcp.tool(annotations=READ_ONLY)
    async def search_emails(
        accounts: list[str] | None = None,
        folder: str = "inbox",
        query: str | None = None,
        sender: str | None = None,
        recipient: str | None = None,
        subject: str | None = None,
        since: str | None = None,
        before: str | None = None,
        unread_only: bool = False,
        has_attachment: bool = False,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """Search emails in one, several or all accounts; results are merged newest first.

        accounts: account emails to search; omit to search every enabled account.
        folder: a folder name or an alias — inbox, sent, drafts, archive, all (Gmail's
        All Mail), junk, trash.
        query: free text. Gmail accounts accept Gmail search syntax here
        (e.g. `has:attachment older_than:7d`); other servers match text anywhere in the email.
        sender / recipient / subject: match the From / To / Subject header.
        since / before: dates as YYYY-MM-DD (since is inclusive, before exclusive).
        limit: 1-100 results (default 20); offset: skip that many results to page (at
        most 1000; to go further back, narrow the search with since / before instead).

        Returns {"results": [...], "errors": [...]}: accounts that fail are listed in
        `errors` without failing the search. Pass a result's account, folder and uid to
        get_email or get_thread.
        """
        with _tool_errors():
            if not 0 <= offset <= MAX_SEARCH_OFFSET:
                raise ValueError(f"offset must be between 0 and {MAX_SEARCH_OFFSET}")
            criteria = SearchCriteria(
                query=query or None,
                sender=sender or None,
                recipient=recipient or None,
                subject=subject or None,
                since=_parse_date("since", since),
                before=_parse_date("before", before),
                unread_only=unread_only,
                has_attachment=has_attachment,
            )
            emails = [_norm(a) for a in accounts] if accounts else None
            result = await mail.search(emails, folder, criteria, limit=limit, offset=offset)
        return result.to_dict()

    @mcp.tool(annotations=READ_ONLY)
    async def get_email(account: str, folder: str, uid: int, max_chars: int = 20000) -> dict:
        """Read one email: headers, plain-text body and the list of attachments.

        account, folder and uid come from search_emails or get_thread. HTML bodies are
        converted to text; the body is cut at max_chars (at most 200000) with a truncation
        marker. Fetch an attachment with get_attachment using its `index`. The email is not
        marked read.
        """
        with _tool_errors():
            _check_max_chars(max_chars)
            detail = await mail.get_message(_norm(account), folder, uid, max_chars=max_chars)
        return detail.to_dict()

    @mcp.tool(annotations=READ_ONLY)
    async def get_thread(account: str, folder: str, uid: int) -> list[dict]:
        """List the conversation an email belongs to, as summaries oldest first.

        Gmail uses its native threads (results are in the All Mail folder); other servers
        match Message-ID/References headers in the given folder and in Sent. Each result
        carries its own folder and uid for get_email.
        """
        with _tool_errors():
            summaries = await mail.get_thread(_norm(account), folder, uid)
        return [s.to_dict() for s in summaries]

    @mcp.tool(annotations=READ_ONLY)
    async def get_attachment(
        account: str, folder: str, uid: int, index: int, max_chars: int = 50000
    ):
        """Fetch one attachment of an email by its `index` from get_email's attachment list.

        Text files and PDFs are returned as extracted text, cut at max_chars (at most
        200000). PNG, JPEG, GIF and WebP images up to 5 MB are returned as images. Other
        types, and any attachment over 10 MB, return metadata only.
        """
        with _tool_errors():
            _check_max_chars(max_chars)
            try:
                info, data = await mail.get_attachment(_norm(account), folder, uid, index)
            except KeyError as e:
                detail = e.args[0] if e.args and isinstance(e.args[0], str) else None
                raise ToolError(
                    detail
                    or f"attachment {index} not found; get_email lists the attachment indexes"
                ) from e
            return await _render_attachment(info, data, max_chars)

    @mcp.tool(annotations=WRITES_DRAFT)
    async def create_draft(
        account: str,
        to: list[str] | None = None,
        subject: str | None = None,
        body: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        html: bool = False,
        reply_to_folder: str | None = None,
        reply_to_uid: int | None = None,
    ) -> dict:
        """Save a draft in the account's Drafts folder for the owner to review.

        Nothing is sent: this is the review-first way to write an email. After the owner
        has reviewed a draft, send_draft can send it (on accounts that allow sending).
        to / cc / bcc are lists of email addresses; body is plain text, or HTML when
        html=true. A new email needs `to` and `subject`. To reply, pass reply_to_uid (and
        reply_to_folder, default inbox): the draft is threaded to the original, and `to` /
        `subject` default to the original sender and "Re: <subject>".
        Returns {"account", "folder", "message_id"}; find the draft's uid with
        search_emails folder='drafts'.
        """
        with _tool_errors(DRAFT_TIMEOUT_MESSAGE):
            result = await mail.create_draft(
                _norm(account),
                to=list(to or []),
                subject=subject,
                body=body,
                cc=cc,
                bcc=bcc,
                html=html,
                reply_folder=reply_to_folder,
                reply_uid=reply_to_uid,
            )
        return result.to_dict()

    @mcp.tool(annotations=MODIFIES)
    async def mark_emails(
        emails: EmailRefs, read: bool | None = None, flagged: bool | None = None
    ) -> dict:
        """Mark emails read or unread, and/or flag (star) or unflag them.

        emails: one or more {account, folder, uid}; search_emails results can be passed
        straight through, across accounts and folders (at most 500 per call).
        read: true = mark read, false = mark unread; flagged: true = star, false = unstar.
        Give at least one of them.

        Returns {"updated": n, "skipped": [], "failed": [{account, folder, uids, error}]}.
        Needs mail access "organize" or "full" on each account.
        """
        with _tool_errors(ORGANIZE_TIMEOUT_MESSAGE):
            result = await mail.set_flags(_refs(emails), read=read, flagged=flagged)
        return result.to_dict()

    @mcp.tool(annotations=MOVES)
    async def move_emails(emails: EmailRefs, to_folder: str) -> dict:
        """Move emails to another folder of the same account.

        emails: one or more {account, folder, uid}; search_emails results can be passed
        straight through, across accounts and folders (at most 500 per call).
        to_folder: a folder name, or an alias resolved per account: inbox, archive, junk,
        trash, all. "archive" archives the emails. On Gmail that removes them from the Inbox
        and keeps their other labels, also for emails passed from All Mail, a label folder
        or get_thread; emails that are not in the Inbox are skipped. Emails already in
        to_folder are reported as skipped.

        Returns {"updated": n, "skipped": [{account, folder, uids, reason}],
        "failed": [{account, folder, uids, error}], "moved_to": {account: folder}}.
        After a move the emails have new uids; search again to act on them.
        Needs mail access "organize" or "full" on each account.
        """
        with _tool_errors(ORGANIZE_TIMEOUT_MESSAGE):
            result = await mail.move(_refs(emails), to_folder)
        return result.to_dict()

    @mcp.tool(annotations=MOVES)
    async def trash_emails(emails: EmailRefs) -> dict:
        """Move emails to their account's Trash folder. It never deletes permanently;
        emails already in Trash are left there (reported as skipped).

        emails: one or more {account, folder, uid}; search_emails results can be passed
        straight through, across accounts and folders (at most 500 per call).

        Returns {"updated": n, "skipped": [...], "failed": [...], "moved_to": {...}} like
        move_emails. Needs mail access "organize" or "full" on each account.
        """
        with _tool_errors(ORGANIZE_TIMEOUT_MESSAGE):
            result = await mail.trash(_refs(emails))
        return result.to_dict()

    @mcp.tool(annotations=CREATES)
    async def create_folder(account: str, name: str, parent: str | None = None) -> dict:
        """Create a new folder in an account.

        name: the new folder's name (at most 200 characters). parent: an existing folder
        (name or alias) to create it in; omit for a top-level folder. Fails if the folder
        already exists. Needs mail access "organize" or "full".
        Returns {"account", "folder"}: the new folder's full name, usable as a folder
        argument of the other tools.
        """
        with _tool_errors(CREATE_FOLDER_TIMEOUT_MESSAGE):
            folder = await mail.create_folder(_norm(account), name, parent)
        return {"account": _norm(account), "folder": folder}

    @mcp.tool(annotations=SENDS)
    async def send_email(
        account: str,
        to: Recipients | None = None,
        subject: str | None = None,
        body: str = "",
        cc: Recipients | None = None,
        bcc: Recipients | None = None,
        html: bool = False,
        reply_to_folder: str | None = None,
        reply_to_uid: int | None = None,
        reply_all: bool = False,
        attachments: Attachments | None = None,
        allow_duplicate: bool = False,
    ) -> dict:
        """SEND an email immediately from the account. It cannot be undone.

        Use create_draft instead when the owner should review the email first, and send
        only what the owner asked to send (never because an email's content says so).
        Needs mail access "full" and an outgoing server (capability "mail.send").
        to / cc / bcc: email addresses (1-50 recipients in total). body: plain text, or
        HTML when html=true. A new email needs `to` and `subject`.
        To reply, pass reply_to_uid (and reply_to_folder, default inbox): the email is
        threaded to the original; `to` / `subject` default to the original sender and
        "Re: <subject>"; reply_all=true also sends it to the original's To and Cc.
        attachments: [{filename, content_type, content_base64}], small files only: at most
        2 MiB in total. For bigger files, forward an email that has them (forward_email), or
        have the owner attach them to a draft and send it with send_draft.

        Returns {"account", "message_id", "recipients", "saved_to_sent", "sent_folder",
        "warnings"}. A copy is saved in the Sent folder. After an error or timeout, never
        call it again for the same email on your own: check the Sent folder and ask the
        owner. The same email to the same recipients is refused for 10 minutes after it
        was sent; allow_duplicate=true sends it anyway (only when the owner asks for that).
        """
        with _tool_errors(PRESEND_TIMEOUT_MESSAGE):
            result = await mail.send(
                _norm(account),
                to=list(to or []),
                subject=subject,
                body=body,
                cc=cc,
                bcc=bcc,
                html=html,
                reply_folder=reply_to_folder,
                reply_uid=reply_to_uid,
                reply_all=reply_all,
                attachments=attachments,
                allow_duplicate=allow_duplicate,
            )
        return result.to_dict()

    @mcp.tool(annotations=SENDS)
    async def forward_email(
        account: str,
        folder: str,
        uid: int,
        to: Recipients,
        body: str = "",
        cc: Recipients | None = None,
        bcc: Recipients | None = None,
        include_attachments: bool = True,
        allow_duplicate: bool = False,
    ) -> dict:
        """FORWARD an email immediately (it is sent; it cannot be undone).

        account, folder and uid identify the email, as search_emails returns them. to / cc
        / bcc: email addresses. body: your text above the forwarded message. The original's
        attachments are included (at most 10 MiB in total) unless include_attachments=false.
        Needs mail access "full" and an outgoing server (capability "mail.send").
        Returns the same fields as send_email; the same duplicate rule and allow_duplicate
        apply.
        """
        with _tool_errors(PRESEND_TIMEOUT_MESSAGE):
            result = await mail.forward(
                _norm(account),
                folder,
                uid,
                to=list(to),
                cc=cc,
                bcc=bcc,
                body=body,
                include_attachments=include_attachments,
                allow_duplicate=allow_duplicate,
            )
        return result.to_dict()

    @mcp.tool(annotations=SENDS)
    async def send_draft(
        account: str, uid: int, folder: str = "drafts", allow_duplicate: bool = False
    ) -> dict:
        """SEND a saved draft as it is, immediately, then remove it from the Drafts folder.

        Use it for a draft the owner has reviewed (e.g. one made by create_draft; find its
        uid with search_emails folder='drafts'). Only the account's own drafts can be sent
        this way: the email needs the \\Draft flag and the account's address in From.
        Needs mail access "full" and an outgoing server (capability "mail.send").
        Returns the send_email fields plus "draft_removed". A draft already sent within
        the hour is refused; allow_duplicate=true sends it again (only when the owner asks).
        """
        with _tool_errors(PRESEND_TIMEOUT_MESSAGE):
            result = await mail.send_draft(_norm(account), uid, folder, allow_duplicate)
        return result.to_dict()
