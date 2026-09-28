"""MCP mail tools: accounts, folders, search, read, thread, attachment, draft.

Every tool is read-only except `create_draft`, which only saves a draft in the Drafts
folder. There is deliberately no tool that sends, deletes, moves or flags mail.

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

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.utilities.types import Image

from postroom.accounts import AccountRepo
from postroom.google.oauth import GoogleOAuthError
from postroom.mail.folders import FolderNotFound
from postroom.mail.heavy import ServerBusy, heavy_work
from postroom.mail.imap import ImapError
from postroom.mail.models import AttachmentInfo, SearchCriteria
from postroom.mail.parse import truncate
from postroom.mail.pdf import PdfTooComplex, extract_text_isolated
from postroom.mail.service import MAX_SEARCH_OFFSET, MailService

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}
WRITES_DRAFT = {"readOnlyHint": False, "destructiveHint": False}

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


@contextmanager
def _tool_errors(timeout_message: str = TIMEOUT_MESSAGE) -> Iterator[None]:
    """Turn expected mail errors into clean `ToolError`s (message only, no traceback)."""
    try:
        yield
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
        """
        return [
            {
                "email": a.email,
                "name": a.display_name,
                "provider": a.provider.value,
                "status": a.status.value,
                "enabled": a.enabled,
                "capabilities": a.capabilities,
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
        """Save a draft in the account's Drafts folder for the owner to review and send.

        Nothing is ever sent. to / cc / bcc are lists of email addresses; body is plain
        text, or HTML when html=true. A new email needs `to` and `subject`. To reply, pass
        reply_to_uid (and reply_to_folder, default inbox): the draft is threaded to the
        original, and `to` / `subject` default to the original sender and "Re: <subject>".
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
