"""MailService: async orchestration over `ImapPool` for search/read/thread/attachment/draft
and for organising mail (flags, move, trash, new folders).

Every synchronous IMAP interaction runs inside `asyncio.to_thread(...)` under a
per-call timeout. Reads open folders read-only (`select_folder(name, readonly=True)`,
i.e. EXAMINE) and fetch bodies only via `BODY.PEEK[...]`, so reading never marks mail
read. The writes are: `append(...)` of a draft to the Drafts folder, and -- only on
accounts whose mail access level is at least "organize" -- STORE of `\\Seen` /
`\\Flagged`, UID MOVE (or COPY + STORE `\\Deleted` + UID EXPUNGE of exactly those
UIDs), and CREATE of a folder. Those select their folder read-write. Nothing here ever
deletes mail permanently or sends it; a plain EXPUNGE is never issued.
"""

import asyncio
import threading
from collections.abc import Callable, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime

import imapclient
from imapclient.exceptions import IMAPClientAbortError, IMAPClientError, IMAPClientReadOnlyError

from postroom.accounts import Account, AccountRepo, AccountStatus, MailAccess
from postroom.mail.folders import FolderNotFound, resolve_folder, special_use_of
from postroom.mail.heavy import heavy_work
from postroom.mail.imap import (
    FETCH_BODY,
    RESP_BODY,
    SUMMARY_FIELDS,
    ImapError,
    ImapPool,
    is_safe_imap_value,
)
from postroom.mail.models import (
    AccountError,
    AttachmentInfo,
    BatchResult,
    DraftResult,
    FolderInfo,
    MessageDetail,
    MessageRef,
    MessageSummary,
    RefGroup,
    SearchCriteria,
    SearchResult,
)
from postroom.mail.parse import (
    MAX_HEADER_BYTES,
    StructPart,
    StructurePlan,
    bodystructure_has_attachment,
    build_draft,
    count_parts,
    decode_header_value,
    decode_transfer,
    format_addresses,
    parse_large_message,
    parse_message,
    structure_plan,
    truncate,
)
from postroom.mail.parse import get_attachment as parse_get_attachment

# Reading one email. It is parsed whole only when it is small and simple: at 5 MiB the
# parse peaks at +40 MiB (base64 attachment) to +67 MiB (8-bit HTML), and thousands of
# MIME parts cost seconds of CPU (10k parts: 3.5 s). Anything bigger or busier is read
# part by part: the header block plus the text parts (each cut at MAX_TEXT_PART_FETCH),
# or one attachment section (at most MAX_ATTACHMENT_FETCH_BYTES decoded), always with
# BODY.PEEK so nothing is marked read.
MAX_FULL_PARSE_BYTES = 5 * 1024 * 1024
MAX_FULL_PARSE_PARTS = 1000
MAX_TEXT_PART_FETCH = 1024 * 1024
MAX_ATTACHMENT_FETCH_BYTES = 5 * 1024 * 1024
# Above this size a whole-message fetch and parse runs under the heavy-work gate, so
# parallel reads of big messages queue instead of stacking up in memory.
HEAVY_MESSAGE_BYTES = 512 * 1024
# Headers are fetched with a size cap too (a stranger's mail can carry megabytes of them).
FETCH_HEADER_CAPPED = f"BODY.PEEK[HEADER]<0.{MAX_HEADER_BYTES}>"
MAX_THREAD_MESSAGES = 200
BODY_NOT_LOADED = "\n\n[… the rest of this email's text was not loaded: the email is too large]"

# Search paging: a deeper offset makes every account fetch summaries for offset + limit
# messages (about 6 KB of RSS each while a FETCH response is parsed), so bound it, fetch in
# chunks and keep only the small `MessageSummary` objects.
MAX_SEARCH_OFFSET = 1000
FETCH_CHUNK = 200

# Organising: one call may change at most this many emails (across all accounts).
MAX_BATCH_REFS = 500
MAX_FOLDER_NAME = 200
MESSAGE_NOT_FOUND = "message not found"
MOVE_UNSUPPORTED = "this server cannot move messages safely (it supports neither MOVE nor UIDPLUS)"
# An account that timed out or lost its connection mid-change may have had some of its
# emails changed already.
MAYBE_APPLIED = (
    "the change may have been partially applied; re-check with search_emails before retrying"
)
PARTIAL_TIMEOUT = f"the mail server did not respond in time; {MAYBE_APPLIED}"
FOLDER_READ_ONLY = "this folder is read-only on the server"
# Gmail archive (= remove from the Inbox) of emails referenced from another folder.
NOT_IN_INBOX = "not in the Inbox"
GMAIL_ARCHIVE_NEEDS_INBOX = (
    "on Gmail, archive works on Inbox emails; search folder=inbox and pass those uids"
)

_BLOCKED_STATUSES = (AccountStatus.NEEDS_RECONNECT, AccountStatus.NEEDS_GOOGLE_CONNECT)
_NOSELECT = (b"\\Noselect", b"\\NonExistent")


def _quote(value: str) -> str:
    return f'"{value}"' if " " in value else value


def imap_criteria(c: SearchCriteria) -> list:
    """Map `SearchCriteria` to an `IMAPClient.search()` criteria list."""
    parts: list = []
    if c.sender:
        parts += ["FROM", c.sender]
    if c.recipient:
        parts += ["TO", c.recipient]
    if c.subject:
        parts += ["SUBJECT", c.subject]
    if c.since:
        parts += ["SINCE", c.since]
    if c.before:
        parts += ["BEFORE", c.before]
    if c.unread_only:
        parts.append("UNSEEN")
    if c.query:
        parts += ["TEXT", c.query]
    return parts or ["ALL"]


def _needs_utf8(criteria: list) -> bool:
    return any(isinstance(v, str) and not v.isascii() for v in criteria)


def gmail_query(c: SearchCriteria) -> str:
    """Map `SearchCriteria` to a Gmail `X-GM-RAW` query string."""
    parts: list[str] = []
    if c.sender:
        parts.append(f"from:{_quote(c.sender)}")
    if c.recipient:
        parts.append(f"to:{_quote(c.recipient)}")
    if c.subject:
        parts.append(f"subject:{_quote(c.subject)}")
    if c.since:
        parts.append(f"after:{c.since:%Y/%m/%d}")
    if c.before:
        parts.append(f"before:{c.before:%Y/%m/%d}")
    if c.unread_only:
        parts.append("is:unread")
    if c.has_attachment:
        parts.append("has:attachment")
    if c.query:
        parts.append(c.query)
    return " ".join(parts)


def _section(data: dict, section: str) -> bytes | None:
    """A fetched section from a FETCH response, with or without the `<0>` partial origin."""
    key = b"BODY[" + section.encode() + b"]"  # a response key, not a (non-PEEK) request
    value = data.get(key + b"<0>")
    return value if value is not None else data.get(key)


def _fetch_part(c, uid: int, part: StructPart, limit: int) -> bytes | None:
    """One body part (PEEK): whole when the server's BODYSTRUCTURE puts it within `limit`
    bytes, else only its first `limit` bytes.

    The sizes come from the server, not the message, so a whole fetch is bounded; the
    partial form is kept for parts that need it because GreenMail answers it in a way
    imapclient cannot parse (no space before the literal).
    """
    item = f"BODY.PEEK[{part.section}]"
    if part.size > limit:
        item += f"<0.{limit}>"
    data = c.fetch([uid], [item]).get(uid)
    return _section(data, part.section) if data is not None else None


def _fetch_attached_message(c, uid: int, section: str) -> bytes | None:
    """An attached message/rfc822 part whole, as `<section>.HEADER` + `<section>.TEXT`:
    what `BODY[<section>]` should return, but GreenMail answers that with the body only.
    Only called for parts whose size is within the attachment cap."""
    items = [f"BODY.PEEK[{section}.HEADER]", f"BODY.PEEK[{section}.TEXT]"]
    data = c.fetch([uid], items).get(uid)
    if data is None:
        return None
    header, text = _section(data, f"{section}.HEADER"), _section(data, f"{section}.TEXT")
    if header is None or text is None:
        return None
    if not header.endswith((b"\r\n\r\n", b"\n\n")):  # GreenMail drops the blank line
        header += b"\r\n" if header.endswith(b"\n") else b"\r\n\r\n"
    return header + text


def _fits_full_parse(size: int, bodystructure) -> bool:
    return size <= MAX_FULL_PARSE_BYTES and count_parts(bodystructure) <= MAX_FULL_PARSE_PARTS


def _plan(bodystructure) -> StructurePlan:
    try:
        return structure_plan(bodystructure)
    except ValueError:
        raise ImapError("message too large") from None


def _fetch_whole(c, uid: int) -> bytes:
    raw = c.fetch([uid], [FETCH_BODY])[uid][RESP_BODY]
    if len(raw) > 2 * MAX_FULL_PARSE_BYTES:  # far more than RFC822.SIZE announced
        raise ImapError("message too large")
    return raw


def _fetch_header(c, uid: int) -> bytes | None:
    fetched = c.fetch([uid], [FETCH_HEADER_CAPPED])
    if uid not in fetched:
        return None
    return _section(fetched[uid], "HEADER") or b""


def _heavy_if(condition: bool):
    return heavy_work() if condition else nullcontext()


def _summary_fields(account: Account) -> list[str]:
    return [*SUMMARY_FIELDS, "X-GM-THRID"] if account.is_gmail else list(SUMMARY_FIELDS)


def _summary_from_fetch(account_email: str, folder: str, uid: int, data: dict) -> MessageSummary:
    envelope = data.get(b"ENVELOPE")
    internaldate = data.get(b"INTERNALDATE")
    date_str = internaldate.isoformat() if isinstance(internaldate, datetime) else None
    flags = data.get(b"FLAGS") or ()
    size = data.get(b"RFC822.SIZE")
    subject = decode_header_value(envelope.subject) if envelope and envelope.subject else ""
    from_addrs = format_addresses(envelope.from_) if envelope else []
    to_addrs = format_addresses(envelope.to) if envelope else []
    thrid = data.get(b"X-GM-THRID")
    return MessageSummary(
        account=account_email,
        folder=folder,
        uid=uid,
        date=date_str,
        from_=from_addrs[0] if from_addrs else "",
        to=to_addrs,
        subject=subject,
        seen=b"\\Seen" in flags,
        size=size,
        has_attachments=bodystructure_has_attachment(data.get(b"BODYSTRUCTURE")),
        thread_id=str(thrid) if thrid is not None else None,
    )


# -- organising helpers ------------------------------------------------------------------


def _group_refs(refs: list[MessageRef]) -> dict[str, dict[str, list[int]]]:
    """account -> folder (as given) -> UIDs, in first-seen order and without duplicates."""
    if not refs:
        raise ValueError("no emails given")
    if len(refs) > MAX_BATCH_REFS:
        raise ValueError(
            f"at most {MAX_BATCH_REFS} emails can be changed in one call ({len(refs)} given); "
            "split the list into smaller batches"
        )
    grouped: dict[str, dict[str, dict[int, None]]] = {}
    for ref in refs:
        uid = ref.uid
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            raise ValueError(f"invalid uid: {uid!r}")
        email = ref.account.strip().lower()
        grouped.setdefault(email, {}).setdefault(ref.folder, {})[uid] = None
    return {
        email: {folder: list(uids) for folder, uids in folders.items()}
        for email, folders in grouped.items()
    }


class _AccountBatch:
    """One account's share of a batch change, and what has happened to it so far.

    The IMAP thread records each folder's outcome as soon as it is done. When the account
    then fails (connection lost, timeout) the folders still pending fail with that error;
    after `close()` late outcomes from a thread the caller gave up on are ignored, and
    the thread checks `closed` so that it starts no further writes.
    """

    def __init__(self, email: str, groups: dict[str, list[int]]):
        self.email = email
        self._pending = dict(groups)
        self._result = BatchResult()
        self._lock = threading.Lock()
        self._closed = False
        # Set once a folder's change has begun: from then on a lost connection may have
        # left part of the change applied.
        self.started = False

    @property
    def closed(self) -> bool:
        """True once the caller has given up on this account (timeout): do nothing more."""
        with self._lock:
            return self._closed

    def pending(self) -> dict[str, list[int]]:
        with self._lock:
            return dict(self._pending)

    def record(
        self,
        keys: list[str],
        *,
        updated: int = 0,
        skipped: Sequence[RefGroup] = (),
        failed: Sequence[RefGroup] = (),
    ) -> None:
        with self._lock:
            if self._closed:
                return
            for key in keys:
                self._pending.pop(key, None)
            self._result.updated += updated
            self._result.skipped.extend(skipped)
            self._result.failed.extend(failed)

    def set_destination(self, folder: str) -> None:
        with self._lock:
            if not self._closed:
                self._result.destinations[self.email] = folder

    def close(self, error: str | None) -> BatchResult:
        with self._lock:
            self._closed = True
            if error is not None:
                for folder, uids in self._pending.items():
                    self._result.failed.append(RefGroup(self.email, folder, uids, error))
            self._pending = {}
            return self._result


@dataclass
class _FolderOutcome:
    updated: int = 0
    skipped: list[int] = field(default_factory=list)
    missing: list[int] = field(default_factory=list)
    skip_reason: str | None = None  # overrides the operation's default reason


# (client, resolved folder name, UIDs in it) -> what happened to them
FolderHandler = Callable[[object, str, list[int]], _FolderOutcome]


@contextmanager
def _folder_errors(batch: _AccountBatch, keys: list[str], name: str, uids: list[int]):
    """Record a server's refusal for one folder and carry on with the next one.

    Errors that break the connection propagate: the pool drops the connection, and the
    account's remaining folders fail with that error.
    """
    try:
        yield
    except IMAPClientReadOnlyError:
        # SELECT answered [READ-ONLY]: the connection is fine (the folder is selected),
        # only this folder cannot be changed. imaplib makes this a subclass of abort.
        batch.record(keys, failed=[RefGroup(batch.email, name, uids, FOLDER_READ_ONLY)])
    except IMAPClientAbortError:
        raise
    except (IMAPClientError, ImapError, FolderNotFound, ValueError) as e:
        batch.record(keys, failed=[RefGroup(batch.email, name, uids, str(e) or type(e).__name__)])


def _each_folder(
    c, folders, batch: _AccountBatch, handle: FolderHandler, skip_reason: str = ""
) -> None:
    """Resolve the batch's folders (merging names that resolve to the same folder) and
    hand each folder's UIDs to `handle`, recording the outcome folder by folder.

    Stops as soon as the batch is closed (the caller timed out): a folder whose change has
    begun is finished, but no further folder is started."""
    if batch.closed:
        return
    merged: dict[str, tuple[list[str], dict[int, None]]] = {}
    for key, uids in batch.pending().items():
        try:
            name = resolve_folder(folders, key)
        except FolderNotFound as e:
            batch.record([key], failed=[RefGroup(batch.email, key, uids, str(e))])
            continue
        keys, merged_uids = merged.setdefault(name, ([], {}))
        keys.append(key)
        merged_uids.update(dict.fromkeys(uids))

    for name, (keys, uid_set) in merged.items():
        if batch.closed:
            return
        uids = list(uid_set)
        with _folder_errors(batch, keys, name, uids):
            batch.started = True
            out = handle(c, name, uids)
            reason = out.skip_reason or skip_reason
            skipped = [RefGroup(batch.email, name, out.skipped, reason)] if out.skipped else []
            failed = (
                [RefGroup(batch.email, name, out.missing, MESSAGE_NOT_FOUND)] if out.missing else []
            )
            batch.record(keys, updated=out.updated, skipped=skipped, failed=failed)


def _existing(c, uids: list[int]) -> tuple[list[int], list[int], dict[int, tuple]]:
    """The UIDs that exist in the selected folder, those that do not, and their flags."""
    fetched = c.fetch(uids, ["FLAGS"])
    present = [u for u in uids if u in fetched]
    missing = [u for u in uids if u not in fetched]
    flags = {u: tuple(fetched[u].get(b"FLAGS") or ()) for u in present}
    return present, missing, flags


def _move_uids(c, uids: list[int], dest: str, flags: dict[int, tuple]) -> None:
    """Move UIDs of the selected folder to `dest`.

    UID MOVE (RFC 6851) when the server has it. Otherwise, with UIDPLUS (RFC 4315): COPY,
    mark the originals \\Deleted, then UID EXPUNGE exactly those UIDs. A plain EXPUNGE
    would also purge every other message someone had marked \\Deleted, so without
    either extension the move is refused.

    A message another mail app marked \\Deleted (without expunging it) has that mark
    removed first: it would travel with the move, and the next expunge of the destination
    would purge the message the owner just filed.
    """
    has_move = c.has_capability("MOVE")
    if not has_move and not c.has_capability("UIDPLUS"):
        raise ImapError(MOVE_UNSUPPORTED)
    marked = [u for u in uids if imapclient.DELETED in flags.get(u, ())]
    if marked:
        c.remove_flags(marked, [imapclient.DELETED], silent=True)
    if has_move:
        c.move(uids, dest)
    else:
        c.copy(uids, dest)
        try:
            c.add_flags(uids, [imapclient.DELETED], silent=True)
            c.uid_expunge(uids)
        except IMAPClientAbortError:
            raise
        except IMAPClientError as e:
            raise ImapError(
                f"copied to {dest!r}, but the originals could not be removed: {e}"
            ) from e


def _destination(account: Account, folders, wanted: str) -> tuple[str, bool]:
    """The folder `wanted` names on this account (SPECIAL-USE first), and whether this is
    a Gmail archive.

    Gmail has no \\Archive folder: archiving there means removing the Inbox label, which a
    move from INBOX to All Mail (\\All) does, so the "archive" alias maps to All Mail.
    """
    if account.is_gmail and wanted.strip().lower() == "archive":
        has_archive = any(
            special_use_of(flags) == "archive" and not any(f in _NOSELECT for f in flags)
            for flags, _delim, _name in folders
        )
        if not has_archive:
            return resolve_folder(folders, "all", special_use_first=True), True
    return resolve_folder(folders, wanted, special_use_first=True), False


def _gmail_archive_from(c, name: str, uids: list[int], inbox: str, dest: str) -> _FolderOutcome:
    """Archive on Gmail emails referenced from a folder other than the Inbox (All Mail, a
    label, a get_thread result): remove them from the Inbox, keeping every other label.

    A MOVE out of a label folder would remove that label and leave the Inbox label, so the
    emails are looked up in the Inbox by their Gmail message id (X-GM-MSGID) and moved from
    there to All Mail. Emails not in the Inbox are skipped.
    """
    c.select_folder(name, readonly=True)
    if not c.has_capability("X-GM-EXT-1"):
        present, missing, _ = _existing(c, uids)
        return _FolderOutcome(
            skipped=present, missing=missing, skip_reason=GMAIL_ARCHIVE_NEEDS_INBOX
        )
    fetched = c.fetch(uids, ["X-GM-MSGID"])
    msgids = {u: fetched[u].get(b"X-GM-MSGID") for u in uids if u in fetched}
    missing = [u for u in uids if u not in fetched]
    if not msgids or any(m is None for m in msgids.values()):
        return _FolderOutcome(
            skipped=list(msgids), missing=missing, skip_reason=GMAIL_ARCHIVE_NEEDS_INBOX
        )

    c.select_folder(inbox, readonly=False)
    in_inbox: dict[int, None] = {}
    archived, not_in_inbox = [], []
    for uid, msgid in msgids.items():
        found = c.search(["X-GM-MSGID", msgid])
        (archived if found else not_in_inbox).append(uid)
        in_inbox.update(dict.fromkeys(found))
    if in_inbox:
        targets, _missing, flags = _existing(c, list(in_inbox))
        if targets:
            _move_uids(c, targets, dest, flags)
    return _FolderOutcome(
        updated=len(archived), skipped=not_in_inbox, missing=missing, skip_reason=NOT_IN_INBOX
    )


def _parent_folder(folders, parent: str) -> tuple[str, str | None]:
    """A parent folder's name and hierarchy delimiter. A parent may be a container that
    cannot hold mail itself (\\Noselect, e.g. Gmail's "[Gmail]")."""
    try:
        name = resolve_folder(folders, parent)
    except FolderNotFound:
        matches = [n for _f, _d, n in folders if n == parent] or [
            n for _f, _d, n in folders if n.lower() == parent.lower()
        ]
        if not matches:
            raise
        name = matches[0]
    delim = next(d for _f, d, n in folders if n == name)
    return name, delim.decode() if isinstance(delim, bytes) else delim


def _server_delimiter(folders) -> str | None:
    """The hierarchy delimiter the server reports (INBOX's first), if it has one."""
    ordered = sorted(folders, key=lambda f: f[2].upper() != "INBOX")
    for _flags, delim, _name in ordered:
        if delim:
            return delim.decode() if isinstance(delim, bytes) else delim
    return None


class MailService:
    def __init__(
        self,
        repo: AccountRepo,
        pool: ImapPool,
        max_concurrency: int = 4,
        account_timeout: float = 90,
    ):
        self.repo = repo
        self.pool = pool
        self.max_concurrency = max_concurrency
        self.account_timeout = account_timeout

    async def _run(self, fn):
        return await asyncio.wait_for(asyncio.to_thread(fn), self.account_timeout)

    def _require_account(self, email: str) -> Account:
        account = self.repo.get(email)
        if account is None:
            raise ImapError(f"unknown account: {email}")
        return account

    # -- folders ---------------------------------------------------------

    async def list_folders(self, email: str, with_counts: bool = False) -> list[FolderInfo]:
        def work():
            with self.pool.session(email) as c:
                out = []
                for flags, _delim, name in c.list_folders():
                    flag_strs = [f.decode() if isinstance(f, bytes) else f for f in flags]
                    messages = unseen = None
                    if with_counts and not any(f in _NOSELECT for f in flags):
                        try:
                            status = c.folder_status(name, ("MESSAGES", "UNSEEN"))
                            messages = status.get(b"MESSAGES")
                            unseen = status.get(b"UNSEEN")
                        except Exception:  # noqa: BLE001, S110 -- counts are best-effort
                            pass
                    out.append(
                        FolderInfo(
                            name=name,
                            special_use=special_use_of(flags),
                            flags=flag_strs,
                            messages=messages,
                            unseen=unseen,
                        )
                    )
                return out

        return await self._run(work)

    # -- search ------------------------------------------------------------

    def _search_account_sync(
        self, email: str, folder: str | None, criteria: SearchCriteria, skip: int, take: int
    ) -> list[MessageSummary]:
        """Summaries of the newest (highest-UID) matches after skipping `skip` of them.

        At most `take` are returned. Summaries are fetched `FETCH_CHUNK` UIDs at a time,
        and the attachment filter stops as soon as it has enough matches.
        """
        account = self._require_account(email)
        with self.pool.session(email) as c:
            folders = c.list_folders()
            name = resolve_folder(folders, folder)
            c.select_folder(name, readonly=True)

            if account.is_gmail:
                query = gmail_query(criteria)
                uids = c.gmail_search(query, charset="UTF-8") if query else c.search(["ALL"])
            else:
                crit = imap_criteria(criteria)
                charset = "UTF-8" if _needs_utf8(crit) else None
                uids = c.search(crit, charset=charset)

            uids = sorted(uids, reverse=True)
            filter_attachments = not account.is_gmail and criteria.has_attachment
            if filter_attachments:
                # Scan at most 3x the wanted number of messages for ones with attachments.
                candidate_uids = uids[: 3 * (skip + take)]
            else:
                candidate_uids = uids[skip : skip + take]
                skip = 0

            fields = _summary_fields(account)
            summaries: list[MessageSummary] = []
            for start in range(0, len(candidate_uids), FETCH_CHUNK):
                chunk = candidate_uids[start : start + FETCH_CHUNK]
                fetched = c.fetch(chunk, fields)
                for uid in chunk:  # newest first, whatever order the server answered in
                    data = fetched.get(uid)
                    if data is None:
                        continue
                    if filter_attachments and not bodystructure_has_attachment(
                        data.get(b"BODYSTRUCTURE")
                    ):
                        continue
                    if skip:
                        skip -= 1
                        continue
                    summaries.append(_summary_from_fetch(email, name, uid, data))
                    if len(summaries) >= take:
                        return summaries
            return summaries

    async def search(
        self,
        emails: list[str] | None,
        folder: str | None,
        criteria: SearchCriteria,
        limit: int = 20,
        offset: int = 0,
    ) -> SearchResult:
        limit = max(1, min(100, limit))
        offset = max(0, min(MAX_SEARCH_OFFSET, offset))
        errors: list[AccountError] = []

        if emails is None:
            targets = []
            for acc in self.repo.list(include_disabled=False):
                if "mail" not in acc.capabilities:
                    continue
                if acc.status in _BLOCKED_STATUSES:
                    errors.append(AccountError(acc.email, f"account status: {acc.status.value}"))
                    continue
                targets.append(acc.email)
        else:
            targets = list(emails)

        # One account can skip `offset` matches on the server side. Merging several needs
        # each account's newest offset + limit, since the page may come from any of them.
        skip = offset if len(targets) == 1 else 0
        take = offset + limit - skip
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(email: str):
            async with sem:
                return await self._run(
                    lambda: self._search_account_sync(email, folder, criteria, skip, take)
                )

        results = await asyncio.gather(*(run_one(e) for e in targets), return_exceptions=True)

        all_summaries: list[MessageSummary] = []
        for email, res in zip(targets, results, strict=True):
            if isinstance(res, BaseException):
                errors.append(AccountError(email, str(res) or type(res).__name__))
            else:
                all_summaries.extend(res)

        # Sort by date descending with `None` dates last: a single `reverse=True`
        # sort on `(date is None, date)` would also flip the None-last ordering, so
        # sort the dated and undated messages separately and concatenate.
        dated = sorted(
            (s for s in all_summaries if s.date is not None), key=lambda s: s.date, reverse=True
        )
        undated = [s for s in all_summaries if s.date is None]
        all_summaries = dated + undated
        page = all_summaries[offset - skip : offset - skip + limit]
        return SearchResult(results=page, errors=errors)

    # -- read ---------------------------------------------------------------

    async def get_message(
        self, email: str, folder: str, uid: int, max_chars: int = 20000
    ) -> MessageDetail:
        def work():
            account = self._require_account(email)
            with self.pool.session(email) as c:
                folders = c.list_folders()
                name = resolve_folder(folders, folder)
                c.select_folder(name, readonly=True)

                fetched = c.fetch([uid], _summary_fields(account))
                if uid not in fetched:
                    raise LookupError("message not found")
                data = fetched[uid]
                size = data.get(b"RFC822.SIZE") or 0
                bodystructure = data.get(b"BODYSTRUCTURE")
                summary = _summary_from_fetch(email, name, uid, data)

                body_cut = False
                if _fits_full_parse(size, bodystructure):
                    with _heavy_if(size > HEAVY_MESSAGE_BYTES):
                        parsed = parse_message(_fetch_whole(c, uid))
                else:
                    with heavy_work():
                        parsed, body_cut = self._read_large(c, uid, bodystructure)

                text, truncated = truncate(parsed.body_text, max(1, max_chars))
                if body_cut and not truncated:
                    text, truncated = text + BODY_NOT_LOADED, True
                parsed.body_text = text
                return MessageDetail(summary=summary, message=parsed, truncated=truncated)

        return await self._run(work)

    @staticmethod
    def _read_large(c, uid: int, bodystructure):
        """Headers and body text of a message too big to parse whole, plus whether the
        body text was cut short. Fetches only the header block and the text parts."""
        plan = _plan(bodystructure)
        header = _fetch_header(c, uid)
        if header is None:
            raise LookupError("message not found")
        texts = {}
        for part in (plan.plain, plan.html):
            if part is not None:
                value = _fetch_part(c, uid, part, MAX_TEXT_PART_FETCH)
                if value is not None:
                    texts[part.section] = value
        parsed = parse_large_message(header, plan, texts)
        used = {"plain": plan.plain, "html": plan.html}.get(parsed.body_source)
        return parsed, used is not None and used.size > MAX_TEXT_PART_FETCH

    async def get_thread(self, email: str, folder: str, uid: int) -> list[MessageSummary]:
        def work():
            account = self._require_account(email)
            with self.pool.session(email) as c:
                folders = c.list_folders()
                name = resolve_folder(folders, folder)
                c.select_folder(name, readonly=True)

                if account.is_gmail:
                    fetched = c.fetch([uid], ["X-GM-THRID"])
                    if uid not in fetched:
                        raise LookupError("message not found")
                    thrid = fetched[uid][b"X-GM-THRID"]
                    all_name = resolve_folder(folders, "all")
                    c.select_folder(all_name, readonly=True)
                    uids = sorted(c.search(["X-GM-THRID", thrid]))[-MAX_THREAD_MESSAGES:]
                    data = c.fetch(uids, _summary_fields(account)) if uids else {}
                    summaries = [
                        _summary_from_fetch(email, all_name, u, d) for u, d in data.items()
                    ]
                else:
                    header = _fetch_header(c, uid)
                    if header is None:
                        raise LookupError("message not found")
                    original = parse_message(header)

                    ids = []
                    # Header values come from whoever sent the mail: skip any that could
                    # break out of the SEARCH command line.
                    for mid in [*original.references, original.in_reply_to, original.message_id]:
                        if mid and mid not in ids and is_safe_imap_value(mid):
                            ids.append(mid)
                    ids = ids[:20]

                    folder_names = [name]
                    try:
                        sent_name = resolve_folder(folders, "sent")
                    except FolderNotFound:
                        sent_name = None
                    if sent_name and sent_name != name:
                        folder_names.append(sent_name)

                    seen_keys = set()
                    summaries = []
                    for fname in folder_names:
                        if fname != name:
                            c.select_folder(fname, readonly=True)
                        uid_set = set()
                        for mid in ids:
                            uid_set.update(c.search(["HEADER", "Message-ID", mid]))
                        if original.message_id and is_safe_imap_value(original.message_id):
                            uid_set.update(c.search(["HEADER", "References", original.message_id]))
                        if not uid_set:
                            continue
                        newest = sorted(uid_set)[-MAX_THREAD_MESSAGES:]
                        fetched = c.fetch(newest, SUMMARY_FIELDS)
                        for u, d in fetched.items():
                            key = (fname, u)
                            if key in seen_keys:
                                continue
                            seen_keys.add(key)
                            summaries.append(_summary_from_fetch(email, fname, u, d))

                summaries.sort(key=lambda s: (s.date is None, s.date or ""))
                return summaries

        return await self._run(work)

    async def get_attachment(
        self, email: str, folder: str, uid: int, index: int
    ) -> tuple[AttachmentInfo, bytes | None]:
        """The attachment's metadata and content. The content is None when the attachment
        is too big to fetch (over MAX_ATTACHMENT_FETCH_BYTES in a message too large to
        parse whole)."""

        def work():
            account = self._require_account(email)
            with self.pool.session(email) as c:
                folders = c.list_folders()
                name = resolve_folder(folders, folder)
                c.select_folder(name, readonly=True)

                fetched = c.fetch([uid], _summary_fields(account))
                if uid not in fetched:
                    raise LookupError("message not found")
                size = fetched[uid].get(b"RFC822.SIZE") or 0
                bodystructure = fetched[uid].get(b"BODYSTRUCTURE")

                if _fits_full_parse(size, bodystructure):
                    with _heavy_if(size > HEAVY_MESSAGE_BYTES):
                        return parse_get_attachment(_fetch_whole(c, uid), index)
                with heavy_work():
                    return self._read_large_attachment(c, uid, bodystructure, index)

        return await self._run(work)

    @staticmethod
    def _read_large_attachment(c, uid: int, bodystructure, index: int):
        plan = _plan(bodystructure)
        match = next((m for m in plan.attachments if m[0].index == index), None)
        if match is None:
            raise KeyError(index)
        info, part = match
        if info.size > MAX_ATTACHMENT_FETCH_BYTES:
            return info, None
        # Encoded size of MAX_ATTACHMENT_FETCH_BYTES of base64, plus slack: what may be
        # fetched at most, and a check on what the server actually sent.
        limit = MAX_ATTACHMENT_FETCH_BYTES * 78 // 57 + 4096
        if part.content_type == "message/rfc822":
            raw = _fetch_attached_message(c, uid, part.section)
        else:
            raw = _fetch_part(c, uid, part, limit)
        if raw is None:
            raise LookupError("attachment not found")
        if len(raw) >= limit:
            return info, None
        payload = (
            raw if part.content_type == "message/rfc822" else decode_transfer(raw, part.encoding)
        )
        info.size = len(payload)
        return info, payload

    # -- draft ----------------------------------------------------------------

    async def create_draft(
        self,
        email: str,
        *,
        to: list[str],
        subject: str | None,
        body: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        html: bool = False,
        reply_folder: str | None = None,
        reply_uid: int | None = None,
    ) -> DraftResult:
        cc = cc or []
        bcc = bcc or []

        def work():
            account = self._require_account(email)
            with self.pool.session(email) as c:
                folders = c.list_folders()

                resolved_to = list(to)
                resolved_subject = subject
                in_reply_to = None
                references: list[str] = []

                if reply_uid is not None:
                    rf_name = resolve_folder(folders, reply_folder)
                    c.select_folder(rf_name, readonly=True)
                    header = _fetch_header(c, reply_uid)
                    if header is None:
                        raise LookupError("message not found")
                    original = parse_message(header)

                    if not resolved_to:
                        if original.reply_to:
                            resolved_to = list(original.reply_to)
                        elif original.from_:
                            resolved_to = [original.from_]

                    if resolved_subject is None:
                        subj = original.subject or ""
                        resolved_subject = subj if subj.lower().startswith("re:") else f"Re: {subj}"

                    if original.message_id and is_safe_imap_value(original.message_id):
                        in_reply_to = original.message_id
                        references = [
                            r
                            for r in [*original.references, original.message_id]
                            if is_safe_imap_value(r)
                        ]

                if not resolved_to:
                    raise ValueError("at least one recipient is required")
                if reply_uid is None and resolved_subject is None:
                    raise ValueError("subject is required")

                raw, msgid = build_draft(
                    from_addr=account.email,
                    from_name=account.display_name,
                    to=resolved_to,
                    cc=cc,
                    bcc=bcc,
                    subject=resolved_subject or "",
                    body=body,
                    html=html,
                    in_reply_to=in_reply_to,
                    references=references,
                )

                drafts_name = resolve_folder(folders, "drafts", special_use_first=True)
                c.append(drafts_name, raw, flags=(imapclient.DRAFT,), msg_time=datetime.now(UTC))
                return DraftResult(account=account.email, folder=drafts_name, message_id=msgid)

        return await self._run(work)

    # -- organise ---------------------------------------------------------------

    async def _batch(
        self,
        refs: list[MessageRef],
        level: MailAccess,
        work: Callable[[Account, _AccountBatch], None],
    ) -> BatchResult:
        """Run `work` for each account's share of `refs`: accounts in parallel, folders
        within an account one after another. Account-level failures (unknown account,
        access level too low, login, timeout) fail that account's pending emails."""
        grouped = _group_refs(refs)
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(email: str, groups: dict[str, list[int]]) -> BatchResult:
            batch = _AccountBatch(email, groups)
            error = None
            try:
                account = self._require_account(email)
                account.require_mail_access(level)
                async with sem:
                    await self._run(lambda: work(account, batch))
            except TimeoutError:
                error = PARTIAL_TIMEOUT
            except Exception as e:  # noqa: BLE001 -- reported per account, like search
                error = str(e) or type(e).__name__
                # The pool wraps a lost connection (socket timeout, EOF, abort) in ImapError:
                # if it broke off a change, the server may have applied it anyway.
                lost = isinstance(e.__cause__, (OSError, IMAPClientAbortError))
                if batch.started and isinstance(e, ImapError) and lost:
                    error = f"{error}; {MAYBE_APPLIED}"
            return batch.close(error)

        results = await asyncio.gather(*(run_one(e, g) for e, g in grouped.items()))
        total = BatchResult()
        for res in results:
            total.updated += res.updated
            total.skipped.extend(res.skipped)
            total.failed.extend(res.failed)
            if res.updated:  # report a destination only where something was moved there
                total.destinations.update(res.destinations)
        return total

    async def set_flags(
        self, refs: list[MessageRef], *, read: bool | None = None, flagged: bool | None = None
    ) -> BatchResult:
        """Mark emails read / unread (\\Seen) and flagged / unflagged (\\Flagged)."""
        if read is None and flagged is None:
            raise ValueError("set read, flagged or both")
        changes = [
            (flag, on)
            for flag, on in ((imapclient.SEEN, read), (imapclient.FLAGGED, flagged))
            if on is not None
        ]

        def handle(c, name: str, uids: list[int]) -> _FolderOutcome:
            c.select_folder(name, readonly=False)
            present, missing, _flags = _existing(c, uids)
            if present:
                for flag, on in changes:
                    store = c.add_flags if on else c.remove_flags
                    store(present, [flag], silent=True)
            return _FolderOutcome(updated=len(present), missing=missing)

        def work(account: Account, batch: _AccountBatch) -> None:
            with self.pool.session(account.email) as c:
                if batch.closed:  # waited for the connection past the caller's timeout
                    return
                _each_folder(c, c.list_folders(), batch, handle)

        return await self._batch(refs, MailAccess.ORGANIZE, work)

    async def move(
        self, refs: list[MessageRef], to_folder: str, *, skip_reason: str | None = None
    ) -> BatchResult:
        """Move emails to `to_folder` (a folder name or alias, resolved per account).
        Emails already in it are left there and reported as skipped.

        On Gmail, "archive" removes emails from the Inbox (see `_gmail_archive_from`)."""
        if not to_folder or not to_folder.strip():
            raise ValueError("to_folder must not be empty")

        def work(account: Account, batch: _AccountBatch) -> None:
            with self.pool.session(account.email) as c:
                if batch.closed:  # waited for the connection past the caller's timeout
                    return
                folders = c.list_folders()
                dest, gmail_archive = _destination(account, folders, to_folder)
                inbox = resolve_folder(folders, "inbox") if gmail_archive else None
                batch.set_destination(dest)

                def handle(c, name: str, uids: list[int]) -> _FolderOutcome:
                    if gmail_archive and name != inbox:
                        return _gmail_archive_from(c, name, uids, inbox, dest)
                    if name == dest:
                        c.select_folder(name, readonly=True)
                        present, missing, _flags = _existing(c, uids)
                        return _FolderOutcome(skipped=present, missing=missing)
                    c.select_folder(name, readonly=False)
                    present, missing, flags = _existing(c, uids)
                    if present:
                        _move_uids(c, present, dest, flags)
                    return _FolderOutcome(updated=len(present), missing=missing)

                _each_folder(c, folders, batch, handle, skip_reason or f"already in {dest}")

        return await self._batch(refs, MailAccess.ORGANIZE, work)

    async def trash(self, refs: list[MessageRef]) -> BatchResult:
        """Move emails to each account's Trash. Emails already there are left alone:
        nothing is ever deleted permanently."""
        return await self.move(refs, "trash", skip_reason="already in trash")

    async def create_folder(self, email: str, name: str, parent: str | None = None) -> str:
        """Create a folder (under `parent`, when given); returns its full name."""
        name = (name or "").strip()
        if not name:
            raise ValueError("folder name must not be empty")
        if len(name) > MAX_FOLDER_NAME:
            raise ValueError(f"folder name must be at most {MAX_FOLDER_NAME} characters")
        if not is_safe_imap_value(name):
            raise ValueError("line breaks and NUL characters are not allowed in folder names")
        account = self._require_account(email)
        account.require_mail_access(MailAccess.ORGANIZE)

        def work() -> str:
            with self.pool.session(account.email) as c:
                folders = c.list_folders()
                if parent:
                    parent_name, delim = _parent_folder(folders, parent)
                    if not delim:
                        raise ValueError(
                            "this server has no folder hierarchy; create the folder without "
                            "a parent"
                        )
                else:
                    delim = _server_delimiter(folders)
                if delim and delim in name:
                    raise ValueError(
                        f"folder name must not contain {delim!r} (the server's folder "
                        "separator); use parent to create a folder inside another"
                    )
                full = f"{parent_name}{delim}{name}" if parent else name
                if any(n.lower() == full.lower() for _f, _d, n in folders):
                    raise ValueError(f"folder already exists: {full!r}")
                try:
                    c.create_folder(full)
                except IMAPClientAbortError:
                    raise
                except IMAPClientError as e:
                    raise ImapError(f"the server refused to create the folder: {e}") from e
                # Many mail apps only show subscribed folders.
                try:
                    c.subscribe_folder(full)
                except IMAPClientAbortError:
                    raise
                except IMAPClientError:
                    pass
                return full

        return await self._run(work)
