"""Composing outgoing mail: address and attachment checks, reply / reply-all recipients,
the forwarded-message text, re-sending a stored draft, and the per-account send rate limit.

Pure functions and data (no I/O). Every value that ends up in a header or in the SMTP
envelope passes through here first, so line breaks never reach either (header injection),
and the limits below hold whoever calls `MailService`.
"""

import base64
import binascii
import email.utils
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.headerregistry import Address as HeaderAddress
from email.parser import BytesHeaderParser

from postroom.mail.models import OutgoingFile, ParsedMessage

MAX_RECIPIENTS = 50
MAX_ADDRESS_CHARS = 320
MAX_SUBJECT_CHARS = 1000
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # decoded, all attachments of one send_email
MAX_FORWARD_ATTACHMENT_BYTES = 20 * 1024 * 1024  # decoded, all re-attached originals
MAX_DRAFT_BYTES = 25 * 1024 * 1024
MAX_FILENAME_CHARS = 200
DEFAULT_CONTENT_TYPE = "application/octet-stream"
FORWARD_MARKER = "---------- Forwarded message ---------"

_LINE_BREAKS = re.compile(r"[\r\n\x00]")
_TOKEN = r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}"
_CONTENT_TYPE = re.compile(rf"{_TOKEN}/{_TOKEN}")
# Control characters, and the bidi controls that can disguise a file's real extension
# ("invoice" + U+202E + "fdp.exe" displays as "invoiceexe.pdf").
_UNSAFE_FILENAME_CHARS = re.compile(
    "[\\x00-\\x1f\\x7f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]"
)
_FWD_PREFIX = re.compile(r"^\s*(fwd?|fw)\s*:", re.IGNORECASE)
_RE_PREFIX = re.compile(r"^\s*re\s*:", re.IGNORECASE)


class SendLimitExceeded(Exception):
    """The account has sent as many emails as the hourly limit allows."""


# -- headers and addresses -------------------------------------------------------------------


def check_header_text(name: str, value: str | None) -> None:
    """Refuse CR, LF and NUL in a value that becomes a header (header injection)."""
    if value and _LINE_BREAKS.search(value):
        raise ValueError(f"{name} must not contain line breaks")


def check_subject(subject: str | None) -> None:
    check_header_text("subject", subject)
    if subject and len(subject) > MAX_SUBJECT_CHARS:
        raise ValueError(f"subject must be at most {MAX_SUBJECT_CHARS} characters")


@dataclass(frozen=True)
class Recipient:
    header: str  # as it goes into To / Cc / Bcc: "Name <addr>" or "addr"
    addr: str  # the bare address for the SMTP envelope

    @property
    def key(self) -> str:
        return self.addr.lower()


def _idna_domain(addr: str) -> str:
    """The address with an internationalised domain in its ASCII (punycode) form."""
    local, _, domain = addr.rpartition("@")
    if domain.isascii():
        return addr
    try:
        return f"{local}@{domain.encode('idna').decode('ascii')}"
    except UnicodeError:
        raise ValueError(f"invalid email address: {addr!r}") from None


def parse_recipient(value: object) -> Recipient:
    """One address ("addr" or "Name <addr>"), validated for use in headers and the envelope."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty email address")
    value = value.strip()
    if _LINE_BREAKS.search(value):
        raise ValueError("email addresses must not contain line breaks")
    if len(value) > MAX_ADDRESS_CHARS:
        raise ValueError(f"email address longer than {MAX_ADDRESS_CHARS} characters")
    if len(email.utils.getaddresses([value])) != 1:
        raise ValueError(f"give one email address per list item: {value!r}")
    name, addr = email.utils.parseaddr(value)
    if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
        raise ValueError(f"invalid email address: {value!r}")
    addr = _idna_domain(addr)
    try:
        header = str(HeaderAddress(display_name=name, addr_spec=addr))
    except (ValueError, IndexError, TypeError):
        raise ValueError(f"invalid email address: {value!r}") from None
    return Recipient(header=header, addr=addr)


@dataclass
class Recipients:
    to: list[Recipient]
    cc: list[Recipient]
    bcc: list[Recipient]

    @property
    def envelope(self) -> list[str]:
        return [r.addr for r in (*self.to, *self.cc, *self.bcc)]

    def headers(self, which: str) -> list[str]:
        return [r.header for r in getattr(self, which)]


def collect_recipients(
    to: Iterable[object], cc: Iterable[object] = (), bcc: Iterable[object] = ()
) -> Recipients:
    """Validate and de-duplicate To / Cc / Bcc (an address is kept in the first list it
    appears in). 1 to MAX_RECIPIENTS addresses in total."""
    seen: set[str] = set()
    lists: list[list[Recipient]] = []
    count = 0
    for values in (to, cc, bcc):
        out = []
        for value in values or ():
            count += 1
            if count > 4 * MAX_RECIPIENTS:  # bound the work on an absurd list
                break
            r = parse_recipient(value)
            if r.key not in seen:
                seen.add(r.key)
                out.append(r)
        lists.append(out)
    total = len(seen)
    if total == 0:
        raise ValueError("at least one recipient is required")
    if total > MAX_RECIPIENTS or count > 4 * MAX_RECIPIENTS:
        raise ValueError(f"at most {MAX_RECIPIENTS} recipients (to + cc + bcc) per email")
    return Recipients(*lists)


def _addr_key(value: str) -> str | None:
    addr = email.utils.parseaddr(value)[1]
    return addr.lower() if addr else None


def reply_subject(original_subject: str | None) -> str:
    subj = original_subject or ""
    return subj if _RE_PREFIX.match(subj) else f"Re: {subj}"


def reply_recipients(
    original: ParsedMessage,
    to: list[str],
    cc: list[str],
    reply_all: bool,
    own: set[str],
) -> tuple[list[str], list[str]]:
    """To and Cc of a reply. `to` defaults to the original's Reply-To, else its From.
    With `reply_all`, the original's To and Cc (without the account's own addresses) are
    added to Cc. Replying to one's own email goes to its recipients instead."""
    own = {o.lower() for o in own}
    to, cc = list(to), list(cc)
    extra: list[str] = []
    if not to:
        to = list(original.reply_to) if original.reply_to else [original.from_]
        to = [a for a in to if a]
        if reply_all and to and all(_addr_key(a) in own for a in to):
            to = [a for a in original.to if _addr_key(a) not in own]
            extra = list(original.cc)
        elif reply_all:
            extra = [*original.to, *original.cc]
    elif reply_all:
        extra = [*original.to, *original.cc]

    taken = {_addr_key(a) for a in (*to, *cc)}
    for value in extra:
        key = _addr_key(value)
        if not key or key in own or key in taken:
            continue
        try:
            parse_recipient(value)
        except ValueError:
            continue  # an unusable address in someone else's header: leave it out
        taken.add(key)
        cc.append(value)
    return to, cc


# -- forwarding ------------------------------------------------------------------------------


def forward_subject(original_subject: str | None) -> str:
    subj = (original_subject or "").strip()
    return subj if _FWD_PREFIX.match(subj) else f"Fwd: {subj}"


def _display_date(iso: str | None) -> str | None:
    if not iso:
        return None
    try:
        return email.utils.format_datetime(datetime.fromisoformat(iso))
    except (ValueError, TypeError):
        return iso


def forward_body(text: str, original: ParsedMessage) -> str:
    """The user's text, the usual "Forwarded message" block, then the original text."""
    lines = [FORWARD_MARKER, f"From: {original.from_}"]
    date = _display_date(original.date)
    if date:
        lines.append(f"Date: {date}")
    lines.append(f"Subject: {original.subject}")
    if original.to:
        lines.append(f"To: {', '.join(original.to)}")
    if original.cc:
        lines.append(f"Cc: {', '.join(original.cc)}")
    intro = f"{text.rstrip()}\n\n" if text and text.strip() else ""
    return f"{intro}{chr(10).join(lines)}\n\n{original.body_text}"


# -- attachments -------------------------------------------------------------------------------


def sanitize_filename(name: object, fallback: str = "attachment") -> str:
    """A plain file name: no directories, control or bidi characters, at most 200 chars."""
    if not isinstance(name, str):
        return fallback
    name = re.split(r"[/\\]", name)[-1]
    name = _UNSAFE_FILENAME_CHARS.sub("", name)
    name = " ".join(name.split()).strip(" .") or ""
    if not name:
        return fallback
    if len(name) > MAX_FILENAME_CHARS:
        stem, dot, ext = name.rpartition(".")
        if dot and stem and len(ext) <= 20:
            name = f"{stem[: MAX_FILENAME_CHARS - len(ext) - 1]}.{ext}"
        else:
            name = name[:MAX_FILENAME_CHARS]
    return name


def normalize_content_type(value: object) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return DEFAULT_CONTENT_TYPE
    ct = value.strip().lower() if isinstance(value, str) else ""
    if not _CONTENT_TYPE.fullmatch(ct):
        raise ValueError(f"content_type must look like type/subtype, got {value!r}")
    if ct.startswith("multipart/"):
        raise ValueError("multipart content types cannot be attached")
    return ct


def _field(item: object, name: str):
    return item.get(name) if isinstance(item, dict) else getattr(item, name, None)


def decode_attachments(items: Iterable[object] | None) -> list[OutgoingFile]:
    """Validate and decode `[{filename, content_type, content_base64}]`: at most
    MAX_ATTACHMENTS files and MAX_ATTACHMENT_BYTES decoded in total."""
    files: list[OutgoingFile] = []
    items = list(items or ())
    if len(items) > MAX_ATTACHMENTS:
        raise ValueError(f"at most {MAX_ATTACHMENTS} attachments per email")
    limit_mib = MAX_ATTACHMENT_BYTES // (1024 * 1024)
    total = 0
    for i, item in enumerate(items, 1):
        filename = sanitize_filename(_field(item, "filename"), fallback=f"attachment-{i}")
        content_type = normalize_content_type(_field(item, "content_type"))
        encoded = _field(item, "content_base64")
        if not isinstance(encoded, str) or not encoded:
            raise ValueError(f"attachment {i} ({filename}): content_base64 is required")
        encoded = "".join(encoded.split())
        if total + len(encoded) * 3 // 4 > MAX_ATTACHMENT_BYTES + 3:
            raise ValueError(f"attachments are larger than {limit_mib} MiB in total")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(
                f"attachment {i} ({filename}): content_base64 is not valid base64"
            ) from None
        total += len(data)
        if total > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"attachments are larger than {limit_mib} MiB in total")
        files.append(OutgoingFile(filename, content_type, data))
    return files


# -- sending a stored draft ------------------------------------------------------------------


@dataclass
class StoredDraft:
    sent_copy: bytes  # Bcc kept, a fresh Date; `without_bcc` gives what is transmitted
    recipients: Recipients
    message_id: str


def _split_header(raw: bytes) -> tuple[bytes, bytes]:
    """(header block without its blank line, body) of a CRLF message."""
    end = raw.find(b"\r\n\r\n")
    return (raw[:end], raw[end + 4 :]) if end != -1 else (raw.rstrip(b"\r\n"), b"")


def _split_fields(header: bytes) -> list[tuple[str, bytes]]:
    """Header block -> [(lower-case field name, the field's raw lines incl. folding)]."""
    fields: list[tuple[str, bytes]] = []
    for line in header.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t") and fields:
            name, raw = fields[-1]
            fields[-1] = (name, raw + b"\r\n" + line)
        else:
            name = line.split(b":", 1)[0].strip().decode("ascii", "replace").lower()
            fields.append((name, line))
    return fields


def _join(lines: Iterable[bytes], body: bytes) -> bytes:
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def without_bcc(raw: bytes) -> bytes:
    """The message as it is transmitted: every Bcc header field removed, nothing else
    touched (the recipients in Bcc get it through the SMTP envelope only)."""
    header, body = _split_header(raw)
    fields = _split_fields(header)
    if not any(name == "bcc" for name, _ in fields):
        return raw
    return _join((line for name, line in fields if name != "bcc"), body)


def prepare_stored_draft(
    raw: bytes, account_email: str, now: datetime | None = None
) -> StoredDraft:
    """Make a stored draft ready to send as-is: its body bytes stay untouched, the Date is
    set to now and a missing Message-ID is added. Bcc stays in this copy (filed in Sent);
    `without_bcc` strips it for transmission."""
    raw = re.sub(rb"\r?\n", b"\r\n", raw)
    header, body = _split_header(raw)
    parsed = BytesHeaderParser(policy=policy.default).parsebytes(header + b"\r\n\r\n")

    def values(name: str) -> list[str]:
        out = []
        for raw_name, raw_value in parsed.raw_items():
            if raw_name.lower() == name:
                out.append(re.sub(r"\r?\n(?=[ \t])", "", str(raw_value)))
        return out

    def addresses(name: str) -> list[str]:
        pairs = email.utils.getaddresses(values(name))
        return [email.utils.formataddr(p) if p[0] else p[1] for p in pairs if p[1]]

    recipients = collect_recipients(addresses("to"), addresses("cc"), addresses("bcc"))
    ids = values("message-id")
    message_id = " ".join(ids[0].split()) if ids else ""
    date = f"Date: {email.utils.format_datetime(now or datetime.now(UTC))}".encode()
    lines = [date]
    if not message_id:
        message_id = email.utils.make_msgid(domain=account_email.rpartition("@")[2])
        lines.append(f"Message-ID: {message_id}".encode())
    lines += [line for name, line in _split_fields(header) if name != "date"]
    return StoredDraft(sent_copy=_join(lines, body), recipients=recipients, message_id=message_id)


# -- rate limit --------------------------------------------------------------------------------


class SendRateLimiter:
    """At most `per_hour` sends per account in any 60-minute window (in memory, per
    process). 0 means unlimited."""

    WINDOW = 3600.0

    def __init__(self, per_hour: int, clock: Callable[[], float] = time.monotonic):
        self.per_hour = per_hour
        self.clock = clock
        self._sent: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def acquire(self, email: str) -> None:
        """Count one send for `email`, or raise `SendLimitExceeded`."""
        if self.per_hour <= 0:
            return
        key = email.strip().lower()
        now = self.clock()
        with self._lock:
            window = self._sent.setdefault(key, deque())
            while window and now - window[0] >= self.WINDOW:
                window.popleft()
            if len(window) >= self.per_hour:
                wait = max(1, int((self.WINDOW - (now - window[0])) // 60) + 1)
                raise SendLimitExceeded(
                    f"sending limit reached for {key}: at most {self.per_hour} emails per hour "
                    f"(POSTROOM_SEND_LIMIT_PER_HOUR); try again in about {wait} minutes"
                )
            window.append(now)
