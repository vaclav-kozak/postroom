"""Pure MIME parsing, HTML->text conversion, and message (RFC 5322) building.

No network or IMAP calls live here -- this module only ever touches bytes it
is handed and returns plain data; it never sends anything itself.
"""

import binascii
import dataclasses
import email
import email.header
import email.parser
import email.utils
import quopri
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from email import policy
from email.headerregistry import Address as HeaderAddress
from email.message import EmailMessage, Message
from html import unescape as html_unescape

from bs4 import BeautifulSoup
from markdownify import MarkdownConverter

from postroom.mail.heavy import heavy_work
from postroom.mail.models import AttachmentInfo, OutgoingFile, ParsedMessage

_ATTACHMENT_MAINTYPES = {b"application", b"image", b"audio", b"video"}

_TOO_DEEPLY_NESTED = "[message structure too deeply nested to parse]"

# The stdlib parser costs about 30x the size of the header block (5 MiB of short header
# lines: +145 MiB), and whoever sends the mail controls it. Header lines past this many
# bytes are dropped before parsing. Real mail carries 2-50 KB of headers, long
# Received/ARC/DKIM chains included.
MAX_HEADER_BYTES = 256 * 1024

# Single cap for `html_to_text`, applied before either the main (BeautifulSoup /
# markdownify) or fallback (crude regex) path runs. The main path costs roughly 2s/MB
# on tag-dense HTML, and body text is truncated downstream regardless, so there is no
# benefit to processing more than this much HTML either way. (There used to be a
# separate, larger cap inside the crude fallback only; it's redundant now that every
# caller of `_crude_html_to_text` goes through this one first.)
_MAX_HTML_CHARS = 1_000_000

# The tree converter's memory grows with the number of nodes, not characters: about
# 600 bytes per tag (200 KB of `<br>` is 51k tags and +31 MiB; a 1 MB newsletter with
# ~50k tags is +25 MiB). Above this many `<` (script/style excluded) the linear crude
# path is used instead, which keeps the converter's peak near 30 MiB.
_MAX_RICH_HTML_TAGS = 50_000

_TAG_RE = re.compile(r"<[^<>]*>")  # `[^<>]*` (not `[^>]+`): can't run past the next `<`,
# so a match attempt fails in O(1) instead of scanning to end-of-string first.


def _strip_script_style(html: str) -> str:
    """Remove `<script>...</script>` and `<style>...</style>` blocks in one linear scan.

    Deliberately NOT a lazy/backreferenced regex (`<(script|style)\\b[^>]*>.*?</\\1>`
    with DOTALL): that pattern is quadratic on hostile input with many unclosed
    openers (each failed match re-scans from the next `<`).

    Every `str.find` call starts at (and each iteration advances) `pos`, so the whole
    scan is O(n). The positions of the next `<script`/`<style` are cached across
    iterations and only ever recomputed when they've fallen behind the current `pos`
    (i.e. we've just consumed/passed them); once a lookup comes back -1 it is cached
    as "absent for the rest of the string" forever, since a later, narrower search
    can't find what an earlier, wider one already didn't. Without this caching, an
    input containing only one of the two tag types re-scans to the end of the string
    on every iteration hunting for the other one -- O(n) per iteration, O(n*k) overall.
    """
    lowered = html.lower()
    out = []
    pos = 0
    n = len(html)
    script_at = lowered.find("<script", pos)
    style_at = lowered.find("<style", pos)
    while pos < n:
        if script_at == -1 and style_at == -1:
            out.append(html[pos:])
            break
        if style_at == -1 or (script_at != -1 and script_at < style_at):
            start, closing = script_at, "</script"
        else:
            start, closing = style_at, "</style"
        out.append(html[pos:start])
        close_at = lowered.find(closing, start)
        if close_at == -1:
            # Unterminated block: drop the rest rather than rescanning for a
            # closing tag that was never going to appear.
            pos = n
            break
        end_at = lowered.find(">", close_at)
        if end_at == -1:
            pos = n
            break
        pos = end_at + 1
        if script_at != -1 and script_at < pos:
            script_at = lowered.find("<script", pos)
        if style_at != -1 and style_at < pos:
            style_at = lowered.find("<style", pos)
    return "".join(out)


def _crude_html_to_text(html: str) -> str:
    """Regex-based fallback for `html_to_text` when the tree is too deep for BeautifulSoup
    or markdownify to walk recursively without blowing the stack.

    Kept strictly linear in input length (see `_strip_script_style` and `_TAG_RE`)
    so this hostile-input path can never hang the way it can't be allowed to crash.
    Sizing the input is `html_to_text`'s job (`_MAX_HTML_CHARS`), not this function's.
    """
    text = _strip_script_style(html)
    text = _TAG_RE.sub("\n", text)
    text = html_unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n\n", text)
    return text.strip()


def decode_header_value(value: bytes | str | None) -> str:
    """Decode an RFC 2047 encoded header value to plain text."""
    if value is None:
        return ""
    s = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    try:
        return str(email.header.make_header(email.header.decode_header(s)))
    except Exception:  # noqa: BLE001 -- header decoding can fail in many ways; fall back to raw
        return s


# RFC 5322 "specials": a display name containing one must be quoted, or a reader of the
# formatted address (e.g. a reply built from it) splits "Doe, John <j@x>" at the comma.
_ADDRESS_SPECIALS = re.compile(r'[][\\()<>@,:;".]')


def format_address(name: str | None, addr: str) -> str:
    """The address as `Name <addr>` (the name quoted when needed, not encoded), or `addr`."""
    if not name:
        return addr
    if _ADDRESS_SPECIALS.search(name):
        name = '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f"{name} <{addr}>"


def format_addresses(addrs) -> list[str]:
    """Format imapclient `Address` tuples as "Name <mailbox@host>" / "mailbox@host"."""
    if not addrs:
        return []
    out = []
    for a in addrs:
        if a.host is None:
            continue  # group marker (e.g. "undisclosed-recipients:;")
        mailbox = a.mailbox.decode("utf-8", "replace") if a.mailbox else ""
        host = a.host.decode("utf-8", "replace") if a.host else ""
        addr = f"{mailbox}@{host}"
        name = decode_header_value(a.name) if a.name else ""
        out.append(format_address(name, addr))
    return out


def html_to_text(html: str) -> str:
    """Strip scripts/styles/head and render remaining HTML as Markdown-ish text.

    Falls back to a crude regex tag-strip on `RecursionError`, which BeautifulSoup's
    recursive tree walk (and markdownify's recursive descent) can raise on hostile,
    deeply-nested HTML, and for tag-dense HTML (more than `_MAX_RICH_HTML_TAGS` tags),
    whose tree would cost too much memory. The input is capped at `_MAX_HTML_CHARS`
    before either path runs, independent of which one ends up handling it.

    Runs under the process-wide heavy-work gate, so call it from a worker thread.
    """
    html = _strip_script_style(html[:_MAX_HTML_CHARS])
    if html.count("<") > _MAX_RICH_HTML_TAGS:
        return _crude_html_to_text(html)
    try:
        with heavy_work():
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style", "head"]):
                tag.decompose()
            text = MarkdownConverter(heading_style="ATX").convert_soup(soup)
    except RecursionError:
        return _crude_html_to_text(html)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    extra = len(text) - max_chars
    return text[:max_chars] + f"\n\n[… truncated, {extra} more characters]", True


def bodystructure_has_attachment(bs) -> bool:
    """Recursively inspect an imapclient BODYSTRUCTURE tuple for attachment-like parts."""
    if not isinstance(bs, (tuple, list)):
        return False
    if bs and isinstance(bs[0], bytes) and bs[0].lower() in _ATTACHMENT_MAINTYPES:
        return True
    for item in bs:
        if isinstance(item, bytes) and item.lower() in (b"attachment", b"filename"):
            return True
        if isinstance(item, (tuple, list)) and bodystructure_has_attachment(item):
            return True
    return False


def _header(msg, name: str, default: str = "") -> str:
    try:
        value = msg[name]
        return str(value) if value is not None else default
    except Exception:  # noqa: BLE001 -- malformed headers can raise many exception types
        # `msg.get()` goes through the same refined/policy-based parsing that just
        # raised, so it is not a real fallback. Read the raw, unrefined header text
        # instead -- this is the one code path that cannot re-trigger the failure.
        for raw_name, raw_value in msg.raw_items():
            if raw_name.lower() == name.lower():
                return raw_value
        return default


def _addr_list(msg: Message, name: str) -> list[str]:
    raw = _header(msg, name)
    if not raw:
        return []
    out = []
    for display_name, addr in email.utils.getaddresses([raw]):
        if not addr:
            continue
        out.append(format_address(display_name, addr))
    return out


def _addr_single(msg: Message, name: str) -> str:
    raw = _header(msg, name)
    if not raw:
        return ""
    addrs = email.utils.getaddresses([raw])
    if not addrs:
        return ""
    display_name, addr = addrs[0]
    return format_address(display_name, addr) if addr else ""


def _content_text(part: Message) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def _walk_parts(part: Message):
    """Yield leaf-like parts in depth-first order.

    A `message/rfc822` part is treated as a single leaf and is *not* descended into,
    even though the stdlib's `is_multipart()` reports `True` for it (its payload is a
    one-element list holding the embedded message) -- descending into it would attach
    its inner parts at unpredictable indexes instead of counting the forwarded message
    as one attachment.
    """
    if part.get_content_type() == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        for sub in part.get_payload():
            yield from _walk_parts(sub)
    else:
        yield part


def _iter_attachment_parts(msg: Message):
    """Yield (index, filename, content_type, payload_bytes, inline, charset) per attachment.

    Shared by `parse_message` and `get_attachment` so indexes always agree. A
    `message/rfc822` part counts as exactly one attachment; its payload is the
    embedded message serialized whole (`part.get_payload(0).as_bytes()`), not its
    decoded body.
    """
    plain_part = msg.get_body(("plain",))
    html_part = msg.get_body(("html",))
    idx = 0
    for part in _walk_parts(msg):
        if part is plain_part or part is html_part:
            continue
        if part.get_content_type() == "message/rfc822":
            filename = part.get_filename() or "attached-message.eml"
            embedded = part.get_payload(0)
            payload = embedded.as_bytes() if embedded is not None else b""
            yield idx, filename, "message/rfc822", payload, False, None
            idx += 1
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        maintype = part.get_content_maintype()
        looks_like_attachment = (disposition in ("attachment", "inline") and filename) or (
            maintype not in ("text", "multipart")
        )
        if not looks_like_attachment:
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() if maintype == "text" else None
        yield idx, filename, part.get_content_type(), payload, (disposition == "inline"), charset
        idx += 1


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse raw RFC 5322 bytes into a `ParsedMessage`.

    Never raises on hostile input: pathologically nested MIME structures can make
    the stdlib `email` parser (or our own recursive attachment walk) raise
    `RecursionError`, in which case we fall back to a headers-only parse so the
    caller still gets a usable subject/from/to/etc.
    """
    raw = _cap_header(raw)
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
        return _parse_message(msg)
    except RecursionError:
        return _parse_message_headers_only(raw)


def _header_end(raw: bytes) -> int:
    """Index of the newline that ends the header block (len(raw) when there is no body)."""
    ends = [i for i in (raw.find(b"\n\r\n"), raw.find(b"\n\n")) if i != -1]
    return min(ends) if ends else len(raw)


def _cap_header(raw: bytes) -> bytes:
    """Drop header lines beyond `MAX_HEADER_BYTES`, keeping the body intact."""
    if len(raw) <= MAX_HEADER_BYTES or raw.startswith((b"\r\n", b"\n")):
        return raw
    end = _header_end(raw)
    if end <= MAX_HEADER_BYTES:
        return raw
    cut = raw.rfind(b"\n", 0, MAX_HEADER_BYTES) + 1 or MAX_HEADER_BYTES
    return raw[:cut] + raw[end + 1 :]


def _with_headers(
    msg: Message, body_text: str, body_source: str, attachments: list[AttachmentInfo]
) -> ParsedMessage:
    """A `ParsedMessage` with the header fields read from `msg` and the given body."""
    references_raw = _header(msg, "References")
    date_raw = _header(msg, "Date")
    date = None
    if date_raw:
        try:
            date = email.utils.parsedate_to_datetime(date_raw).isoformat()
        except Exception:  # noqa: BLE001 -- malformed date headers can fail in many ways
            date = None
    return ParsedMessage(
        subject=_header(msg, "Subject"),
        from_=_addr_single(msg, "From"),
        to=_addr_list(msg, "To"),
        cc=_addr_list(msg, "Cc"),
        reply_to=_addr_list(msg, "Reply-To"),
        date=date,
        message_id=_header(msg, "Message-ID") or None,
        in_reply_to=_header(msg, "In-Reply-To") or None,
        references=references_raw.split() if references_raw else [],
        body_text=body_text,
        body_source=body_source,
        attachments=attachments,
    )


def _parse_message(msg: Message) -> ParsedMessage:
    plain_part = msg.get_body(("plain",))
    html_part = msg.get_body(("html",))
    plain_text = _content_text(plain_part) if plain_part is not None else None

    if plain_text is not None and len(plain_text.strip()) > 20:
        body_text, body_source = plain_text, "plain"
    elif html_part is not None:
        body_text = html_to_text(_content_text(html_part))
        body_source = "html"
    elif plain_text is not None:
        body_text, body_source = plain_text, "plain"
    else:
        body_text, body_source = "", "none"

    attachments = [
        AttachmentInfo(
            index=idx,
            filename=filename,
            content_type=content_type,
            size=len(payload),
            inline=inline,
            charset=charset,
        )
        for idx, filename, content_type, payload, inline, charset in _iter_attachment_parts(msg)
    ]
    return _with_headers(msg, body_text, body_source, attachments)


def _parse_message_headers_only(raw: bytes) -> ParsedMessage:
    """Headers-only fallback used when the full body/MIME parse is too deeply nested."""
    msg = email.parser.BytesHeaderParser(policy=policy.default).parsebytes(raw)
    return _with_headers(msg, _TOO_DEEPLY_NESTED, "none", [])


def get_attachment(raw: bytes, index: int) -> tuple[AttachmentInfo, bytes]:
    raw = _cap_header(raw)
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
        for idx, filename, content_type, payload, inline, charset in _iter_attachment_parts(msg):
            if idx == index:
                info = AttachmentInfo(
                    index=idx,
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    inline=inline,
                    charset=charset,
                )
                return info, payload
    except RecursionError:
        raise KeyError(
            f"attachment {index} unavailable: message too deeply nested to parse"
        ) from None
    raise KeyError(index)


# -- messages too large to parse whole: work from the server's BODYSTRUCTURE -------------
#
# The functions below mirror `EmailMessage.get_body()` and `_iter_attachment_parts` over an
# imapclient BODYSTRUCTURE, so a big message is read by fetching single sections
# (`BODY.PEEK[<section>]`) instead of the whole message.


@dataclasses.dataclass(eq=False)
class StructPart:
    """One node of a BODYSTRUCTURE. `children` is None for a leaf."""

    section: str  # IMAP part number, e.g. "1.2"
    content_type: str  # lower case, e.g. "text/plain"
    encoding: str  # lower-case Content-Transfer-Encoding
    size: int  # encoded octets, as reported by the server
    disposition: str | None
    filename: str | None
    charset: str | None
    content_id: str | None
    start: str | None  # the "start" parameter of a multipart/related
    children: list["StructPart"] | None

    @property
    def maintype(self) -> str:
        return self.content_type.partition("/")[0]

    @property
    def decoded_size(self) -> int:
        """Estimated decoded size (base64 lines are 76 characters plus CRLF)."""
        return self.size * 57 // 78 if self.encoding == "base64" else self.size


@dataclasses.dataclass
class StructurePlan:
    plain: StructPart | None
    html: StructPart | None
    attachments: list[tuple[AttachmentInfo, StructPart]]


_PARAM_NAME = re.compile(r"[A-Za-z0-9*_.-]+")


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _param_list(value) -> list[tuple[str, str]]:
    """imapclient's flat (name, value, name, value, ...) tuple as clean pairs."""
    if not isinstance(value, (list, tuple)):
        return []
    items = [_text(v) or "" for v in value]
    return [
        (name, re.sub(r"[\r\n\x00]", " ", val))
        for name, val in zip(items[::2], items[1::2], strict=False)
        if _PARAM_NAME.fullmatch(name)
    ]


def _format_params(pairs: list[tuple[str, str]]) -> str:
    out = []
    for name, value in pairs:
        if name.endswith("*"):  # RFC 2231 extended value: already a token, sent raw
            out.append(f"; {name}={value}")
        else:
            out.append('; {}="{}"'.format(name, value.replace("\\", "\\\\").replace('"', '\\"')))
    return "".join(out)


def _mime_headers(content_type: str, params, disposition) -> Message:
    """A header-only message rebuilt from BODYSTRUCTURE data, so the stdlib decodes the
    parameters (RFC 2231 continuations and charsets, RFC 2047 words) exactly as it does
    for a fully parsed message."""
    lines = [f"Content-Type: {content_type}{_format_params(_param_list(params))}"]
    if isinstance(disposition, (list, tuple)) and disposition:
        kind = _text(disposition[0]) or ""
        if _PARAM_NAME.fullmatch(kind):
            extra = disposition[1] if len(disposition) > 1 else None
            lines.append(f"Content-Disposition: {kind}{_format_params(_param_list(extra))}")
    return email.message_from_string("\r\n".join(lines) + "\r\n\r\n", policy=policy.default)


def _safe_call(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 -- malformed parameters can raise many types
        return None


def _struct_node(bs, section: str) -> StructPart:
    if isinstance(bs[0], list):  # multipart: ([parts], subtype, params, disposition, ...)
        subtype = (_text(bs[1]) or "mixed").lower() if len(bs) > 1 else "mixed"
        headers = _mime_headers(
            f"multipart/{subtype}", bs[2] if len(bs) > 2 else None, bs[3] if len(bs) > 3 else None
        )
        prefix = f"{section}." if section else ""
        children = [_struct_node(child, f"{prefix}{i}") for i, child in enumerate(bs[0], 1)]
        return StructPart(
            section=section or "",
            content_type=f"multipart/{subtype}",
            encoding="7bit",
            size=0,
            disposition=_safe_call(headers.get_content_disposition),
            filename=None,
            charset=None,
            content_id=None,
            start=_safe_call(lambda: headers.get_param("start")),
            children=children,
        )

    maintype = (_text(bs[0]) or "application").lower()
    subtype = (_text(bs[1]) or "octet-stream").lower()
    content_type = f"{maintype}/{subtype}"
    # Extension data sits after the type-specific fields (RFC 3501 7.4.2).
    if maintype == "text":
        disp_at = 9  # ... size, lines, md5, disposition
    elif content_type == "message/rfc822":
        disp_at = 11  # ... size, envelope, body, lines, md5, disposition
    else:
        disp_at = 8  # ... size, md5, disposition
    disposition = bs[disp_at] if len(bs) > disp_at else None
    headers = _mime_headers(content_type, bs[2] if len(bs) > 2 else None, disposition)
    size = bs[6] if len(bs) > 6 and isinstance(bs[6], int) else 0
    return StructPart(
        section=section or "1",  # a single-part message's body is section 1
        content_type=content_type,
        encoding=((_text(bs[5]) if len(bs) > 5 else None) or "7bit").lower(),
        size=size,
        disposition=_safe_call(headers.get_content_disposition),
        filename=_safe_call(headers.get_filename),
        charset=_safe_call(headers.get_content_charset) if maintype == "text" else None,
        content_id=(_text(bs[3]) if len(bs) > 3 else None),
        start=None,
        children=None,
    )


def _struct_find_body(part: StructPart, subtype: str) -> StructPart | None:
    """`EmailMessage.get_body((subtype,))` over a BODYSTRUCTURE."""
    if part.disposition == "attachment":
        return None
    maintype, _, sub = part.content_type.partition("/")
    if maintype == "text":
        return part if sub == subtype else None
    if maintype != "multipart" or part.children is None:
        return None
    if sub != "related":
        for child in part.children:
            found = _struct_find_body(child, subtype)
            if found is not None:
                return found
        return None
    candidate = None
    if part.start:
        candidate = next((c for c in part.children if c.content_id == part.start), None)
    if candidate is None and part.children:
        candidate = part.children[0]
    return _struct_find_body(candidate, subtype) if candidate is not None else None


def _struct_leaves(part: StructPart):
    if part.children is None:
        yield part
        return
    for child in part.children:
        yield from _struct_leaves(child)


def count_parts(bs) -> int:
    """Number of leaf parts in a BODYSTRUCTURE (0 when it is missing or malformed)."""
    if not isinstance(bs, (list, tuple)) or not bs:
        return 0
    if isinstance(bs[0], list):
        return sum(count_parts(child) for child in bs[0])
    return 1


def structure_plan(bs) -> StructurePlan:
    """Body parts and attachments of a message from its BODYSTRUCTURE.

    Attachment indexes follow the same rules as `parse_message`. Raises `ValueError` when
    the structure is missing or unusable.
    """
    if not isinstance(bs, (list, tuple)) or not bs:
        raise ValueError("the server did not describe this message's structure")
    try:
        root = _struct_node(bs, "")
    except (IndexError, TypeError, RecursionError) as e:
        raise ValueError("the server did not describe this message's structure") from e
    plain = _struct_find_body(root, "plain")
    html = _struct_find_body(root, "html")
    attachments = []
    for part in _struct_leaves(root):
        if part is plain or part is html:
            continue
        if part.content_type == "message/rfc822":
            filename, inline, charset = part.filename or "attached-message.eml", False, None
        else:
            looks_like_attachment = (
                part.disposition in ("attachment", "inline") and part.filename
            ) or part.maintype not in ("text", "multipart")
            if not looks_like_attachment:
                continue
            filename, inline, charset = part.filename, part.disposition == "inline", part.charset
        info = AttachmentInfo(
            index=len(attachments),
            filename=filename,
            content_type=part.content_type,
            size=part.decoded_size,
            inline=inline,
            charset=charset,
        )
        attachments.append((info, part))
    return StructurePlan(plain=plain, html=html, attachments=attachments)


def decode_transfer(data: bytes, encoding: str) -> bytes:
    """Undo a Content-Transfer-Encoding; tolerates data cut off mid-stream."""
    if encoding == "base64":
        try:
            return binascii.a2b_base64(data)  # skips line breaks and other non-alphabet bytes
        except binascii.Error:  # bad or missing padding, e.g. a cut-off partial fetch
            clean = re.sub(rb"[^A-Za-z0-9+/]", b"", data)
            clean = clean[: len(clean) - len(clean) % 4] if len(clean) % 4 == 1 else clean
            try:
                return binascii.a2b_base64(clean + b"=" * (-len(clean) % 4))
            except binascii.Error:
                return b""
    if encoding == "quoted-printable":
        return quopri.decodestring(data)
    return data


def _decode_charset(data: bytes, charset: str | None) -> str:
    try:
        return data.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def parse_large_message(
    header: bytes, plan: StructurePlan, texts: dict[str, bytes]
) -> ParsedMessage:
    """A `ParsedMessage` from the header block, the fetched (possibly cut-off) text parts
    keyed by section, and the structure plan. Same body choice as `parse_message`."""
    msg = email.parser.BytesHeaderParser(policy=policy.default).parsebytes(_cap_header(header))

    def text_of(part: StructPart | None) -> str | None:
        if part is None or part.section not in texts:
            return None
        return _decode_charset(decode_transfer(texts[part.section], part.encoding), part.charset)

    plain_text = text_of(plan.plain)
    html_text = text_of(plan.html)
    if plain_text is not None and len(plain_text.strip()) > 20:
        body_text, body_source = plain_text, "plain"
    elif html_text is not None:
        body_text, body_source = html_to_text(html_text), "html"
    elif plain_text is not None:
        body_text, body_source = plain_text, "plain"
    else:
        body_text, body_source = "", "none"
    return _with_headers(msg, body_text, body_source, [info for info, _ in plan.attachments])


def _attach(msg: EmailMessage, f: OutgoingFile) -> None:
    """Add one attachment. An attached email (message/rfc822) is embedded as a message,
    which is how RFC 2046 wants it (never base64); anything unusable becomes bytes."""
    maintype, _, subtype = f.content_type.partition("/")
    if f.content_type == "message/rfc822":
        try:
            inner = email.message_from_bytes(_cap_header(f.data), policy=policy.default)
            msg.add_attachment(inner, filename=f.filename)
            return
        except (RecursionError, ValueError, TypeError):
            maintype, subtype = "application", "octet-stream"
    if maintype in ("multipart", "message"):
        maintype, subtype = "application", "octet-stream"
    msg.add_attachment(f.data, maintype=maintype, subtype=subtype, filename=f.filename)


def build_message(
    *,
    from_addr: str,
    from_name: str | None,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body: str,
    html: bool,
    in_reply_to: str | None,
    references: list[str],
    attachments: Sequence[OutgoingFile] = (),
    msg_policy: policy.EmailPolicy = policy.SMTP,
) -> tuple[EmailMessage, str]:
    """Build an RFC 5322 message and return it with its Message-ID.

    Bcc is kept as a header: a draft or a Sent copy carries it, and whoever transmits the
    message must remove it first (`MailService.send` does; so does the owner's mail app
    when it sends a draft).
    """
    msg = EmailMessage(policy=msg_policy)
    msg["From"] = HeaderAddress(display_name=from_name or "", addr_spec=from_addr)
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    msg["Subject"] = subject
    msg["Date"] = email.utils.format_datetime(datetime.now(UTC))
    msgid = email.utils.make_msgid(domain=from_addr.split("@")[1])
    msg["Message-ID"] = msgid
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = " ".join(references)

    if html:
        msg.set_content(html_to_text(body))
        msg.add_alternative(body, subtype="html")
    else:
        msg.set_content(body)
    for f in attachments:
        _attach(msg, f)
    return msg, msgid


def build_draft(
    *,
    from_addr: str,
    from_name: str | None,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body: str,
    html: bool,
    in_reply_to: str | None,
    references: list[str],
) -> tuple[bytes, str]:
    """Build a draft (CRLF bytes, Bcc kept for the owner's mail app) and its Message-ID."""
    msg, msgid = build_message(
        from_addr=from_addr,
        from_name=from_name,
        to=to,
        cc=cc,
        bcc=bcc,
        subject=subject,
        body=body,
        html=html,
        in_reply_to=in_reply_to,
        references=references,
    )
    return msg.as_bytes(), msgid


def iter_attachments(raw: bytes):
    """(AttachmentInfo, payload) for every attachment of a whole message, in the same order
    and with the same indexes as `parse_message` lists them."""
    raw = _cap_header(raw)
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
        items = list(_iter_attachment_parts(msg))
    except RecursionError:
        raise ValueError("the email is too deeply nested to read its attachments") from None
    for idx, filename, content_type, payload, inline, charset in items:
        info = AttachmentInfo(idx, filename, content_type, len(payload), inline, charset)
        yield info, payload
