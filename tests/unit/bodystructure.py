"""Test helper: an imapclient-style BODYSTRUCTURE for a message, the way an IMAP server
(Dovecot) builds it: raw parameters (RFC 2231 names untouched), encoded sizes, section
layout of RFC 3501 7.4.2."""

import email
import re

from imapclient.response_types import BodyData


def _split_params(raw: str | None) -> tuple[str, tuple]:
    """'text/plain; charset="utf-8"; name*=utf-8''x' -> ('text/plain', (b'CHARSET', b'utf-8', ...))"""
    if raw is None:
        return "", ()
    raw = re.sub(r"\r?\n[ \t]", " ", raw)
    items, cur, quoted = [], "", False
    for ch in raw:
        if ch == '"':
            quoted = not quoted
        if ch == ";" and not quoted:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    value, params = items[0].strip(), []
    for item in items[1:]:
        if "=" not in item:
            continue
        name, _, val = item.strip().partition("=")
        val = val.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        params += [name.strip().upper().encode(), val.encode()]
    return value, tuple(params)


def _body(part: email.message.Message) -> bytes:
    raw = part.as_bytes()
    return raw.split(b"\n\n", 1)[1] if b"\n\n" in raw else b""


def bodystructure(part: email.message.Message):
    ctype, params = _split_params(part.get("Content-Type"))
    maintype, _, subtype = (ctype or "text/plain").partition("/")
    disp_raw = part.get("Content-Disposition")
    if disp_raw:
        kind, disp_params = _split_params(disp_raw)
        disposition = (kind.upper().encode(), disp_params or None)
    else:
        disposition = None
    if part.is_multipart() and maintype.lower() == "multipart":
        children = [bodystructure(sub) for sub in part.get_payload()]
        return BodyData.create(
            (*children, subtype.upper().encode(), params or None, disposition, None, None)
        )
    cid = part.get("Content-ID")
    enc = (part.get("Content-Transfer-Encoding") or "7bit").upper().encode()
    body = _body(part)
    fields = (
        maintype.upper().encode(),
        subtype.upper().encode(),
        params or None,
        cid.encode() if cid else None,
        None,
        enc,
        len(body),
    )
    if maintype.lower() == "text":
        return BodyData.create((*fields, body.count(b"\n"), None, disposition, None, None))
    if ctype.lower() == "message/rfc822":
        inner = bodystructure(part.get_payload(0))
        return BodyData.create((*fields, None, inner, 0, None, disposition, None, None))
    return BodyData.create((*fields, None, disposition, None, None))


def bodystructure_of(raw: bytes):
    return bodystructure(email.message_from_bytes(raw))
