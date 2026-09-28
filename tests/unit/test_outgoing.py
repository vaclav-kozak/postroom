"""Building outgoing mail: recipients, header injection, replies, forwards, attachments,
stored drafts, Bcc handling and the send rate limit."""

import base64
import email
from datetime import UTC, datetime
from email import policy

import pytest

from postroom.mail.models import ParsedMessage
from postroom.mail.outgoing import (
    FORWARD_MARKER,
    MAX_ATTACHMENT_BYTES,
    MAX_RECIPIENTS,
    SendLimitExceeded,
    SendRateLimiter,
    check_subject,
    collect_recipients,
    decode_attachments,
    forward_body,
    forward_subject,
    normalize_content_type,
    parse_recipient,
    prepare_stored_draft,
    reply_recipients,
    reply_subject,
    sanitize_filename,
    without_bcc,
)
from postroom.mail.parse import build_message

ME = "user@example.com"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# -- recipients ------------------------------------------------------------------------------


def test_recipient_forms():
    r = parse_recipient("  Alice Example <Alice@Example.org> ")
    assert r.addr == "Alice@Example.org" and r.key == "alice@example.org"
    assert r.header == "Alice Example <Alice@Example.org>"
    assert parse_recipient("bob@example.org").header == "bob@example.org"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "no-at-sign",
        "@example.org",
        "user@",
        "a@example.org, b@example.org",
        "a@example.org\r\nBcc: victim@example.org",
        "a@example.org\nX: y",
        "a@example.org\x00",
        "x" * 310 + "@example.org",
        None,
        42,
    ],
)
def test_bad_recipients_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_recipient(bad)


def test_international_domain_goes_out_as_punycode():
    assert parse_recipient("jan@příklad.example").addr == "jan@xn--pklad-zsa96e.example"


def test_collect_dedupes_across_lists_and_counts():
    r = collect_recipients(
        ["a@example.org", "A@example.org"], ["b@example.org", "a@example.org"], ["c@example.org"]
    )
    assert r.envelope == ["a@example.org", "b@example.org", "c@example.org"]
    assert r.headers("cc") == ["b@example.org"]


def test_recipient_count_limits():
    with pytest.raises(ValueError, match="at least one recipient"):
        collect_recipients([], [], [])
    many = [f"u{i}@example.org" for i in range(MAX_RECIPIENTS)]
    assert len(collect_recipients(many[:30], many[30:], []).envelope) == MAX_RECIPIENTS
    with pytest.raises(ValueError, match=f"at most {MAX_RECIPIENTS} recipients"):
        collect_recipients(many, [], ["one-more@example.org"])


@pytest.mark.parametrize("subject", ["a\r\nBcc: x@example.org", "a\nb", "a\rb", "a\x00b"])
def test_subject_injection_is_rejected(subject):
    with pytest.raises(ValueError, match="line breaks"):
        check_subject(subject)


def test_subject_length():
    check_subject("ok")
    check_subject(None)
    with pytest.raises(ValueError, match="at most"):
        check_subject("x" * 1001)


# -- replies and forwards ----------------------------------------------------------------------


def original(**kw) -> ParsedMessage:
    base = {
        "message_id": "<orig@example.org>",
        "in_reply_to": None,
        "references": ["<root@example.org>"],
        "from_": "Alice <alice@example.org>",
        "to": [ME, "bob@example.org"],
        "cc": ["Carol <carol@example.org>", "USER@example.com"],
        "reply_to": [],
        "subject": "Plans",
        "date": "2026-09-20T10:00:00+00:00",
        "body_text": "Original text",
        "body_source": "plain",
        "attachments": [],
    }
    base.update(kw)
    return ParsedMessage(**base)


def test_reply_subject_prefix_once():
    assert reply_subject("Plans") == "Re: Plans"
    assert reply_subject("RE: Plans") == "RE: Plans"
    assert reply_subject(None) == "Re: "


def test_reply_goes_to_sender_or_reply_to():
    assert reply_recipients(original(), [], [], False, {ME}) == (
        ["Alice <alice@example.org>"],
        [],
    )
    to, _ = reply_recipients(original(reply_to=["list@example.org"]), [], [], False, {ME})
    assert to == ["list@example.org"]


def test_reply_all_adds_to_and_cc_without_own_addresses():
    to, cc = reply_recipients(original(), [], [], True, {ME})
    assert to == ["Alice <alice@example.org>"]
    assert cc == ["bob@example.org", "Carol <carol@example.org>"]


def test_reply_all_keeps_explicit_recipients_and_dedupes():
    to, cc = reply_recipients(
        original(), ["bob@example.org"], ["carol@example.org"], True, {ME.upper()}
    )
    assert to == ["bob@example.org"]
    assert cc == ["carol@example.org"]  # nothing added twice; own address left out


def test_reply_all_to_own_email_goes_to_its_recipients():
    mine = original(from_=ME, to=["bob@example.org"], cc=["carol@example.org"])
    to, cc = reply_recipients(mine, [], [], True, {ME})
    assert to == ["bob@example.org"] and cc == ["carol@example.org"]


def test_reply_all_skips_unusable_addresses_from_the_original():
    _to, cc = reply_recipients(original(cc=["undisclosed-recipients:;"]), [], [], True, {ME})
    assert cc == ["bob@example.org"]


def test_forward_subject_and_body():
    assert forward_subject("Plans") == "Fwd: Plans"
    assert forward_subject("Fwd: Plans") == "Fwd: Plans"
    assert forward_subject("FW: Plans") == "FW: Plans"
    body = forward_body("See below.", original())
    assert body.startswith("See below.\n\n" + FORWARD_MARKER)
    assert "From: Alice <alice@example.org>" in body
    assert "Date: Sun, 20 Sep 2026 10:00:00 +0000" in body
    assert "Subject: Plans" in body and "To: user@example.com, bob@example.org" in body
    assert "Cc: Carol <carol@example.org>" in body
    assert body.endswith("\n\nOriginal text")
    assert forward_body("", original()).startswith(FORWARD_MARKER)


# -- attachments -----------------------------------------------------------------------------------


def test_filename_sanitising():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("C:\\Users\\x\\report.pdf") == "report.pdf"
    assert sanitize_filename("inv\u202efdp.exe\r\n") == "invfdp.exe"
    assert sanitize_filename("  .. ") == "attachment"
    assert sanitize_filename(None, fallback="attachment-2") == "attachment-2"
    long = sanitize_filename("a" * 300 + ".pdf")
    assert len(long) == 200 and long.endswith(".pdf")


def test_content_type_validation():
    assert normalize_content_type(None) == "application/octet-stream"
    assert normalize_content_type(" Application/PDF ") == "application/pdf"
    for bad in ("pdf", "text/plain; charset=utf-8", "text/plain\r\nX: y", "multipart/mixed", 5):
        with pytest.raises(ValueError):
            normalize_content_type(bad)


def test_decode_attachments():
    files = decode_attachments(
        [
            {"filename": "a.txt", "content_type": "text/plain", "content_base64": b64(b"hi")},
            {"filename": "../b.bin", "content_base64": b64(b"\x00\x01")},
        ]
    )
    assert [(f.filename, f.content_type, f.data) for f in files] == [
        ("a.txt", "text/plain", b"hi"),
        ("b.bin", "application/octet-stream", b"\x00\x01"),
    ]
    assert decode_attachments(None) == []


def test_attachment_errors():
    with pytest.raises(ValueError, match="not valid base64"):
        decode_attachments([{"filename": "a", "content_base64": "@@@"}])
    with pytest.raises(ValueError, match="content_base64 is required"):
        decode_attachments([{"filename": "a"}])
    big = b64(b"x" * (MAX_ATTACHMENT_BYTES // 2 + 1))
    with pytest.raises(ValueError, match="larger than 10 MiB"):
        decode_attachments([{"filename": "a", "content_base64": big}] * 2)
    with pytest.raises(ValueError, match="at most 20 attachments"):
        decode_attachments([{"filename": "a", "content_base64": b64(b"x")}] * 21)


# -- building and Bcc ------------------------------------------------------------------------------

SEND_POLICY = policy.SMTP.clone(cte_type="7bit")


def build(**kw):
    args = {
        "from_addr": ME,
        "from_name": "Me",
        "to": ["bob@example.org"],
        "cc": [],
        "bcc": ["secret@example.org"],
        "subject": "Hello",
        "body": "Body text žluťoučký",
        "html": False,
        "in_reply_to": None,
        "references": [],
        "msg_policy": SEND_POLICY,
    }
    args.update(kw)
    msg, msgid = build_message(**args)
    return msg.as_bytes(), msgid


def test_sent_copy_keeps_bcc_and_the_wire_copy_does_not():
    raw, msgid = build()
    assert b"\r\nBcc: secret@example.org\r\n" in raw
    wire = without_bcc(raw)
    assert b"bcc" not in wire.lower().split(b"\r\n\r\n", 1)[0]
    assert b"secret@example.org" not in wire
    assert raw.replace(b"Bcc: secret@example.org\r\n", b"") == wire
    assert wire.isascii()  # 7-bit transfer encodings: any server takes it
    assert msgid in raw.decode()


def test_without_bcc_removes_folded_and_repeated_fields_only_in_the_header():
    raw = (
        b"From: a@example.org\r\nBcc: x@example.org,\r\n y@example.org\r\n"
        b"To: b@example.org\r\nbcc: z@example.org\r\n\r\nBcc: stays in the body\r\n"
    )
    assert without_bcc(raw) == (
        b"From: a@example.org\r\nTo: b@example.org\r\n\r\nBcc: stays in the body\r\n"
    )
    no_bcc = b"From: a@example.org\r\n\r\nbody"
    assert without_bcc(no_bcc) is no_bcc


def test_attachments_are_built_as_parts():
    files = decode_attachments(
        [
            {
                "filename": "r.pdf",
                "content_type": "application/pdf",
                "content_base64": b64(b"%PDF"),
            },
            {"filename": "n.txt", "content_type": "text/plain", "content_base64": b64(b"note")},
        ]
    )
    raw, _ = build(attachments=files)
    msg = email.message_from_bytes(raw, policy=policy.default)
    parts = list(msg.iter_attachments())
    assert [(p.get_filename(), p.get_content_type()) for p in parts] == [
        ("r.pdf", "application/pdf"),
        ("n.txt", "text/plain"),
    ]
    assert parts[0].get_content() == b"%PDF"
    assert msg.get_body(("plain",)).get_content().strip() == "Body text žluťoučký"


def test_reply_headers_in_the_built_message():
    raw, _ = build(in_reply_to="<orig@example.org>", references=["<a@x>", "<orig@example.org>"])
    msg = email.message_from_bytes(raw, policy=policy.default)
    assert msg["In-Reply-To"] == "<orig@example.org>"
    assert msg["References"] == "<a@x> <orig@example.org>"


# -- stored drafts -------------------------------------------------------------------------------


DRAFT = (
    b"From: Me <user@example.com>\r\n"
    b"To: Bob <bob@example.org>,\r\n carol@example.org\r\n"
    b"Cc: dan@example.org\r\n"
    b"Bcc: hidden@example.org\r\n"
    b"Subject: Draft\r\n"
    b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
    b"Message-ID: <draft-1@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hello\r\n"
)


def test_prepare_stored_draft():
    now = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
    d = prepare_stored_draft(DRAFT, ME, now=now)
    assert d.message_id == "<draft-1@example.com>"
    assert d.recipients.envelope == [
        "bob@example.org",
        "carol@example.org",
        "dan@example.org",
        "hidden@example.org",
    ]
    assert d.sent_copy.startswith(b"Date: Mon, 28 Sep 2026 12:00:00 +0000\r\n")
    assert d.sent_copy.count(b"Date:") == 1
    assert b"Bcc: hidden@example.org" in d.sent_copy  # kept for the Sent copy
    assert b"hidden@example.org" not in without_bcc(d.sent_copy)
    assert d.sent_copy.endswith(b"\r\n\r\nHello\r\n")


def test_stored_draft_without_message_id_gets_one_and_lf_is_normalised():
    raw = b"From: user@example.com\nTo: bob@example.org\nSubject: x\n\nbody\n"
    d = prepare_stored_draft(raw, ME)
    assert d.message_id.endswith("@example.com>")
    assert f"Message-ID: {d.message_id}".encode() in d.sent_copy
    assert b"\n" not in d.sent_copy.replace(b"\r\n", b"")


def test_stored_draft_without_recipients_is_refused():
    with pytest.raises(ValueError, match="at least one recipient"):
        prepare_stored_draft(b"From: user@example.com\r\nSubject: x\r\n\r\nbody", ME)


# -- rate limit ------------------------------------------------------------------------------------


def test_rate_limit_sliding_window():
    now = [1000.0]
    limiter = SendRateLimiter(2, clock=lambda: now[0])
    limiter.acquire(ME)
    limiter.acquire("other@example.org")
    now[0] += 10
    limiter.acquire(ME.upper())
    with pytest.raises(SendLimitExceeded, match="at most 2 emails per hour") as e:
        limiter.acquire(ME)
    assert "POSTROOM_SEND_LIMIT_PER_HOUR" in str(e.value)
    now[0] += 3590  # the first send leaves the window
    limiter.acquire(ME)
    with pytest.raises(SendLimitExceeded):
        limiter.acquire(ME)


def test_rate_limit_zero_is_unlimited():
    limiter = SendRateLimiter(0)
    for _ in range(1000):
        limiter.acquire(ME)
