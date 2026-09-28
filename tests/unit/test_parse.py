import email
import json
import sys
import time
from datetime import date
from email import policy
from email.message import EmailMessage

from imapclient.response_types import Address

from postroom.mail import models, parse


def _mixed() -> bytes:
    m = EmailMessage()
    m["From"] = "=?utf-8?q?Tom=C3=A1=C5=A1?= <v@x.example.com>"
    m["To"] = "a@x.example.com, B <b@y.example.org>"
    m["Cc"] = "c@z.example.net"
    m["Subject"] = "=?utf-8?q?P=C5=99=C3=ADloha?="
    m["Message-ID"] = "<m1@x.example.com>"
    m["In-Reply-To"] = "<m0@x.example.com>"
    m["References"] = "<a@x.example.com> <m0@x.example.com>"
    m["Date"] = "Thu, 25 Sep 2026 10:00:00 +0200"
    m.set_content("Plain body here, long enough to be preferred.")
    m.add_alternative("<p>HTML <b>body</b></p>", subtype="html")
    m.add_attachment(
        b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="faktura.pdf"
    )
    m.add_attachment(b"\x89PNG....", maintype="image", subtype="png", filename="img.png")
    return m.as_bytes()


def test_parse_headers_and_body():
    p = parse.parse_message(_mixed())
    assert p.subject == "Příloha"
    assert p.from_ == "Tomáš <v@x.example.com>"
    assert p.to == ["a@x.example.com", "B <b@y.example.org>"] and p.cc == ["c@z.example.net"]
    assert p.message_id == "<m1@x.example.com>" and p.in_reply_to == "<m0@x.example.com>"
    assert p.references == ["<a@x.example.com>", "<m0@x.example.com>"]
    assert p.date.startswith("2026-09-25T10:00:00")
    assert p.body_source == "plain" and "Plain body" in p.body_text
    assert [(a.index, a.filename, a.content_type) for a in p.attachments] == [
        (0, "faktura.pdf", "application/pdf"),
        (1, "img.png", "image/png"),
    ]


def test_html_only_is_converted():
    m = EmailMessage()
    m["Subject"] = "x"
    m.set_content(
        "<html><head><style>p{}</style><script>alert(1)</script></head>"
        "<body><h1>Title</h1><p>Hello <a href='https://e.example.org'>link</a></p></body></html>",
        subtype="html",
    )
    p = parse.parse_message(m.as_bytes())
    assert p.body_source == "html"
    assert (
        "Title" in p.body_text and "Hello" in p.body_text and "https://e.example.org" in p.body_text
    )
    assert "alert(1)" not in p.body_text and "p{}" not in p.body_text


def test_short_plain_falls_back_to_html():
    m = EmailMessage()
    m.set_content(" ")
    m.add_alternative("<p>Real content in HTML</p>", subtype="html")
    p = parse.parse_message(m.as_bytes())
    assert p.body_source == "html" and "Real content" in p.body_text


def test_get_attachment():
    info, data = parse.get_attachment(_mixed(), 0)
    assert info.filename == "faktura.pdf" and data.startswith(b"%PDF")
    try:
        parse.get_attachment(_mixed(), 5)
        raise AssertionError
    except KeyError:
        pass


def test_broken_charset_does_not_crash():
    raw = (
        b"Subject: x\r\nContent-Type: text/plain; charset=unknown-8bit\r\n\r\n"
        b"\xff\xfe broken \xe9\r\n"
    )
    p = parse.parse_message(raw)
    assert "broken" in p.body_text


def test_format_address_quotes_names_with_specials():
    from email.policy import default

    assert parse.format_address("Doe, John", "j@example.org") == '"Doe, John" <j@example.org>'
    assert parse.format_address('Pat "P" O\\N', "p@example.org") == (
        '"Pat \\"P\\" O\\\\N" <p@example.org>'
    )
    assert parse.format_address("Plain Name", "x@example.org") == "Plain Name <x@example.org>"
    assert parse.format_address("", "x@example.org") == "x@example.org"
    # A comma inside a quoted name no longer splits one address into two.
    header = ", ".join([parse.format_address("Doe, John", "j@example.org"), "Roe <r@example.org>"])
    msg = email.message_from_bytes(f"To: {header}\r\n\r\n".encode(), policy=default)
    assert [a.addr_spec for a in msg["To"].addresses] == ["j@example.org", "r@example.org"]
    assert msg["To"].addresses[0].display_name == "Doe, John"
    addrs = [Address(b"Doe, John", None, b"j", b"example.org")]
    assert parse.format_addresses(addrs) == ['"Doe, John" <j@example.org>']


def test_format_addresses_and_decode():
    addrs = (
        Address(b"=?utf-8?q?Tom=C3=A1=C5=A1?=", None, b"v", b"x.example.com"),
        Address(None, None, b"a", b"y.example.org"),
    )
    assert parse.format_addresses(addrs) == ["Tomáš <v@x.example.com>", "a@y.example.org"]
    assert parse.format_addresses(None) == []
    assert parse.decode_header_value(b"=?utf-8?b?xb5sdcWlb3XEjWvDvQ==?=") == "žluťoučký"


def test_bodystructure_has_attachment():
    plain = (
        b"text",
        b"plain",
        (b"charset", b"utf-8"),
        None,
        None,
        b"7bit",
        10,
        1,
        None,
        None,
        None,
        None,
    )
    att = (
        b"application",
        b"pdf",
        (b"name", b"a.pdf"),
        None,
        None,
        b"base64",
        100,
        None,
        (b"attachment", (b"filename", b"a.pdf")),
        None,
        None,
    )
    assert parse.bodystructure_has_attachment(plain) is False
    assert parse.bodystructure_has_attachment(([plain, att], b"mixed")) is True


def test_build_draft_reply():
    raw, msgid = parse.build_draft(
        from_addr="me@x.example.com",
        from_name="Tomáš",
        to=["a@y.example.org"],
        cc=["c@y.example.org"],
        bcc=[],
        subject="Re: Příloha",
        body="Díky!",
        html=False,
        in_reply_to="<m1@x.example.com>",
        references=["<m0@x.example.com>", "<m1@x.example.com>"],
    )
    m = email.message_from_bytes(raw, policy=policy.default)
    assert str(m["From"]) == "Tomáš <me@x.example.com>"
    assert (
        m["In-Reply-To"] == "<m1@x.example.com>"
        and m["References"] == "<m0@x.example.com> <m1@x.example.com>"
    )
    assert m["Message-ID"] == msgid and msgid.endswith("@x.example.com>")
    assert m.get_content().strip() == "Díky!"
    assert b"\r\n" in raw and "Bcc" not in m


def test_build_draft_bcc_and_html():
    raw, _ = parse.build_draft(
        from_addr="me@x.example.com",
        from_name=None,
        to=["a@y.example.org"],
        cc=[],
        bcc=["h@y.example.org"],
        subject="S",
        body="<p>Hi</p>",
        html=True,
        in_reply_to=None,
        references=[],
    )
    m = email.message_from_bytes(raw, policy=policy.default)
    assert m["Bcc"] == "h@y.example.org"
    assert m.get_body(("plain",)) is not None and m.get_body(("html",)) is not None


def test_truncate():
    assert parse.truncate("abc", 10) == ("abc", False)
    t, cut = parse.truncate("a" * 50, 10)
    assert cut and t.startswith("a" * 10) and "truncated" in t


# --- Fix round 1 regression tests -----------------------------------------------


def _nested_multipart(depth: int) -> bytes:
    """Raw bytes for `depth` levels of nested multipart/mixed, terminating in one leaf."""
    inner = b"Content-Type: text/plain\r\n\r\nleaf\r\n"
    for i in range(depth):
        bnd = f"b{i}".encode()
        inner = (
            b'Content-Type: multipart/mixed; boundary="' + bnd + b'"\r\n\r\n'
            b"--" + bnd + b"\r\n" + inner + b"\r\n--" + bnd + b"--\r\n"
        )
    return b"Subject: nested\r\n" + inner


def test_html_to_text_survives_deep_nesting():
    depth = sys.getrecursionlimit() * 5
    html = "<div>" * depth + "deep content" + "</div>" * depth
    text = parse.html_to_text(html)
    assert "deep content" in text
    assert "<div>" not in text


def test_parse_message_html_only_deep_nesting_does_not_crash():
    depth = sys.getrecursionlimit() * 5
    html_body = "<div>" * depth + "deep hello" + "</div>" * depth
    m = EmailMessage()
    m["Subject"] = "deep"
    m.set_content(html_body, subtype="html")
    p = parse.parse_message(m.as_bytes())
    assert p.body_source == "html"
    assert "deep hello" in p.body_text


def test_build_draft_html_deep_nesting_does_not_crash():
    depth = sys.getrecursionlimit() * 5
    body = "<div>" * depth + "deep body" + "</div>" * depth
    raw, msgid = parse.build_draft(
        from_addr="me@x.example.com",
        from_name=None,
        to=["a@y.example.org"],
        cc=[],
        bcc=[],
        subject="S",
        body=body,
        html=True,
        in_reply_to=None,
        references=[],
    )
    assert raw and msgid


def test_parse_message_deeply_nested_multipart_falls_back_to_headers_only():
    depth = sys.getrecursionlimit() * 3
    raw = _nested_multipart(depth)
    p = parse.parse_message(raw)
    assert p.subject == "nested"
    assert p.body_source == "none"
    assert p.attachments == []
    assert "too deeply nested" in p.body_text


def test_get_attachment_deeply_nested_multipart_raises_keyerror():
    depth = sys.getrecursionlimit() * 3
    raw = _nested_multipart(depth)
    try:
        parse.get_attachment(raw, 0)
        raise AssertionError
    except KeyError:
        pass


def test_message_rfc822_attachment_counts_as_one_part_and_is_not_descended():
    inner = EmailMessage()
    inner["Subject"] = "Inner subject"
    inner["From"] = "inner@x.example.com"
    inner.set_content("Inner body, long enough to be a real plain-text body for sure.")
    inner.add_attachment(b"\x89PNGfake", maintype="image", subtype="png", filename="inner.png")

    outer = EmailMessage()
    outer["Subject"] = "Outer subject"
    outer.set_content("Outer body, long enough to be the chosen plain body text for sure.")
    outer.add_attachment(inner, subtype="rfc822")
    raw = outer.as_bytes()

    p = parse.parse_message(raw)
    assert [(a.index, a.filename, a.content_type) for a in p.attachments] == [
        (0, "attached-message.eml", "message/rfc822")
    ]

    info, data = parse.get_attachment(raw, 0)
    assert info.content_type == "message/rfc822" and info.filename == "attached-message.eml"
    inner_parsed = email.message_from_bytes(data, policy=policy.default)
    assert inner_parsed["Subject"] == "Inner subject"


def test_search_criteria_to_dict_is_json_safe():
    sc = models.SearchCriteria(since=date(2026, 1, 1), before=date(2026, 2, 1))
    d = sc.to_dict()
    json.dumps(d)  # must not raise
    assert d["since"] == "2026-01-01"
    assert d["before"] == "2026-02-01"


class _RaisingHeaderMsg:
    """A stand-in Message whose refined header access *and* `.get()` both raise --
    exactly the code path `_header`'s except-branch used to (uselessly) retry."""

    def __getitem__(self, name):
        raise ValueError("refined header access boom")

    def get(self, name, default=""):
        raise ValueError("refined header access boom")

    def raw_items(self):
        return [("Subject", "raw subject value")]


def test_header_fallback_reads_raw_value_when_refined_access_fails():
    msg = _RaisingHeaderMsg()
    assert parse._header(msg, "Subject") == "raw subject value"
    assert parse._header(msg, "Missing", "fallback-default") == "fallback-default"


# --- Fix round 2 regression test --------------------------------------------------


def test_crude_html_to_text_strips_unclosed_script_tags_in_linear_time():
    html = "<script>x" * 200_000
    start = time.monotonic()
    text = parse._crude_html_to_text(html)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"crude html->text took {elapsed:.2f}s on hostile input"
    assert "<script" not in text.lower()


def test_crude_html_to_text_strips_unclosed_style_openers_in_linear_time():
    html = "<style" * 200_000
    start = time.monotonic()
    text = parse._crude_html_to_text(html)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"crude html->text took {elapsed:.2f}s on hostile input"
    assert "<style" not in text.lower()


# --- Fix round 3 regression tests -------------------------------------------------


def test_crude_html_to_text_single_tag_type_stays_linear_time():
    # Only "<style>" pairs, never "<script>": the old code re-scanned to the end of
    # the string hunting for the absent "<script" on every single iteration.
    html = "<style></style>" * 40_000
    start = time.monotonic()
    parse._crude_html_to_text(html)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"crude html->text took {elapsed:.2f}s on hostile input"


def test_crude_html_to_text_bare_angle_brackets_stay_linear_time():
    # No ">" anywhere, so none of these ever close into a full tag: the old
    # `<[^>]+>` tag regex backtracked to end-of-string on every failed match attempt
    # (one attempt per "<"). The point of this test is the time bound, not the
    # (unchanged) content -- with no closing ">" there is nothing valid to strip.
    html = "<" * 200_000
    start = time.monotonic()
    parse._crude_html_to_text(html)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0, f"crude html->text took {elapsed:.2f}s on hostile input"


def test_html_to_text_caps_input_before_processing():
    marker = "MARKER_AFTER_CAP"
    html = "a" * 1_000_000 + f"<p>{marker}</p>"
    text = parse.html_to_text(html)
    assert marker not in text


def test_get_attachment_reports_text_charset():
    msg = EmailMessage()
    msg["Subject"] = "cs"
    msg.set_content("body text long enough to be the plain body of this message")
    msg.add_attachment(
        "příliš žluťoučký".encode("iso-8859-2"),
        maintype="text",
        subtype="plain",
        filename="poznamka.txt",
    )
    part = next(iter(msg.iter_attachments()))
    part.set_param("charset", "iso-8859-2")
    info, data = parse.get_attachment(msg.as_bytes(), 0)
    assert info.charset == "iso-8859-2"
    assert data.decode("iso-8859-2") == "příliš žluťoučký"
    assert "charset" not in info.to_dict()
