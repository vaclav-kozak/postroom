from datetime import UTC, datetime

import pytest
from fastmcp import Client, FastMCP

from postroom.accounts import AccountStatus, Provider
from postroom.mail.folders import FolderNotFound
from postroom.mail.imap import AccountUnavailable
from postroom.mail.models import (
    AccountError,
    AttachmentInfo,
    DraftResult,
    MessageSummary,
    SearchCriteria,
    SearchResult,
)
from postroom.tools.mail_tools import register_mail_tools


class FakeMail:
    def __init__(self):
        self.calls = []

    async def search(self, emails, folder, criteria, limit=20, offset=0):
        self.calls.append(("search", emails, folder, criteria, limit, offset))
        return SearchResult(
            [
                MessageSummary(
                    "a@x.cz",
                    "INBOX",
                    5,
                    "2026-09-25T10:00:00+00:00",
                    "p@x.cz",
                    ["a@x.cz"],
                    "Hello",
                    False,
                    10,
                    False,
                )
            ],
            [AccountError("b@x.cz", "boom")],
        )

    async def create_draft(self, email, **kw):
        self.calls.append(("draft", email, kw))
        return DraftResult(email, "Drafts", "<m@x.cz>")

    async def list_folders(self, email, with_counts=False):
        from postroom.mail.models import FolderInfo

        return [FolderInfo("INBOX", None, [])]


@pytest.fixture
def server(repo):
    repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        status=AccountStatus.CONNECTED,
    )
    mcp = FastMCP("t")
    mail = FakeMail()
    register_mail_tools(mcp, repo, mail)
    return mcp, mail


async def test_tools_listed(server):
    mcp, _ = server
    async with Client(mcp) as c:
        names = {t.name for t in await c.list_tools()}
    assert names == {
        "list_accounts",
        "list_folders",
        "search_emails",
        "get_email",
        "get_thread",
        "get_attachment",
        "create_draft",
    }


async def test_no_send_or_delete_tools(server):
    mcp, _ = server
    async with Client(mcp) as c:
        names = " ".join(t.name for t in await c.list_tools())
    for bad in ("send", "delete", "move", "trash", "flag", "mark"):
        assert bad not in names


async def test_list_accounts(server):
    mcp, _ = server
    async with Client(mcp) as c:
        res = await c.call_tool("list_accounts", {})
    acc = res.data[0] if isinstance(res.data, list) else res.structured_content["result"][0]
    assert acc["email"] == "a@x.cz" and acc["capabilities"] == ["mail"]


async def test_search_maps_params(server):
    mcp, mail = server
    async with Client(mcp) as c:
        res = await c.call_tool(
            "search_emails",
            {"sender": "p@x.cz", "since": "2026-09-01", "unread_only": True, "limit": 5},
        )
    _, emails, folder, crit, limit, _offset = mail.calls[0]
    assert emails is None and folder == "inbox" and limit == 5
    assert crit == SearchCriteria(
        sender="p@x.cz", since=datetime(2026, 9, 1, tzinfo=UTC).date(), unread_only=True
    )
    data = res.structured_content
    assert data["results"][0]["from"] == "p@x.cz" and data["errors"][0]["account"] == "b@x.cz"


async def test_bad_date_is_tool_error(server):
    mcp, _ = server
    async with Client(mcp) as c:
        res = await c.call_tool("search_emails", {"since": "yesterday"}, raise_on_error=False)
    assert res.is_error


async def test_create_draft(server):
    mcp, mail = server
    async with Client(mcp) as c:
        res = await c.call_tool(
            "create_draft", {"account": "a@x.cz", "to": ["z@y.cz"], "subject": "S", "body": "B"}
        )
    assert res.structured_content["folder"] == "Drafts"
    assert mail.calls[0][2]["to"] == ["z@y.cz"]


async def test_create_draft_timeout_does_not_invite_a_duplicate(server, monkeypatch):
    # The APPEND may have landed before the timeout: "try again" would make a second draft.
    mcp, mail = server

    async def slow(email, **kw):
        raise TimeoutError()

    monkeypatch.setattr(mail, "create_draft", slow)
    async with Client(mcp) as c:
        res = await c.call_tool(
            "create_draft",
            {"account": "a@x.cz", "to": ["z@y.cz"], "subject": "S", "body": "B"},
            raise_on_error=False,
        )
    text = res.content[0].text
    assert res.is_error and "may or may not have been saved" in text
    assert "check the Drafts folder before trying again" in text


# -- additional coverage: get_attachment rendering and error mapping -----------------------


def make_pdf(text: str) -> bytes:
    content = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


class FakeReader:
    """Mail service stub for the read tools; `attachment`/`error` configure the outcome."""

    def __init__(self):
        self.calls = []
        self.attachment = None
        self.error = None

    async def get_message(self, email, folder, uid, max_chars=20000):
        self.calls.append(("get_message", email, folder, uid, max_chars))
        raise self.error

    async def get_attachment(self, email, folder, uid, index):
        self.calls.append(("get_attachment", email, folder, uid, index))
        if self.error is not None:
            raise self.error
        content_type, data, *charset = self.attachment
        size = len(data) if data is not None else 40 * 1024 * 1024
        info = AttachmentInfo(index, "file", content_type, size, False, *charset)
        return info, data


@pytest.fixture
def reader(repo):
    mcp = FastMCP("t")
    mail = FakeReader()
    register_mail_tools(mcp, repo, mail)
    return mcp, mail


async def _attachment(mcp, **extra):
    args = {"account": "A@X.cz", "folder": "inbox", "uid": 7, "index": 0, **extra}
    async with Client(mcp) as c:
        return await c.call_tool("get_attachment", args, raise_on_error=False)


async def test_attachment_text_is_truncated(reader):
    mcp, mail = reader
    mail.attachment = ("text/plain", "příliš žluťoučký kůň".encode() * 10)
    res = await _attachment(mcp, max_chars=30)
    assert mail.calls[0] == ("get_attachment", "a@x.cz", "inbox", 7, 0)
    data = res.structured_content
    assert data["content_type"] == "text/plain" and data["filename"] == "file"
    assert data["text"].startswith("příliš žluťoučký kůň") and "truncated" in data["text"]


async def test_attachment_pdf_text(reader):
    mcp, mail = reader
    mail.attachment = ("application/pdf", make_pdf("Invoice 2026-042"))
    res = await _attachment(mcp)
    assert "Invoice 2026-042" in res.structured_content["text"]


async def test_attachment_broken_pdf_returns_metadata(reader):
    mcp, mail = reader
    mail.attachment = ("application/pdf", b"%PDF-1.4 garbage")
    res = await _attachment(mcp)
    assert not res.is_error and "text" not in res.structured_content
    assert res.structured_content["note"]


async def test_attachment_image(reader):
    mcp, mail = reader
    mail.attachment = ("image/png", b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
    res = await _attachment(mcp)
    assert res.content[0].type == "image" and res.content[0].mime_type == "image/png"


async def test_attachment_large_image_returns_metadata(reader):
    mcp, mail = reader
    mail.attachment = ("image/jpeg", b"\xff" * (5 * 1024 * 1024 + 1))
    res = await _attachment(mcp)
    assert res.structured_content["size"] == 5 * 1024 * 1024 + 1
    assert "5 MB" in res.structured_content["note"]


async def test_attachment_over_size_cap_returns_metadata(reader):
    mcp, mail = reader
    mail.attachment = ("text/plain", b"x" * (10 * 1024 * 1024 + 1))
    res = await _attachment(mcp)
    assert "text" not in res.structured_content and "10 MB" in res.structured_content["note"]


async def test_attachment_other_type_returns_metadata(reader):
    mcp, mail = reader
    mail.attachment = ("application/zip", b"PK\x03\x04")
    res = await _attachment(mcp)
    data = res.structured_content
    assert data["content_type"] == "application/zip" and data["index"] == 0 and data["note"]


async def test_attachment_bad_index_is_tool_error(reader):
    mcp, mail = reader
    mail.error = KeyError(3)
    res = await _attachment(mcp, index=3)
    assert res.is_error and res.content[0].text.startswith("attachment 3 not found")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (AccountUnavailable("account needs reconnect: bad login"), "account needs reconnect"),
        (FolderNotFound("Foo"), "folder not found: 'Foo'"),
        (LookupError("message not found"), "message not found"),
        (TimeoutError(), "did not respond in time"),
    ],
)
async def test_mail_errors_become_clean_tool_errors(reader, error, message):
    mcp, mail = reader
    mail.error = error
    async with Client(mcp) as c:
        res = await c.call_tool(
            "get_email", {"account": "a@x.cz", "folder": "x", "uid": 1}, raise_on_error=False
        )
    assert res.is_error and message in res.content[0].text
    assert "Traceback" not in res.content[0].text


# -- security fix round: PDF limits and text charsets ------------------------------------------


def make_pdf_pages(texts: list[str]) -> bytes:
    """A minimal PDF with one page per text."""
    n = len(texts)
    font = 3 + 2 * n
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [%s] /Count %d >>"
        % (b" ".join(b"%d 0 R" % (3 + 2 * i) for i in range(n)), n),
    ]
    for i, text in enumerate(texts):
        content = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents %d 0 R "
            b"/Resources << /Font << /F1 %d 0 R >> >> >>" % (4 + 2 * i, font)
        )
        objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


async def test_attachment_pdf_page_cap(reader, monkeypatch):
    from postroom.tools import mail_tools

    monkeypatch.setattr(mail_tools, "MAX_PDF_PAGES", 2)
    mcp, mail = reader
    mail.attachment = ("application/pdf", make_pdf_pages(["PageOne", "PageTwo", "PageThree"]))
    data = (await _attachment(mcp)).structured_content
    assert "PageOne" in data["text"] and "PageTwo" in data["text"]
    assert "PageThree" not in data["text"]
    assert "first 2 of 3 pages" in data["note"]


def test_pdf_page_cap_default():
    from postroom.tools import mail_tools

    assert mail_tools.MAX_PDF_PAGES == 50
    assert mail_tools.MAX_PDF_BYTES == 5 * 1024 * 1024
    assert mail_tools.PDF_TIMEOUT_SECONDS == 20


async def test_attachment_large_pdf_is_not_parsed(reader, monkeypatch):
    from postroom.tools import mail_tools

    def boom(*a, **kw):
        raise AssertionError("must not parse")

    monkeypatch.setattr(mail_tools, "_pdf_text", boom)
    mcp, mail = reader
    mail.attachment = ("application/pdf", b"%PDF-1.4\n" + b"0" * (5 * 1024 * 1024))
    res = await _attachment(mcp)
    assert not res.is_error and "text" not in res.structured_content
    assert "5 MB" in res.structured_content["note"]


async def test_attachment_pdf_extraction_times_out(reader, monkeypatch):
    import sys
    import time

    from postroom.mail import pdf
    from postroom.tools import mail_tools

    # A child that hangs is killed at the timeout (a thread could not be).
    monkeypatch.setattr(
        pdf, "_child_command", lambda *a: [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    monkeypatch.setattr(mail_tools, "PDF_TIMEOUT_SECONDS", 0.5)
    mcp, mail = reader
    mail.attachment = ("application/pdf", make_pdf("x"))
    start = time.monotonic()
    res = await _attachment(mcp)
    assert time.monotonic() - start < 5
    assert not res.is_error and "text" not in res.structured_content
    assert "timed out" in res.structured_content["note"]


async def test_attachment_pdf_content_bomb_returns_metadata(reader):
    from tests.unit.test_pdf import make_bomb_pdf

    mcp, mail = reader
    mail.attachment = ("application/pdf", make_bomb_pdf(5))  # 16 KiB, was +222 MiB in-process
    res = await _attachment(mcp)
    assert not res.is_error and "text" not in res.structured_content
    assert "too complex" in res.structured_content["note"]


async def test_attachment_pdf_when_busy_is_a_clean_error(reader, monkeypatch):
    from postroom.mail import heavy
    from postroom.mail.heavy import ServerBusy
    from postroom.tools import mail_tools

    def busy(*a, **kw):
        raise ServerBusy()

    monkeypatch.setattr(mail_tools, "extract_text_isolated", busy)
    monkeypatch.setattr(heavy, "HEAVY_WAIT_SECONDS", 0.05)
    mcp, mail = reader
    mail.attachment = ("application/pdf", make_pdf("x"))
    res = await _attachment(mcp)
    assert res.is_error and "busy" in res.content[0].text


async def test_attachment_too_large_to_fetch_returns_metadata(reader):
    # The service does not download a part of a big message beyond its fetch cap.
    mcp, mail = reader
    mail.attachment = ("application/pdf", None)
    res = await _attachment(mcp)
    assert not res.is_error and "text" not in res.structured_content
    assert res.structured_content["size"] == 40 * 1024 * 1024
    assert "too large" in res.structured_content["note"]


async def test_attachment_text_uses_declared_charset(reader):
    mcp, mail = reader
    mail.attachment = ("text/plain", "příliš žluťoučký".encode("iso-8859-2"), "iso-8859-2")
    res = await _attachment(mcp)
    assert res.structured_content["text"] == "příliš žluťoučký"


async def test_attachment_text_unknown_charset_falls_back_to_utf8(reader):
    mcp, mail = reader
    mail.attachment = ("text/plain", "kůň".encode(), "x-no-such-charset")
    res = await _attachment(mcp)
    assert res.structured_content["text"] == "kůň"
