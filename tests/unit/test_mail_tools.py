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
        "mark_emails",
        "move_emails",
        "trash_emails",
        "create_folder",
        "send_email",
        "forward_email",
        "send_draft",
    }


async def test_no_delete_tools(server):
    mcp, _ = server
    async with Client(mcp) as c:
        names = " ".join(t.name for t in await c.list_tools())
    for bad in ("delete", "expunge", "purge"):
        assert bad not in names


async def test_list_accounts(server):
    mcp, _ = server
    async with Client(mcp) as c:
        res = await c.call_tool("list_accounts", {})
    acc = res.data[0] if isinstance(res.data, list) else res.structured_content["result"][0]
    assert acc["email"] == "a@x.cz"
    # The default level: read and organise, no sending.
    assert acc["capabilities"] == ["mail", "mail.organize"]
    assert acc["mail_access"] == "organize"


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


# -- organising tools ---------------------------------------------------------------------------


class FakeOrganizer:
    def __init__(self):
        self.calls = []
        self.error = None

    async def _answer(self, *call):
        from postroom.mail.models import BatchResult, RefGroup

        self.calls.append(call)
        if self.error is not None:
            raise self.error
        return BatchResult(
            updated=1,
            skipped=[RefGroup("user@example.com", "Trash", [9], "already in trash")],
            failed=[RefGroup("user@example.com", "INBOX", [8], "message not found")],
            destinations={"user@example.com": "Trash"},
        )

    async def set_flags(self, refs, *, read=None, flagged=None):
        return await self._answer("set_flags", refs, read, flagged)

    async def move(self, refs, to_folder):
        return await self._answer("move", refs, to_folder)

    async def trash(self, refs):
        return await self._answer("trash", refs)

    async def create_folder(self, email, name, parent=None):
        self.calls.append(("create_folder", email, name, parent))
        if self.error is not None:
            raise self.error
        return f"{parent}/{name}" if parent else name


@pytest.fixture
def organizer(repo):
    mcp = FastMCP("t")
    mail = FakeOrganizer()
    register_mail_tools(mcp, repo, mail)
    return mcp, mail


SEARCH_RESULT = {  # one search_emails result, passed straight through
    "account": "User@Example.com",
    "folder": "INBOX",
    "uid": 7,
    "date": "2026-09-25T10:00:00+00:00",
    "from": "p@example.org",
    "to": ["user@example.com"],
    "subject": "Hello",
    "seen": False,
    "size": 10,
    "has_attachments": False,
    "thread_id": None,
}


async def test_organize_tool_schemas(organizer):
    mcp, _ = organizer
    async with Client(mcp) as c:
        tools = {t.name: t for t in await c.list_tools()}
    for name in ("mark_emails", "move_emails", "trash_emails"):
        schema = tools[name].input_schema
        emails = schema["properties"]["emails"]
        assert emails["type"] == "array" and "emails" in schema["required"]
        assert emails["maxItems"] == 500 and emails["minItems"] == 1
        item = emails["items"]
        if "$ref" in item:  # FastMCP may keep the model in $defs
            item = schema["$defs"][item["$ref"].rsplit("/", 1)[-1]]
        assert item["type"] == "object"
        assert set(item["required"]) == {"account", "folder", "uid"}
        assert item["properties"]["account"]["type"] == "string"
        assert item["properties"]["folder"]["type"] == "string"
        assert item["properties"]["uid"]["type"] == "integer"
        assert item["properties"]["uid"]["minimum"] == 1
        assert all(p.get("description") for p in item["properties"].values())
    mark = tools["mark_emails"].input_schema["properties"]
    assert {"read", "flagged"} <= set(mark)
    assert tools["move_emails"].input_schema["required"] == ["emails", "to_folder"]
    create = tools["create_folder"].input_schema
    assert create["required"] == ["account", "name"] and "parent" in create["properties"]
    ann = {n: tools[n].annotations for n in tools}
    assert ann["mark_emails"].read_only_hint is False
    assert ann["mark_emails"].destructive_hint is False and ann["mark_emails"].idempotent_hint
    assert ann["move_emails"].destructive_hint is True
    assert ann["trash_emails"].destructive_hint is True
    assert ann["create_folder"].destructive_hint is False


async def test_mark_emails_accepts_search_results(organizer):
    from postroom.mail.models import MessageRef

    mcp, mail = organizer
    async with Client(mcp) as c:
        res = await c.call_tool("mark_emails", {"emails": [SEARCH_RESULT], "read": True})
    assert mail.calls == [("set_flags", [MessageRef("user@example.com", "INBOX", 7)], True, None)]
    assert res.structured_content == {
        "updated": 1,
        "skipped": [
            {
                "account": "user@example.com",
                "folder": "Trash",
                "uids": [9],
                "reason": "already in trash",
            }
        ],
        "failed": [
            {
                "account": "user@example.com",
                "folder": "INBOX",
                "uids": [8],
                "error": "message not found",
            }
        ],
        "moved_to": {"user@example.com": "Trash"},
    }


async def test_move_trash_and_create_folder_tools(organizer):
    mcp, mail = organizer
    async with Client(mcp) as c:
        await c.call_tool("move_emails", {"emails": [SEARCH_RESULT], "to_folder": "archive"})
        await c.call_tool("trash_emails", {"emails": [SEARCH_RESULT]})
        res = await c.call_tool(
            "create_folder", {"account": " User@Example.com", "name": "Clients", "parent": "Work"}
        )
    assert [call[0] for call in mail.calls] == ["move", "trash", "create_folder"]
    assert mail.calls[0][2] == "archive"
    assert mail.calls[2] == ("create_folder", "user@example.com", "Clients", "Work")
    assert res.structured_content == {"account": "user@example.com", "folder": "Work/Clients"}


async def test_bad_email_ref_is_rejected(organizer):
    mcp, mail = organizer
    async with Client(mcp) as c:
        res = await c.call_tool(
            "mark_emails",
            {"emails": [{"account": "user@example.com", "folder": "INBOX", "uid": 0}], "read": 1},
            raise_on_error=False,
        )
    assert res.is_error and mail.calls == []


async def test_organize_timeout_warns_of_partial_change(organizer):
    mcp, mail = organizer
    mail.error = TimeoutError()
    async with Client(mcp) as c:
        res = await c.call_tool("trash_emails", {"emails": [SEARCH_RESULT]}, raise_on_error=False)
        text = res.content[0].text
        assert res.is_error and "partially applied" in text and "search_emails" in text
        res = await c.call_tool(
            "create_folder", {"account": "user@example.com", "name": "X"}, raise_on_error=False
        )
    text = res.content[0].text
    assert res.is_error and "may or may not have been created" in text


def _real_server(repo, pool):
    from postroom.mail.service import MailService

    mcp = FastMCP("t")
    register_mail_tools(mcp, repo, MailService(repo, pool))
    return mcp


async def test_read_only_account_through_the_tools(repo):
    from postroom.accounts import MailAccess
    from tests.unit.test_mail_organize import StubPool, fake

    repo.upsert(email="user@example.com", provider=Provider.IMAP, status=AccountStatus.CONNECTED)
    repo.set_mail_access("user@example.com", MailAccess.READ)
    f = fake()
    mcp = _real_server(repo, StubPool({"user@example.com": f}))
    denied = (
        "account user@example.com is set to read-only mail access; "
        "the owner can change this in the admin UI (the account's access level) or with the "
        "`postroom set-access` command"
    )
    async with Client(mcp) as c:
        res = await c.call_tool("mark_emails", {"emails": [SEARCH_RESULT], "read": True})
        assert res.structured_content["failed"][0]["error"] == denied
        res = await c.call_tool(
            "create_folder", {"account": "user@example.com", "name": "X"}, raise_on_error=False
        )
        assert res.is_error and res.content[0].text == denied
    assert f.calls == []


async def test_too_many_refs_through_the_tools(repo):
    from tests.unit.test_mail_organize import StubPool

    mcp = _real_server(repo, StubPool({}))
    emails = [{"account": "user@example.com", "folder": "INBOX", "uid": u} for u in range(1, 502)]
    async with Client(mcp) as c:
        res = await c.call_tool(
            "mark_emails", {"emails": emails, "read": True}, raise_on_error=False
        )
        # The cap is in the input schema (maxItems), so the arguments are rejected up front.
        assert res.is_error and "at most 500 items" in res.content[0].text
        res = await c.call_tool("mark_emails", {"emails": emails[:1]}, raise_on_error=False)
        assert res.is_error and "read, flagged or both" in res.content[0].text
