"""Reading messages too large to parse whole: section fetches driven by BODYSTRUCTURE
(final fix round: review A I2, review B I3)."""

import email
import re
import threading
from datetime import UTC, datetime

import pytest
from imapclient.exceptions import ProtocolError

from postroom.accounts import AccountStatus, Provider
from postroom.mail import heavy, parse, service
from postroom.mail.heavy import ServerBusy, heavy_work
from postroom.mail.imap import FETCH_BODY, ImapError
from postroom.mail.service import MailService
from tests.unit.bodystructure import bodystructure
from tests.unit.test_mail_service import StubPool, env
from tests.unit.test_parse_structure import _mixed

_PARTIAL = re.compile(r"BODY\.PEEK\[([^\]]*)\](?:<0\.(\d+)>)?$")


def _part_bytes(msg, section: str) -> bytes:
    part = msg
    for n in section.split("."):
        if part.get_content_type() == "message/rfc822":
            part = part.get_payload(0)
        part = part.get_payload()[int(n) - 1] if part.is_multipart() else part
    if part.get_content_type() == "message/rfc822":
        return part.get_payload(0).as_bytes()
    raw = part.as_bytes()
    return raw.split(b"\n\n", 1)[1]


class SectionServer:
    """Fake IMAP session serving one message (UID 1) by section, like a real server."""

    def __init__(self, raw: bytes, size: int | None = None):
        self.raw = raw
        self.msg = email.message_from_bytes(raw)
        self.size = size if size is not None else len(raw)
        self.items: list[str] = []

    def list_folders(self):
        return [((), b"/", "INBOX"), ((b"\\Drafts",), b"/", "Drafts"), ((b"\\Sent",), b"/", "Sent")]

    def section_bytes(self, section: str) -> bytes:
        return _part_bytes(self.msg, section)  # RFC 3501: an attached message whole

    def select_folder(self, name, readonly=False):
        assert readonly is True

    def search(self, criteria, charset=None):
        return [1]

    def fetch(self, uids, fields):
        out = {}
        for field in fields:
            self.items.append(field)
            if field == FETCH_BODY:
                out[b"BODY[]"] = self.raw
                continue
            m = _PARTIAL.match(field)
            if m is None:  # summary fields
                out.update(
                    {
                        b"ENVELOPE": env("big", "p"),
                        b"INTERNALDATE": datetime(2026, 9, 25, tzinfo=UTC),
                        b"FLAGS": (),
                        b"RFC822.SIZE": self.size,
                        b"BODYSTRUCTURE": bodystructure(self.msg),
                    }
                )
                continue
            section, limit = m.group(1), m.group(2)
            if section == "HEADER":
                data = self.raw.split(b"\n\n", 1)[0] + b"\n\n"
            elif section.endswith((".HEADER", ".TEXT")):  # of an attached message
                head, _, body = _part_bytes(self.msg, section.rsplit(".", 1)[0]).partition(b"\n\n")
                data = head + b"\n\n" if section.endswith("HEADER") else body
            else:
                data = self.section_bytes(section)
            key = f"BODY[{section}]".encode()
            if limit is not None:
                data, key = data[: int(limit)], key + b"<0>"
            out[key] = data
        return {1: out}


@pytest.fixture
def account(repo):
    repo.upsert(
        email="a@x.example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="p",
        status=AccountStatus.CONNECTED,
    )
    return "a@x.example.com"


def _svc(repo, server):
    return MailService(repo, StubPool({"a@x.example.com": server}))


def _assert_peek_only(server):
    assert FETCH_BODY not in server.items  # the whole message is never fetched
    for item in server.items:
        if item.startswith(("BODY[", "BODY.")):
            assert item.startswith("BODY.PEEK[")


async def test_large_message_is_read_by_section(repo, account):
    raw = _mixed().as_bytes()
    server = SectionServer(raw, size=30 * 1024 * 1024)
    detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    _assert_peek_only(server)
    assert f"BODY.PEEK[HEADER]<0.{parse.MAX_HEADER_BYTES}>" in server.items
    assert detail.message.subject == "Faktura"
    assert detail.message.body_text.startswith("Dobrý den, v příloze")
    assert detail.truncated is False
    full = parse.parse_message(raw)
    assert [(a.index, a.filename, a.content_type) for a in detail.message.attachments] == [
        (a.index, a.filename, a.content_type) for a in full.attachments
    ]


async def test_large_message_body_cut_is_flagged(repo, account, monkeypatch):
    monkeypatch.setattr(service, "MAX_TEXT_PART_FETCH", 40)
    server = SectionServer(_mixed().as_bytes(), size=30 * 1024 * 1024)
    detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    assert detail.truncated is True
    assert detail.message.body_text.endswith(service.BODY_NOT_LOADED)
    assert "BODY.PEEK[1.1]<0.40>" in server.items


async def test_message_with_many_parts_is_read_by_section(repo, account, monkeypatch):
    monkeypatch.setattr(service, "MAX_FULL_PARSE_PARTS", 3)
    server = SectionServer(_mixed().as_bytes())  # small, but 6 parts
    detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    _assert_peek_only(server)
    assert len(detail.message.attachments) == 4


async def test_small_message_is_still_parsed_whole(repo, account):
    server = SectionServer(_mixed().as_bytes())
    detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    assert FETCH_BODY in server.items
    assert detail.message.body_text.startswith("Dobrý den")


async def test_large_message_attachment_is_fetched_alone(repo, account):
    raw = _mixed().as_bytes()
    server = SectionServer(raw, size=30 * 1024 * 1024)
    info, data = await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 0)
    _assert_peek_only(server)
    _, full_data = parse.get_attachment(raw, 0)
    assert (info.filename, info.content_type, data) == ("faktura.pdf", "application/pdf", full_data)
    assert info.size == len(full_data)
    info, data = await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 2)
    assert info.content_type == "message/rfc822" and b"Subject: forwarded" in data


async def test_large_message_attachment_over_cap_is_not_fetched(repo, account, monkeypatch):
    monkeypatch.setattr(service, "MAX_ATTACHMENT_FETCH_BYTES", 100)
    server = SectionServer(_mixed().as_bytes(), size=30 * 1024 * 1024)
    info, data = await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 0)
    assert data is None and info.filename == "faktura.pdf"
    assert not any(i.startswith("BODY.PEEK[2]") for i in server.items)


async def test_large_message_bad_attachment_index(repo, account):
    server = SectionServer(_mixed().as_bytes(), size=30 * 1024 * 1024)
    with pytest.raises(KeyError):
        await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 9)


async def test_large_message_without_structure_is_refused(repo, account):
    class NoStructure(SectionServer):
        def fetch(self, uids, fields):
            out = super().fetch(uids, fields)
            out[1].pop(b"BODYSTRUCTURE", None)
            return out

    server = NoStructure(_mixed().as_bytes(), size=30 * 1024 * 1024)
    with pytest.raises(ImapError, match="too large"):
        await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    assert FETCH_BODY not in server.items


@pytest.mark.parametrize("size", [600 * 1024, 30 * 1024 * 1024])
async def test_big_reads_queue_on_the_heavy_work_gate(repo, account, monkeypatch, size):
    monkeypatch.setattr(heavy, "HEAVY_WAIT_SECONDS", 0.05)
    server = SectionServer(_mixed().as_bytes(), size=size)
    holding, release = threading.Event(), threading.Event()

    def holder():
        with heavy_work():
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(5)
    try:
        with pytest.raises(ServerBusy):
            await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
        with pytest.raises(ServerBusy):
            await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 0)
    finally:
        release.set()
        t.join()


async def test_small_plain_read_does_not_wait_for_the_gate(repo, account, monkeypatch):
    monkeypatch.setattr(heavy, "HEAVY_WAIT_SECONDS", 0.05)
    server = SectionServer(_mixed().as_bytes())  # plain body: no HTML conversion either
    holding, release = threading.Event(), threading.Event()

    def holder():
        with heavy_work():
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(5)
    try:
        detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    finally:
        release.set()
        t.join()
    assert detail.message.subject == "Faktura"


async def test_thread_and_reply_fetch_headers_with_a_cap(repo, account):
    capped = f"BODY.PEEK[HEADER]<0.{parse.MAX_HEADER_BYTES}>"
    server = SectionServer(_mixed().as_bytes())
    await _svc(repo, server).get_thread("a@x.example.com", "INBOX", 1)
    assert capped in server.items and "BODY.PEEK[HEADER]" not in server.items
    server.items.clear()
    server.appended = []
    server.append = lambda folder, msg, flags=(), msg_time=None: server.appended.append(msg)
    await _svc(repo, server).create_draft(
        "a@x.example.com", to=[], subject=None, body="ok", reply_folder="INBOX", reply_uid=1
    )
    assert capped in server.items
    assert b"Subject: Re: Faktura" in server.appended[0]


class GreenMailLike(SectionServer):
    """GreenMail answers a partial numeric section as `BODY[1.1]<0>{65}` (no space
    before the literal), which imapclient cannot parse: parts that fit must be fetched
    whole, only oversized ones partially."""

    def fetch(self, uids, fields):
        for f in fields:
            m = _PARTIAL.match(f)
            if m and m.group(2) and m.group(1)[0].isdigit():
                raise ProtocolError(f"uneven number of response items for {f}")
        return super().fetch(uids, fields)

    def section_bytes(self, section: str) -> bytes:
        data = super().section_bytes(section)
        if data.startswith(b"Subject: forwarded"):  # GreenMail: an attached message's body only
            data = data.partition(b"\n\n")[2]
        return data


async def test_large_message_parts_that_fit_are_fetched_whole(repo, account):
    raw = _mixed().as_bytes()
    server = GreenMailLike(raw, size=30 * 1024 * 1024)
    detail = await _svc(repo, server).get_message("a@x.example.com", "INBOX", 1)
    assert detail.message.subject == "Faktura"
    assert detail.message.body_text.startswith("Dobrý den, v příloze")
    _, data = await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 0)
    assert data == parse.get_attachment(raw, 0)[1]
    _assert_peek_only(server)
    assert "BODY.PEEK[1.1]" in server.items and "BODY.PEEK[2]" in server.items
    # an attached message as HEADER + TEXT, which every server answers the same way
    _, data = await _svc(repo, server).get_attachment("a@x.example.com", "INBOX", 1, 2)
    assert data == parse.get_attachment(raw, 2)[1]


def test_rfc_partial_response_parses_to_the_origin_key():
    # What Dovecot sends for BODY.PEEK[1.1]<0.30> (RFC 3501: SP before the literal).
    # GreenMail omits that space and cannot be used to test the partial path.
    from imapclient.response_parser import parse_fetch_response

    body = "Dobrý den, v příloze".encode()
    line = (b"1 (UID 7 BODY[1.1]<0> {%d}" % len(body), body)
    parsed = parse_fetch_response([line, b")"], uid_is_key=True)
    assert service._section(parsed[7], "1.1") == body


# -- forwarding a large email: the attachment budget counts decoded bytes (M7) --------------


def _with_attachment(size: int) -> bytes:
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "p@example.org", "a@x.example.com", "big"
    m.set_content("see attached")
    m.add_attachment(bytes(range(256)) * (size // 256), maintype="application", subtype="pdf")
    return m.as_bytes()


def test_large_forward_budget_counts_decoded_bytes(monkeypatch):
    size = 64 * 1024
    raw = _with_attachment(size)
    server = SectionServer(raw)
    structure = bodystructure(server.msg)
    # Between the decoded size and the base64 size: it fits.
    monkeypatch.setattr(service, "MAX_FORWARD_ATTACHMENT_BYTES", size + 1024)
    ((_info, data),) = MailService._large_attachments(server, 1, structure)
    assert len(data) == size
    # Below the decoded size: refused, before or after the fetch.
    monkeypatch.setattr(service, "MAX_FORWARD_ATTACHMENT_BYTES", size - 1024)
    with pytest.raises(ValueError, match="forward it with include_attachments=false"):
        MailService._large_attachments(server, 1, structure)
