from email.message import EmailMessage

import pytest

from postroom.mail.imap import ImapConnector, ImapPool
from postroom.mail.models import SearchCriteria
from postroom.mail.service import MailService
from tests.integration.conftest import insecure_ctx

pytestmark = pytest.mark.integration


def seed(raw_imap, subject, body="hello", sender="bob@example.com"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = (
        sender,
        "alice@example.com",
        subject,
        f"<{subject}@t>",
    )
    m.set_content(body)
    raw_imap.append("INBOX", m.as_bytes())


@pytest.fixture
def svc(repo, gm_account, raw_imap):
    for name in ("Drafts", "Sent"):
        if not raw_imap.folder_exists(name):
            raw_imap.create_folder(name)
    pool = ImapPool(repo, ImapConnector(ssl_context=insecure_ctx()))
    yield MailService(repo, pool)
    pool.close_all()


async def test_search_get_does_not_mark_seen(svc, raw_imap, gm_account):
    seed(raw_imap, "peek-test", body="unique-body-text")
    res = await svc.search([gm_account], "inbox", SearchCriteria(subject="peek-test"))
    assert len(res.results) == 1 and res.results[0].seen is False
    uid = res.results[0].uid
    detail = await svc.get_message(gm_account, "INBOX", uid)
    assert "unique-body-text" in detail.message.body_text
    raw_imap.select_folder("INBOX", readonly=True)
    flags = raw_imap.get_flags([uid])[uid]
    assert b"\\Seen" not in flags


async def test_create_draft_lands_in_drafts(svc, raw_imap, gm_account):
    seed(raw_imap, "reply-me")
    res = await svc.search([gm_account], "inbox", SearchCriteria(subject="reply-me"))
    d = await svc.create_draft(
        gm_account,
        to=[],
        subject=None,
        body="Thanks",
        reply_folder="INBOX",
        reply_uid=res.results[0].uid,
    )
    raw_imap.select_folder("Drafts", readonly=True)
    uids = raw_imap.search(["HEADER", "Message-ID", d.message_id])
    assert len(uids) == 1
    msg = raw_imap.fetch(uids, ["BODY.PEEK[HEADER]", "FLAGS"])[uids[0]]
    assert b"In-Reply-To: <reply-me@t>" in msg[b"BODY[HEADER]"]
    assert b"\\Draft" in msg[b"FLAGS"]


async def test_thread_non_gmail(svc, raw_imap, gm_account):
    seed(raw_imap, "thread-root")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "bob@example.com", "alice@example.com", "Re: thread-root"
    m["Message-ID"], m["In-Reply-To"], m["References"] = (
        "<thread-2@t>",
        "<thread-root@t>",
        "<thread-root@t>",
    )
    m.set_content("second")
    raw_imap.append("INBOX", m.as_bytes())
    res = await svc.search([gm_account], "inbox", SearchCriteria(subject="thread-root"))
    root_uid = min(r.uid for r in res.results)
    thread = await svc.get_thread(gm_account, "INBOX", root_uid)
    assert [t.subject for t in thread] == ["thread-root", "Re: thread-root"]


async def test_big_message_is_read_by_section_without_marking_seen(
    svc, raw_imap, gm_account, monkeypatch
):
    from postroom.mail import parse, service
    from tests.unit.test_parse_structure import _mixed

    m = _mixed()
    m["Message-ID"] = "<section-read@t>"
    raw = m.as_bytes()
    raw_imap.append("INBOX", raw)
    monkeypatch.setattr(service, "MAX_FULL_PARSE_BYTES", 100)  # every message is "big"
    res = await svc.search([gm_account], "inbox", SearchCriteria(subject="Faktura"))
    uid = res.results[0].uid
    full = parse.parse_message(raw)

    detail = await svc.get_message(gm_account, "INBOX", uid)
    assert detail.message.subject == "Faktura"
    assert detail.message.body_text == full.body_text.rstrip("\n")  # CRLF before a boundary
    assert [(a.index, a.filename, a.content_type) for a in detail.message.attachments] == [
        (a.index, a.filename, a.content_type) for a in full.attachments
    ]
    for a in full.attachments:
        info, data = await svc.get_attachment(gm_account, "INBOX", uid, a.index)
        want = parse.get_attachment(raw, a.index)[1]
        assert info.filename == a.filename
        if a.content_type == "message/rfc822":  # as stored: CRLF, no newline before boundary
            data, want = data.replace(b"\r\n", b"\n"), want.rstrip(b"\n")
        assert data == want

    raw_imap.select_folder("INBOX", readonly=True)
    assert b"\\Seen" not in raw_imap.get_flags([uid])[uid]
