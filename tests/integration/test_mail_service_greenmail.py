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


def _uid(raw_imap, folder, subject):
    raw_imap.select_folder(folder, readonly=True)
    uids = raw_imap.search(["SUBJECT", subject])
    assert len(uids) == 1, (folder, subject, uids)
    return uids[0]


def _flags(raw_imap, folder, uid):
    raw_imap.select_folder(folder, readonly=True)
    return raw_imap.get_flags([uid])[uid]


async def test_mark_read_unread_and_flagged(svc, raw_imap, gm_account):
    from postroom.mail.models import MessageRef

    seed(raw_imap, "org-mark")
    uid = _uid(raw_imap, "INBOX", "org-mark")
    ref = [MessageRef(gm_account, "inbox", uid)]

    res = await svc.set_flags(ref, read=True, flagged=True)
    assert res.updated == 1 and not res.failed
    assert {b"\\Seen", b"\\Flagged"} <= set(_flags(raw_imap, "INBOX", uid))

    res = await svc.set_flags(ref + [MessageRef(gm_account, "inbox", 999999)], read=False)
    assert res.updated == 1 and res.failed[0].uids == [999999]
    flags = set(_flags(raw_imap, "INBOX", uid))
    assert b"\\Seen" not in flags and b"\\Flagged" in flags

    await svc.set_flags(ref, flagged=False)
    assert b"\\Flagged" not in set(_flags(raw_imap, "INBOX", uid))


async def test_move_and_trash(svc, raw_imap, gm_account):
    from postroom.mail.models import MessageRef

    for name in ("Projects", "Trash"):
        if not raw_imap.folder_exists(name):
            raw_imap.create_folder(name)
    seed(raw_imap, "org-move")
    seed(raw_imap, "org-trash")
    move_uid = _uid(raw_imap, "INBOX", "org-move")
    trash_uid = _uid(raw_imap, "INBOX", "org-trash")

    res = await svc.move([MessageRef(gm_account, "INBOX", move_uid)], "projects")
    assert res.updated == 1 and res.destinations == {gm_account: "Projects"}
    raw_imap.select_folder("INBOX", readonly=True)
    assert raw_imap.search(["SUBJECT", "org-move"]) == []
    moved_uid = _uid(raw_imap, "Projects", "org-move")

    res = await svc.trash(
        [MessageRef(gm_account, "INBOX", trash_uid), MessageRef(gm_account, "Projects", moved_uid)]
    )
    assert res.updated == 2 and res.destinations == {gm_account: "Trash"}
    in_trash = _uid(raw_imap, "Trash", "org-trash")
    _uid(raw_imap, "Trash", "org-move")

    res = await svc.trash([MessageRef(gm_account, "trash", in_trash)])
    assert res.updated == 0 and res.skipped[0].message == "already in trash"
    assert _uid(raw_imap, "Trash", "org-trash") == in_trash


async def test_move_without_move_extension_expunges_only_the_moved(
    svc, raw_imap, gm_account, monkeypatch
):
    from postroom.mail.imap import SafeIMAPClient
    from postroom.mail.models import MessageRef

    real = SafeIMAPClient.has_capability
    monkeypatch.setattr(
        SafeIMAPClient, "has_capability", lambda self, cap: cap != "MOVE" and real(self, cap)
    )
    expunged = []
    real_expunge = SafeIMAPClient.uid_expunge

    def spy(self, messages):
        expunged.append(list(messages))
        return real_expunge(self, messages)

    monkeypatch.setattr(SafeIMAPClient, "uid_expunge", spy)
    if not raw_imap.folder_exists("Kept"):
        raw_imap.create_folder("Kept")
    seed(raw_imap, "org-uidplus")
    seed(raw_imap, "org-bystander")
    uid = _uid(raw_imap, "INBOX", "org-uidplus")
    bystander = _uid(raw_imap, "INBOX", "org-bystander")
    raw_imap.select_folder("INBOX")
    raw_imap.add_flags([bystander], [b"\\Deleted"])  # someone else's pending delete

    res = await svc.move([MessageRef(gm_account, "INBOX", uid)], "Kept")
    assert res.updated == 1 and not res.failed and expunged == [[uid]]
    _uid(raw_imap, "Kept", "org-uidplus")
    raw_imap.select_folder("INBOX", readonly=True)
    assert raw_imap.search(["SUBJECT", "org-uidplus"]) == []
    assert raw_imap.search(["SUBJECT", "org-bystander"]) == [bystander]  # not expunged
    raw_imap.select_folder("INBOX")
    raw_imap.remove_flags([bystander], [b"\\Deleted"])


async def test_create_folder(svc, raw_imap, gm_account):
    top = await svc.create_folder(gm_account, "Clients")
    assert top == "Clients" and raw_imap.folder_exists("Clients")
    sub = await svc.create_folder(gm_account, "Acme Příliš", parent="clients")
    assert sub == "Clients.Acme Příliš" and raw_imap.folder_exists("Clients.Acme Příliš")
    with pytest.raises(ValueError, match="already exists"):
        await svc.create_folder(gm_account, "clients")
