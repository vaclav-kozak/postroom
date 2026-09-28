"""Sending against a real server: GreenMail's SMTPS delivers to its own IMAP mailboxes,
so a sent email can be read back and the Sent copy checked."""

import base64
import email
import time
from email.message import EmailMessage
from email.policy import default

import pytest

from postroom.accounts import Provider, SmtpStatus
from postroom.mail.imap import ImapConnector, ImapPool
from postroom.mail.service import MailService
from postroom.mail.smtp import SmtpConnector, SmtpSender
from tests.integration.conftest import USER, insecure_ctx

pytestmark = pytest.mark.integration


@pytest.fixture
def smtp_account(repo, gm_account, greenmail_smtps):
    host, port = greenmail_smtps
    repo.upsert(
        email=USER,
        provider=Provider.IMAP,
        smtp_host=host,
        smtp_port=port,
        smtp_security="ssl",
    )
    return USER


@pytest.fixture
def svc(repo, smtp_account, raw_imap):
    for name in ("Drafts", "Sent", "Trash"):
        if not raw_imap.folder_exists(name):
            raw_imap.create_folder(name)
    pool = ImapPool(repo, ImapConnector(ssl_context=insecure_ctx()))
    smtp = SmtpSender(repo, SmtpConnector(ssl_context=insecure_ctx()), locks=pool.locks)
    yield MailService(repo, pool, smtp=smtp)
    pool.close_all()


def wait_for(raw_imap, folder, criteria, timeout=10.0):
    """UIDs matching `criteria` in `folder`, polling while SMTP delivery completes."""
    deadline = time.monotonic() + timeout
    while True:
        raw_imap.select_folder(folder, readonly=True)
        uids = raw_imap.search(criteria)
        if uids or time.monotonic() > deadline:
            return uids
        time.sleep(0.2)


def fetch(raw_imap, folder, uid):
    raw_imap.select_folder(folder, readonly=True)
    data = raw_imap.fetch([uid], ["BODY.PEEK[]", "FLAGS"])[uid]
    return email.message_from_bytes(data[b"BODY[]"], policy=default), data[b"FLAGS"]


async def test_sender_check_logs_in(repo, svc, smtp_account):
    assert svc.smtp.check(smtp_account) is None
    assert repo.get(smtp_account).smtp_status == SmtpStatus.OK


async def test_send_delivers_and_files_a_copy_in_sent(svc, raw_imap, smtp_account):
    pdf = base64.b64encode(b"%PDF-1.4 fake").decode()
    res = await svc.send(
        smtp_account,
        to=["bob@example.com"],
        bcc=[USER],
        subject="smtp-roundtrip",
        body="Hello over SMTP",
        attachments=[
            {"filename": "a.pdf", "content_type": "application/pdf", "content_base64": pdf}
        ],
    )
    assert res.recipients == 2 and res.warnings == []
    assert res.saved_to_sent is True and res.sent_folder == "Sent"

    # Delivered to the Bcc recipient (the account itself) without the Bcc header.
    uids = wait_for(raw_imap, "INBOX", ["HEADER", "Message-ID", res.message_id])
    assert len(uids) == 1
    got, _ = fetch(raw_imap, "INBOX", uids[0])
    assert got["Bcc"] is None
    assert got["To"] == "bob@example.com" and got["From"].addresses[0].addr_spec == USER
    assert "Hello over SMTP" in got.get_body(("plain",)).get_content()
    assert [p.get_filename() for p in got.iter_attachments()] == ["a.pdf"]

    # The Sent copy keeps the Bcc (the owner's record) and is already read.
    uids = wait_for(raw_imap, "Sent", ["HEADER", "Message-ID", res.message_id])
    assert len(uids) == 1
    copy, flags = fetch(raw_imap, "Sent", uids[0])
    assert copy["Bcc"] == USER and b"\\Seen" in flags


async def test_reply_threads_and_marks_the_original_answered(svc, raw_imap, smtp_account):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = (
        "bob@example.com",
        USER,
        "question",
        "<question@t>",
    )
    m.set_content("Can you?")
    raw_imap.append("INBOX", m.as_bytes())
    raw_imap.select_folder("INBOX", readonly=True)
    original = raw_imap.search(["HEADER", "Message-ID", "<question@t>"])[0]

    res = await svc.send(
        smtp_account,
        to=None,
        subject=None,
        body="Yes.",
        cc=[USER],
        reply_folder="INBOX",
        reply_uid=original,
    )
    assert res.warnings == []
    uids = wait_for(raw_imap, "INBOX", ["HEADER", "Message-ID", res.message_id])
    got, _ = fetch(raw_imap, "INBOX", uids[0])
    assert got["Subject"] == "Re: question"
    assert got["In-Reply-To"] == "<question@t>" and got["To"] == "bob@example.com"
    raw_imap.select_folder("INBOX", readonly=True)
    assert b"\\Answered" in raw_imap.get_flags([original])[original]


async def test_forward_sends_the_original_on(svc, raw_imap, smtp_account):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = (
        "carol@example.com",
        USER,
        "report",
        "<report@t>",
    )
    m.set_content("The numbers.")
    m.add_attachment(b"1,2,3\n", maintype="text", subtype="csv", filename="n.csv")
    raw_imap.append("INBOX", m.as_bytes())
    raw_imap.select_folder("INBOX", readonly=True)
    original = raw_imap.search(["HEADER", "Message-ID", "<report@t>"])[0]

    res = await svc.forward(smtp_account, "INBOX", original, to=[USER], body="FYI")
    uids = wait_for(raw_imap, "INBOX", ["HEADER", "Message-ID", res.message_id])
    got, _ = fetch(raw_imap, "INBOX", uids[0])
    assert got["Subject"] == "Fwd: report"
    text = got.get_body(("plain",)).get_content()
    assert text.startswith("FYI") and "The numbers." in text
    assert [p.get_filename() for p in got.iter_attachments()] == ["n.csv"]


async def test_send_draft_sends_and_removes_the_draft(svc, raw_imap, smtp_account):
    d = await svc.create_draft(smtp_account, to=[USER], subject="draft-to-send", body="Draft body")
    raw_imap.select_folder("Drafts", readonly=True)
    draft_uid = raw_imap.search(["HEADER", "Message-ID", d.message_id])[0]

    res = await svc.send_draft(smtp_account, draft_uid)
    assert res.draft_removed is True and res.warnings == []

    uids = wait_for(raw_imap, "INBOX", ["SUBJECT", "draft-to-send"])
    got, _ = fetch(raw_imap, "INBOX", uids[0])
    assert "Draft body" in got.get_body(("plain",)).get_content()
    raw_imap.select_folder("Drafts", readonly=True)
    assert raw_imap.search(["HEADER", "Message-ID", d.message_id]) == []
    assert wait_for(raw_imap, "Sent", ["SUBJECT", "draft-to-send"])


async def test_wrong_smtp_password_pauses_sending(repo, svc, smtp_account):
    repo.upsert(email=USER, provider=Provider.IMAP, smtp_username="nobody@example.com")
    try:
        with pytest.raises(Exception, match="authentication failed|login"):
            await svc.send(smtp_account, to=[USER], subject="never", body="x")
        assert repo.get(smtp_account).smtp_status == SmtpStatus.AUTH_FAILED
    finally:
        repo.upsert(email=USER, provider=Provider.IMAP, smtp_username=USER)
