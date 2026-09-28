"""MailService sending: send / reply / forward / send_draft, the access-level and SMTP
gating, the Sent copy, flags on the original, draft removal, and the send tools."""

import asyncio
import base64
import contextlib
import email
import time
from email import policy
from email.message import EmailMessage

import pytest
from fastmcp import Client, FastMCP
from imapclient.exceptions import IMAPClientError

from postroom.accounts import AccountStatus, MailAccess, Provider, SendingDisabled
from postroom.mail import heavy
from postroom.mail import service as service_module
from postroom.mail.imap import FETCH_BODY, RESP_BODY, ImapError
from postroom.mail.outgoing import DuplicateSend, SendLimitExceeded, SendTimeout
from postroom.mail.service import FETCH_HEADER_CAPPED, MAYBE_SENT_KEYWORD, MailService
from postroom.mail.smtp import SendOutcome, SmtpMaybeSent, SmtpRejected
from postroom.tools.mail_tools import (
    PRESEND_TIMEOUT_MESSAGE,
    SEND_TIMEOUT_MESSAGE,
    register_mail_tools,
)

A, G = "user@example.com", "me@gmail.com"
SEEN, DRAFT, DELETED, ANSWERED = b"\\Seen", b"\\Draft", b"\\Deleted", b"\\Answered"


def message(
    subject="Plans",
    sender="Alice <alice@example.org>",
    to="user@example.com, bob@example.org",
    cc="carol@example.org",
    msgid="<orig@example.org>",
    body="Original text",
    attachments=(),
    extra=(),
) -> bytes:
    m = EmailMessage(policy=policy.SMTP)
    m["From"] = sender
    m["To"] = to
    if cc:
        m["Cc"] = cc
    m["Subject"] = subject
    m["Date"] = "Sun, 20 Sep 2026 10:00:00 +0000"
    m["Message-ID"] = msgid
    for name, value in extra:
        m[name] = value
    m.set_content(body)
    for filename, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return m.as_bytes()


class MailFake:
    """An IMAP client over in-memory folders: name -> {uid: [flags, raw]}."""

    def __init__(self, boxes, special=None, caps=("MOVE", "UIDPLUS"), append_error=None):
        self.boxes = {
            name: {u: [set(f), raw] for u, (f, raw) in msgs.items()} for name, msgs in boxes.items()
        }
        self.special = special or {
            "Sent Items": (b"\\Sent",),
            "Drafts": (b"\\Drafts",),
            "Trash": (b"\\Trash",),
        }
        for name in self.special:
            self.boxes.setdefault(name, {})
        self.caps = set(caps)
        self.append_error = append_error
        self.calls = []
        self.selected = None
        self.readonly = None
        self.next_uid = 500

    def list_folders(self):
        return [(tuple(self.special.get(n, ())), b"/", n) for n in self.boxes]

    def select_folder(self, name, readonly=False):
        assert name in self.boxes
        self.calls.append(("select", name, readonly))
        self.selected, self.readonly = name, readonly

    def fetch(self, uids, fields):
        box = self.boxes[self.selected]
        out = {}
        for u in uids:
            if u not in box:
                continue
            flags, raw = box[u]
            d = {}
            for f in fields:
                if f == "FLAGS":
                    d[b"FLAGS"] = tuple(flags)
                elif f == "RFC822.SIZE":
                    d[b"RFC822.SIZE"] = len(raw)
                elif f == FETCH_BODY:
                    d[RESP_BODY] = raw
                elif f == FETCH_HEADER_CAPPED:
                    d[b"BODY[HEADER]<0>"] = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            out[u] = d
        return out

    def append(self, folder, raw, flags=(), msg_time=None):
        self.calls.append(("append", folder, tuple(flags)))
        if self.append_error is not None:
            raise self.append_error
        self.next_uid += 1
        self.boxes[folder][self.next_uid] = [set(flags), raw]

    def _writable(self):
        assert self.readonly is False, "write on a folder opened read-only"
        return self.boxes[self.selected]

    def add_flags(self, uids, flags, silent=False):
        box = self._writable()
        self.calls.append(("add_flags", self.selected, list(uids), tuple(flags)))
        for u in uids:
            box[u][0] |= {f.encode() if isinstance(f, str) else f for f in flags}

    def has_capability(self, cap):
        return cap.upper() in self.caps

    def move(self, uids, folder):
        box = self._writable()
        assert "MOVE" in self.caps
        self.calls.append(("move", self.selected, list(uids), folder))
        for u in uids:
            self.next_uid += 1
            self.boxes[folder][self.next_uid] = box.pop(u)

    def uid_expunge(self, uids):
        box = self._writable()
        assert "UIDPLUS" in self.caps
        self.calls.append(("uid_expunge", self.selected, list(uids)))
        for u in uids:
            if DELETED in box.get(u, [()])[0]:
                del box[u]

    def expunge(self, *args):
        raise AssertionError("a plain EXPUNGE must never be issued")

    def ops(self, *kinds):
        return [c for c in self.calls if c[0] in kinds]

    def sent_copies(self, folder="Sent Items"):
        return [raw for _flags, raw in self.boxes[folder].values()]


class StubPool:
    def __init__(self, clients):
        self.clients = clients

    @contextlib.contextmanager
    def session(self, email, manual=False):
        c = self.clients[email]
        if isinstance(c, Exception):
            raise c
        yield c


class FakeSmtp:
    def __init__(self, refused=None, error=None, delay=0.0):
        self.sent = []
        self.refused = refused or {}
        self.error = error
        self.delay = delay

    def send(self, email, sender, recipients, raw):
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        wire = raw if isinstance(raw, bytes) else b"".join(raw)  # (header, body view)
        self.sent.append((email, sender, list(recipients), wire))
        return SendOutcome(refused=dict(self.refused))


@pytest.fixture
def accounts(repo):
    repo.upsert(
        email=A,
        provider=Provider.IMAP,
        imap_host="imap.example.com",
        imap_port=993,
        imap_security="ssl",
        secret="p",
        status=AccountStatus.CONNECTED,
        smtp_host="smtp.example.com",
        display_name="Me Example",
        mail_access=MailAccess.FULL,  # sending is opt-in
    )
    repo.upsert(
        email=G,
        provider=Provider.GOOGLE,
        status=AccountStatus.CONNECTED,
        mail_access=MailAccess.FULL,
    )


def service(repo, imap, smtp=None, **kw):
    return MailService(repo, StubPool(imap), smtp=smtp or FakeSmtp(), **kw)


def header_block(raw: bytes) -> bytes:
    return raw.split(b"\r\n\r\n", 1)[0]


def parsed(raw: bytes):
    return email.message_from_bytes(raw, policy=policy.default)


# -- gating --------------------------------------------------------------------------------


@pytest.mark.parametrize("level", [MailAccess.READ, MailAccess.ORGANIZE])
async def test_sending_needs_full_access(repo, accounts, level):
    repo.set_mail_access(A, level)
    imap, smtp = MailFake({"INBOX": {}}), FakeSmtp()
    svc = service(repo, {A: imap}, smtp)
    with pytest.raises(SendingDisabled, match=f"access level {level.value}"):
        await svc.send(A, to=["bob@example.org"], subject="x")
    with pytest.raises(SendingDisabled, match="admin UI"):
        await svc.forward(A, "inbox", 1, to=["bob@example.org"])
    with pytest.raises(SendingDisabled):
        await svc.send_draft(A, 1)
    assert smtp.sent == [] and imap.calls == []


async def test_sending_needs_an_smtp_server(repo, accounts):
    repo.set_smtp(A, host="")
    svc = service(repo, {A: MailFake({})})
    with pytest.raises(SendingDisabled, match="SMTP is not configured"):
        await svc.send(A, to=["bob@example.org"], subject="x")


async def test_unknown_account(repo, accounts):
    with pytest.raises(ImapError, match="unknown account"):
        await service(repo, {}).send("nobody@example.com", to=["b@example.org"], subject="x")


# -- send ------------------------------------------------------------------------------------


async def test_send_new_email(repo, accounts):
    imap, smtp = MailFake({"INBOX": {}}), FakeSmtp()
    result = await service(repo, {A: imap}, smtp).send(
        A,
        to=["Bob <bob@example.org>"],
        cc=["carol@example.org"],
        bcc=["secret@example.org"],
        subject="Hello",
        body="Hi Bob",
    )
    ((email_, sender, rcpts, wire),) = smtp.sent
    assert email_ == sender == A
    assert rcpts == ["bob@example.org", "carol@example.org", "secret@example.org"]
    # Nothing on the wire names the Bcc recipient.
    assert b"secret@example.org" not in wire and b"bcc:" not in header_block(wire).lower()
    msg = parsed(wire)
    assert msg["From"] == "Me Example <user@example.com>"
    assert msg["To"] == "Bob <bob@example.org>" and msg["Subject"] == "Hello"
    # The Sent copy keeps Bcc, is \Seen, and goes to the \Sent special-use folder.
    assert imap.ops("append") == [("append", "Sent Items", (SEEN,))]
    (copy,) = imap.sent_copies()
    assert parsed(copy)["Bcc"] == "secret@example.org"
    assert copy.replace(b"Bcc: secret@example.org\r\n", b"") == wire
    assert result.to_dict() == {
        "account": A,
        "message_id": msg["Message-ID"],
        "recipients": 3,
        "saved_to_sent": True,
        "sent_folder": "Sent Items",
        "warnings": [],
    }


async def test_send_validates_before_contacting_anything(repo, accounts):
    imap, smtp = MailFake({}), FakeSmtp()
    svc = service(repo, {A: imap}, smtp)
    with pytest.raises(ValueError, match="line breaks"):
        await svc.send(A, to=["bob@example.org"], subject="x\r\nBcc: evil@example.org")
    with pytest.raises(ValueError, match="invalid email address"):
        await svc.send(A, to=["not-an-address"], subject="x")
    with pytest.raises(ValueError, match="at least one recipient"):
        await svc.send(A, to=[], subject="x")
    with pytest.raises(ValueError, match="subject is required"):
        await svc.send(A, to=["bob@example.org"], subject=None)
    with pytest.raises(ValueError, match="reply_all needs"):
        await svc.send(A, to=["bob@example.org"], subject="x", reply_all=True)
    with pytest.raises(ValueError, match="not valid base64"):
        await svc.send(
            A,
            to=["bob@example.org"],
            subject="x",
            attachments=[{"filename": "a", "content_base64": "!!"}],
        )
    assert smtp.sent == [] and imap.calls == []


async def test_send_with_attachments(repo, accounts):
    imap, smtp = MailFake({}), FakeSmtp()
    await service(repo, {A: imap}, smtp).send(
        A,
        to=["bob@example.org"],
        subject="Report",
        body="Attached.",
        attachments=[
            {
                "filename": "../report.pdf",
                "content_type": "application/pdf",
                "content_base64": base64.b64encode(b"%PDF-1.7 data").decode(),
            }
        ],
    )
    wire = smtp.sent[0][3]
    assert wire.isascii()
    (part,) = parsed(wire).iter_attachments()
    assert part.get_filename() == "report.pdf" and part.get_content_type() == "application/pdf"
    assert part.get_content() == b"%PDF-1.7 data"


async def test_reply_threads_and_marks_answered(repo, accounts):
    imap = MailFake({"INBOX": {7: (set(), message())}})
    smtp = FakeSmtp()
    result = await service(repo, {A: imap}, smtp).send(
        A, to=None, subject=None, body="Sure.", reply_uid=7
    )
    msg = parsed(smtp.sent[0][3])
    assert msg["To"] == "Alice <alice@example.org>" and msg["Subject"] == "Re: Plans"
    assert msg["In-Reply-To"] == "<orig@example.org>"
    assert msg["References"] == "<orig@example.org>"
    assert msg["Cc"] is None
    assert ("add_flags", "INBOX", [7], (ANSWERED,)) in imap.ops("add_flags")
    assert ANSWERED in imap.boxes["INBOX"][7][0]
    assert result.saved_to_sent is True


async def test_reply_all_copies_the_original_recipients_except_own(repo, accounts):
    imap = MailFake({"INBOX": {7: (set(), message())}})
    smtp = FakeSmtp()
    await service(repo, {A: imap}, smtp).send(
        A, to=None, subject=None, reply_uid=7, reply_all=True, cc=["dan@example.org"]
    )
    msg = parsed(smtp.sent[0][3])
    assert msg["To"] == "Alice <alice@example.org>"
    assert msg["Cc"] == "dan@example.org, bob@example.org, carol@example.org"
    assert A not in smtp.sent[0][2]


async def test_reply_to_a_missing_email(repo, accounts):
    smtp = FakeSmtp()
    with pytest.raises(LookupError, match="message not found"):
        await service(repo, {A: MailFake({"INBOX": {}})}, smtp).send(
            A, to=None, subject=None, reply_uid=99
        )
    assert smtp.sent == []


async def test_answered_flag_failure_is_ignored(repo, accounts):
    imap = MailFake({"INBOX": {7: (set(), message())}})

    def refuse(*a, **kw):
        raise IMAPClientError("STORE failed")

    imap.add_flags = refuse
    result = await service(repo, {A: imap}).send(A, to=None, subject=None, reply_uid=7)
    assert result.saved_to_sent is True and result.warnings == []


async def test_sent_append_failure_is_a_warning_not_an_error(repo, accounts):
    imap = MailFake({}, append_error=IMAPClientError("APPEND failed: over quota"))
    smtp = FakeSmtp()
    result = await service(repo, {A: imap}, smtp).send(A, to=["bob@example.org"], subject="x")
    assert len(smtp.sent) == 1
    assert result.saved_to_sent is False and result.sent_folder is None
    assert "over quota" in result.warnings[0] and "was sent" in result.warnings[0]


async def test_no_sent_folder_is_a_warning(repo, accounts):
    imap = MailFake({}, special={"Drafts": (b"\\Drafts",)})
    result = await service(repo, {A: imap}).send(A, to=["bob@example.org"], subject="x")
    assert result.saved_to_sent is False and "no Sent folder" in result.warnings[0]


async def test_imap_down_after_sending_is_a_warning(repo, accounts):
    smtp = FakeSmtp()
    result = await service(repo, {A: ConnectionError("IMAP gone")}, smtp).send(
        A, to=["bob@example.org"], subject="x"
    )
    assert len(smtp.sent) == 1
    assert result.saved_to_sent is False and "updating the mailbox failed" in result.warnings[0]


async def test_refused_recipients_are_reported(repo, accounts):
    smtp = FakeSmtp(refused={"bad@example.org": "550 5.1.1 unknown user"})
    result = await service(repo, {A: MailFake({})}, smtp).send(
        A, to=["bad@example.org", "bob@example.org"], subject="x"
    )
    assert result.recipients == 1
    assert "bad@example.org: 550 5.1.1 unknown user" in result.warnings[0]


async def test_smtp_rejection_is_an_error_and_nothing_is_filed(repo, accounts):
    imap = MailFake({})
    smtp = FakeSmtp(error=SmtpRejected("the SMTP server refused every recipient (...)"))
    with pytest.raises(SmtpRejected):
        await service(repo, {A: imap}, smtp).send(A, to=["bob@example.org"], subject="x")
    assert imap.calls == []


async def test_gmail_files_sent_mail_itself(repo, accounts):
    imap, smtp = MailFake({"INBOX": {}}), FakeSmtp()
    result = await service(repo, {G: imap}, smtp).send(
        G, to=["bob@example.org"], bcc=["secret@example.org"], subject="x"
    )
    assert smtp.sent[0][2] == ["bob@example.org", "secret@example.org"]
    assert b"secret@example.org" not in smtp.sent[0][3]
    assert imap.calls == []  # no APPEND, not even a session
    assert result.saved_to_sent is True and result.sent_folder == "sent"


async def test_gmail_reply_still_marks_answered(repo, accounts):
    imap = MailFake({"INBOX": {7: (set(), message())}})
    await service(repo, {G: imap}).send(G, to=None, subject=None, reply_uid=7)
    assert imap.ops("append") == []
    assert imap.ops("add_flags") == [("add_flags", "INBOX", [7], (ANSWERED,))]


async def test_rate_limit(repo, accounts):
    smtp = FakeSmtp()
    svc = service(repo, {A: MailFake({})}, smtp, send_limit_per_hour=2)
    await svc.send(A, to=["bob@example.org"], subject="1")
    await svc.send(A, to=["bob@example.org"], subject="2")
    with pytest.raises(SendLimitExceeded, match="at most 2 emails per hour"):
        await svc.send(A, to=["bob@example.org"], subject="3")
    assert len(smtp.sent) == 2


async def test_send_timeout_propagates(repo, accounts):
    svc = service(repo, {A: MailFake({})}, FakeSmtp(delay=0.3), send_timeout=0.05)
    with pytest.raises(TimeoutError):
        await svc.send(A, to=["bob@example.org"], subject="x")


# -- forward -------------------------------------------------------------------------------


def with_attachment():
    return message(
        attachments=[
            ("notes.txt", "text/plain", b"the notes"),
            ("a.bin", "application/octet-stream", b"\x00\x01"),
        ]
    )


async def test_forward_with_attachments(repo, accounts):
    imap = MailFake({"INBOX": {5: (set(), with_attachment())}})
    smtp = FakeSmtp()
    result = await service(repo, {A: imap}, smtp).forward(
        A, "inbox", 5, to=["dan@example.org"], body="FYI"
    )
    msg = parsed(smtp.sent[0][3])
    assert msg["Subject"] == "Fwd: Plans" and msg["To"] == "dan@example.org"
    assert msg["References"] == "<orig@example.org>"
    text = msg.get_body(("plain",)).get_content().replace("\r\n", "\n")
    assert text.startswith("FYI\n\n---------- Forwarded message ---------\n")
    assert "From: Alice <alice@example.org>" in text and "Original text" in text
    names = [(p.get_filename(), p.get_content()) for p in msg.iter_attachments()]
    assert ("a.bin", b"\x00\x01") in names
    assert any(n == "notes.txt" and "the notes" in str(c) for n, c in names)
    assert ("add_flags", "INBOX", [5], ("$Forwarded",)) in imap.ops("add_flags")
    assert result.saved_to_sent is True


async def test_forward_without_attachments_and_no_double_prefix(repo, accounts):
    raw = message(subject="Fwd: Plans", attachments=[("n.txt", "text/plain", b"x")])
    imap = MailFake({"INBOX": {5: (set(), raw)}})
    smtp = FakeSmtp()
    await service(repo, {A: imap}, smtp).forward(
        A, "inbox", 5, to=["dan@example.org"], include_attachments=False
    )
    msg = parsed(smtp.sent[0][3])
    assert msg["Subject"] == "Fwd: Plans"
    assert list(msg.iter_attachments()) == []


async def test_forward_attachments_over_the_cap(repo, accounts, monkeypatch):
    monkeypatch.setattr(service_module, "MAX_FORWARD_ATTACHMENT_BYTES", 5)
    imap = MailFake({"INBOX": {5: (set(), with_attachment())}})
    smtp = FakeSmtp()
    with pytest.raises(ValueError, match="include_attachments=false"):
        await service(repo, {A: imap}, smtp).forward(A, "inbox", 5, to=["dan@example.org"])
    assert smtp.sent == []


async def test_forward_missing_email(repo, accounts):
    with pytest.raises(LookupError):
        await service(repo, {A: MailFake({"INBOX": {}})}).forward(
            A, "inbox", 5, to=["dan@example.org"]
        )


# -- send_draft ----------------------------------------------------------------------------

STORED = (
    b"From: Me Example <user@example.com>\r\n"
    b"To: bob@example.org\r\n"
    b"Bcc: hidden@example.org\r\n"
    b"Subject: Reviewed\r\n"
    b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
    b"Message-ID: <draft-1@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Final text\r\n"
)


def drafts(caps=("MOVE", "UIDPLUS")):
    return MailFake(
        {
            "INBOX": {3: (set(), message()), 4: ({DRAFT}, STORED)},
            "Drafts": {9: ({DRAFT}, STORED), 10: ({DRAFT, DELETED}, STORED)},
        },
        caps=caps,
    )


async def test_send_draft_sends_files_and_expunges_only_that_draft(repo, accounts):
    imap, smtp = drafts(), FakeSmtp()
    result = await service(repo, {A: imap}, smtp).send_draft(A, 9)
    (_, _, rcpts, wire) = smtp.sent[0]
    assert rcpts == ["bob@example.org", "hidden@example.org"]
    assert b"hidden@example.org" not in wire
    msg = parsed(wire)
    assert msg["Message-ID"] == "<draft-1@example.com>"
    assert msg["Date"] != "Mon, 01 Jan 2024 00:00:00 +0000"
    assert msg.get_content().strip() == "Final text"
    (copy,) = imap.sent_copies()
    assert b"Bcc: hidden@example.org" in copy
    assert imap.ops("uid_expunge") == [("uid_expunge", "Drafts", [9])]
    # The other message flagged \Deleted by someone else is untouched.
    assert set(imap.boxes["Drafts"]) == {10}
    assert result.draft_removed is True
    assert result.to_dict()["draft_removed"] is True


async def test_send_draft_moves_to_trash_without_uidplus(repo, accounts):
    imap = drafts(caps=("MOVE",))
    result = await service(repo, {A: imap}).send_draft(A, 9)
    assert imap.ops("move") == [("move", "Drafts", [9], "Trash")]
    assert imap.ops("uid_expunge") == []
    assert result.draft_removed is True


async def test_send_draft_leaves_it_when_it_cannot_remove_safely(repo, accounts):
    imap = drafts(caps=())
    result = await service(repo, {A: imap}).send_draft(A, 9)
    assert 9 in imap.boxes["Drafts"]
    assert result.draft_removed is False and "left in Drafts" in result.warnings[0]


async def test_send_draft_accepts_a_draft_flagged_elsewhere(repo, accounts):
    imap, smtp = drafts(), FakeSmtp()
    await service(repo, {A: imap}, smtp).send_draft(A, 4, folder="inbox")
    assert len(smtp.sent) == 1


async def test_send_draft_refuses_ordinary_mail(repo, accounts):
    imap, smtp = drafts(), FakeSmtp()
    with pytest.raises(ValueError, match="not a draft"):
        await service(repo, {A: imap}, smtp).send_draft(A, 3, folder="inbox")
    assert smtp.sent == []


async def test_send_draft_needs_the_flag_even_in_the_drafts_folder(repo, accounts):
    imap = drafts()
    imap.boxes["Drafts"][9][0] = set()
    smtp = FakeSmtp()
    with pytest.raises(ValueError, match="no \\\\Draft flag"):
        await service(repo, {A: imap}, smtp).send_draft(A, 9)
    assert smtp.sent == []


async def test_send_draft_refuses_a_foreign_from_even_with_the_flag(repo, accounts):
    """A received email moved into Drafts (organise is allowed) and flagged \\Draft must not
    go out through the owner's server under its original sender's name."""
    phishing = message(sender="Bank <security@bank.example>", to="user@example.com")
    imap = drafts()
    imap.boxes["Drafts"][11] = [{DRAFT}, phishing]
    spoofed_sender = STORED.replace(
        b"Subject: Reviewed", b"Sender: someone@example.net\r\nSubject: Reviewed"
    )
    imap.boxes["Drafts"][12] = [{DRAFT}, spoofed_sender]
    smtp = FakeSmtp()
    svc = service(repo, {A: imap}, smtp)
    for uid in (11, 12):
        with pytest.raises(ValueError, match="From is not this account"):
            await svc.send_draft(A, uid)
    assert smtp.sent == [] and imap.ops("append") == []


async def test_send_draft_size_cap(repo, accounts, monkeypatch):
    monkeypatch.setattr(service_module, "MAX_DRAFT_BYTES", 100)
    smtp = FakeSmtp()
    with pytest.raises(ValueError, match="larger than 10 MiB"):
        await service(repo, {A: drafts()}, smtp).send_draft(A, 9)
    assert smtp.sent == []


async def test_send_draft_on_gmail_removes_the_draft_without_filing(repo, accounts):
    imap = drafts()
    imap.boxes["Drafts"][9][1] = STORED.replace(b"user@example.com", G.encode())
    result = await service(repo, {G: imap}).send_draft(G, 9)
    assert imap.ops("append") == []
    assert result.saved_to_sent is True and result.draft_removed is True


async def test_send_draft_missing(repo, accounts):
    with pytest.raises(LookupError):
        await service(repo, {A: drafts()}).send_draft(A, 99)


# -- tools -----------------------------------------------------------------------------------


@pytest.fixture
def tools(repo, accounts):
    def make(imap, smtp, **kw):
        mcp = FastMCP("t")
        register_mail_tools(mcp, repo, service(repo, {A: imap, G: imap}, smtp, **kw))
        return mcp

    return make


async def test_send_email_tool(tools):
    imap, smtp = MailFake({}), FakeSmtp()
    async with Client(tools(imap, smtp)) as c:
        res = await c.call_tool(
            "send_email",
            {
                "account": " User@Example.com ",
                "to": ["bob@example.org"],
                "subject": "Hi",
                "body": "Hello",
                "attachments": [
                    {
                        "filename": "a.txt",
                        "content_type": "text/plain",
                        "content_base64": base64.b64encode(b"hi").decode(),
                    }
                ],
            },
        )
    data = res.structured_content
    assert data["account"] == A and data["recipients"] == 1 and data["saved_to_sent"] is True
    assert len(smtp.sent) == 1


async def test_send_tool_errors_are_clean(tools, repo):
    repo.set_mail_access(A, MailAccess.ORGANIZE)
    async with Client(tools(MailFake({}), FakeSmtp())) as c:
        res = await c.call_tool(
            "send_email",
            {"account": A, "to": ["bob@example.org"], "subject": "Hi"},
            raise_on_error=False,
        )
    assert res.is_error
    assert res.content[0].text.startswith(
        f"sending is disabled for account {A} (access level organize)"
    )


async def test_send_tool_rejection_message(tools):
    smtp = FakeSmtp(error=SmtpRejected("the SMTP server rejected the message: 554 5.7.1 spam"))
    async with Client(tools(MailFake({}), smtp)) as c:
        res = await c.call_tool(
            "send_email",
            {"account": A, "to": ["bob@example.org"], "subject": "Hi"},
            raise_on_error=False,
        )
    assert res.is_error and "554 5.7.1 spam" in res.content[0].text


async def test_send_tool_timeout_warns_about_duplicates(tools):
    async with Client(tools(MailFake({}), FakeSmtp(delay=0.3), send_timeout=0.05)) as c:
        res = await c.call_tool(
            "send_email",
            {"account": A, "to": ["bob@example.org"], "subject": "Hi"},
            raise_on_error=False,
        )
    assert res.is_error and res.content[0].text == SEND_TIMEOUT_MESSAGE
    assert "search_emails folder='sent'" in SEND_TIMEOUT_MESSAGE


async def test_forward_and_send_draft_tools(tools):
    imap = drafts()
    imap.boxes["INBOX"][5] = [set(), with_attachment()]
    smtp = FakeSmtp()
    async with Client(tools(imap, smtp)) as c:
        fwd = await c.call_tool(
            "forward_email",
            {"account": A, "folder": "inbox", "uid": 5, "to": ["dan@example.org"]},
        )
        sent = await c.call_tool("send_draft", {"account": A, "uid": 9})
    assert fwd.structured_content["recipients"] == 1
    assert sent.structured_content["draft_removed"] is True
    assert len(smtp.sent) == 2


async def test_attachment_schema_rejects_unknown_fields(tools):
    async with Client(tools(MailFake({}), FakeSmtp())) as c:
        res = await c.call_tool(
            "send_email",
            {
                "account": A,
                "to": ["bob@example.org"],
                "subject": "Hi",
                "attachments": [{"filename": "a", "content_base64": "aGk=", "path": "/etc/x"}],
            },
            raise_on_error=False,
        )
    assert res.is_error


# -- duplicates, "maybe sent", timeouts ------------------------------------------------------


async def test_an_identical_send_is_refused_unless_allowed(repo, accounts):
    smtp = FakeSmtp()
    svc = service(repo, {A: MailFake({})}, smtp)
    args = {"to": ["bob@example.org"], "subject": "Hi", "body": "Hello"}
    await svc.send(A, **args)
    with pytest.raises(DuplicateSend, match="sent from this account 1 min ago"):
        await svc.send(A, **args)
    await svc.send(A, **{**args, "body": "Hello again"})  # different content: fine
    await svc.send(A, **args, allow_duplicate=True)
    assert len(smtp.sent) == 3


async def test_a_send_refused_before_data_can_be_retried(repo, accounts):
    smtp = FakeSmtp(error=SmtpRejected("the SMTP server refused every recipient"))
    svc = service(repo, {A: MailFake({})}, smtp)
    for _ in range(2):
        with pytest.raises(SmtpRejected):
            await svc.send(A, to=["bob@example.org"], subject="Hi")


async def test_maybe_sent_files_a_marked_copy_and_blocks_a_retry(repo, accounts):
    imap = MailFake({})
    smtp = FakeSmtp(error=SmtpMaybeSent("the connection broke while sending"))
    svc = service(repo, {A: imap}, smtp)
    with pytest.raises(SmtpMaybeSent) as e:
        await svc.send(A, to=["bob@example.org"], subject="Hi", body="x")
    text = str(e.value)
    assert "Do not retry automatically" in text and "Ask the owner" in text
    assert f"saved in Sent Items with the keyword {MAYBE_SENT_KEYWORD}" in text
    assert imap.ops("append") == [("append", "Sent Items", (SEEN, MAYBE_SENT_KEYWORD))]
    smtp.error = None
    with pytest.raises(DuplicateSend, match="may have gone through"):
        await svc.send(A, to=["bob@example.org"], subject="Hi", body="x")
    assert smtp.sent == []


async def test_maybe_sent_without_keyword_support_still_files_the_copy(repo, accounts):
    class NoKeywords(MailFake):
        def append(self, folder, raw, flags=(), msg_time=None):
            if MAYBE_SENT_KEYWORD in flags:
                self.calls.append(("append-refused", folder))
                raise IMAPClientError("APPEND failed: keywords not allowed")
            super().append(folder, raw, flags, msg_time)

    imap = NoKeywords({})
    svc = service(repo, {A: imap}, FakeSmtp(error=SmtpMaybeSent("broke")))
    with pytest.raises(SmtpMaybeSent, match="a copy was saved in Sent Items"):
        await svc.send(A, to=["bob@example.org"], subject="Hi")
    assert imap.ops("append") == [("append", "Sent Items", (SEEN,))]


async def test_maybe_sent_on_gmail_points_at_the_sent_folder(repo, accounts):
    imap = MailFake({})
    svc = service(repo, {G: imap}, FakeSmtp(error=SmtpMaybeSent("broke")))
    with pytest.raises(SmtpMaybeSent, match="check the Sent folder"):
        await svc.send(G, to=["bob@example.org"], subject="Hi")
    assert imap.ops("append") == []


async def test_a_timed_out_send_still_files_the_copy_and_blocks_a_retry(repo, accounts):
    imap = MailFake({})
    smtp = FakeSmtp(delay=0.3)
    svc = service(repo, {A: imap}, smtp, send_timeout=0.05)
    with pytest.raises(SendTimeout):
        await svc.send(A, to=["bob@example.org"], subject="Hi")
    # The worker is still sending: a retry now is refused as in flight.
    with pytest.raises(DuplicateSend, match="being sent from this account right now"):
        await svc.send(A, to=["bob@example.org"], subject="Hi")
    for _ in range(50):
        if imap.ops("append"):
            break
        await asyncio.sleep(0.02)
    # The abandoned call finished its work: sent once, with the Sent copy.
    assert len(smtp.sent) == 1 and len(imap.sent_copies()) == 1
    with pytest.raises(DuplicateSend, match="was sent from this account"):
        await svc.send(A, to=["bob@example.org"], subject="Hi")


async def test_a_timeout_before_sending_says_nothing_was_sent(tools):
    class SlowImap(MailFake):
        def select_folder(self, name, readonly=False):
            time.sleep(0.3)
            super().select_folder(name, readonly)

    imap = SlowImap({"INBOX": {5: (set(), message())}})
    smtp = FakeSmtp()
    async with Client(tools(imap, smtp, account_timeout=0.05)) as c:
        res = await c.call_tool(
            "send_email",
            {"account": A, "reply_to_uid": 5, "body": "Thanks"},
            raise_on_error=False,
        )
    assert res.is_error and res.content[0].text == PRESEND_TIMEOUT_MESSAGE
    assert smtp.sent == []


async def test_parallel_send_draft_calls_send_once(repo, accounts):
    imap, smtp = drafts(), FakeSmtp(delay=0.1)
    svc = service(repo, {A: imap}, smtp)
    results = await asyncio.gather(
        svc.send_draft(A, 9), svc.send_draft(A, 9), return_exceptions=True
    )
    assert len(smtp.sent) == 1
    ok = [r for r in results if not isinstance(r, Exception)]
    errors = [r for r in results if isinstance(r, Exception)]
    assert len(ok) == 1 and ok[0].draft_removed is True
    assert len(errors) == 1 and isinstance(errors[0], LookupError)  # the draft is gone
    assert svc._draft_locks == {}


async def test_a_sent_draft_left_in_place_is_not_sent_again(repo, accounts):
    imap, smtp = drafts(caps=()), FakeSmtp()  # cannot remove it
    svc = service(repo, {A: imap}, smtp)
    await svc.send_draft(A, 9)
    with pytest.raises(DuplicateSend):
        await svc.send_draft(A, 9)
    # The same draft (Message-ID) under another uid, e.g. after a client re-saved it.
    imap.boxes["Drafts"][20] = [{DRAFT}, STORED]
    with pytest.raises(DuplicateSend):
        await svc.send_draft(A, 20)
    await svc.send_draft(A, 9, allow_duplicate=True)
    assert len(smtp.sent) == 2


async def test_a_large_send_runs_under_the_heavy_gate(repo, accounts, monkeypatch):
    monkeypatch.setattr(service_module, "HEAVY_MESSAGE_BYTES", 10)
    depths = []

    class GateSmtp(FakeSmtp):
        def send(self, email, sender, recipients, raw):
            depths.append(getattr(heavy._local, "depth", 0))
            return super().send(email, sender, recipients, raw)

    imap = MailFake({})
    await service(repo, {A: imap}, GateSmtp()).send(A, to=["bob@example.org"], subject="Hi")
    assert depths == [1]


async def test_reply_all_reports_dropped_addresses(repo, accounts):
    original = message(cc="carol@example.org, Mallory <not-an-address>")
    imap = MailFake({"INBOX": {5: (set(), original)}})
    result = await service(repo, {A: imap}).send(
        A, to=None, subject=None, body="ok", reply_uid=5, reply_all=True, reply_folder="inbox"
    )
    assert any("not-an-address" in w and "reply-all left out" in w for w in result.warnings)


async def test_reply_to_a_last_first_sender(repo, accounts):
    original = message(sender='"Doe, John" <john@example.org>', cc='"Roe, Jane" <jane@example.org>')
    imap, smtp = MailFake({"INBOX": {5: (set(), original)}}), FakeSmtp()
    result = await service(repo, {A: imap}, smtp).send(
        A, to=None, subject=None, body="ok", reply_uid=5, reply_all=True, reply_folder="inbox"
    )
    (_, _, rcpts, wire) = smtp.sent[0]
    assert rcpts == ["john@example.org", "bob@example.org", "jane@example.org"]
    msg = parsed(wire)
    assert msg["To"].addresses[0].display_name == "Doe, John"
    assert result.warnings == []
