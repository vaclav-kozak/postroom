"""CR/LF/NUL in an inline IMAP argument would end the command and inject new ones."""

import contextlib
import imaplib
from datetime import UTC, datetime

import pytest
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError
from imapclient.imapclient import datetime_to_INTERNALDATE, seq_to_parenstr

from postroom.mail.imap import SafeIMAPClient, UnsafeImapArgument

PAYLOAD = "x\r\nZ1 SELECT INBOX\r\nZ2 UID MOVE 1:* Trash"


class _StubImap:
    def __init__(self):
        self.sent = b""
        self.tagged_commands = {}
        self.untagged_responses = {}
        self.n = 0

    def _new_tag(self):
        self.n += 1
        return f"K{self.n:03d}".encode()

    def send(self, data):
        self.sent += data

    def _command_complete(self, cmd, tag):
        return "OK", [b""]

    def _get_response(self):
        return None


def _client(cls=SafeIMAPClient):
    c = object.__new__(cls)
    c._imap = _StubImap()
    c.use_uid = True
    c.folder_encode = True
    c._cached_capabilities = (b"IMAP4REV1", b"X-GM-EXT-1", b"LITERAL+")
    c._starttls_done = False
    return c


def test_stock_imapclient_is_injectable():
    """Documents why SafeIMAPClient exists; fails if imapclient ever starts escaping."""
    c = _client(IMAPClient)
    with contextlib.suppress(IMAPClientError, AttributeError, KeyError):
        c.search(["TEXT", PAYLOAD])
    assert b"\r\nZ2 UID MOVE" in c._imap.sent


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.search(["TEXT", PAYLOAD]),
        lambda c: c.search(["HEADER", "Message-ID", PAYLOAD]),
        lambda c: c.search(["FROM", "a\nb"]),
        lambda c: c.search(["SUBJECT", "a\x00b"]),
        lambda c: c.gmail_search(PAYLOAD),
        lambda c: c.select_folder(PAYLOAD, readonly=True),
        lambda c: c.folder_status(PAYLOAD),
    ],
)
def test_line_breaks_are_refused_before_anything_is_sent(call):
    c = _client()
    with pytest.raises(UnsafeImapArgument):
        call(c)
    assert c._imap.sent == b""


def test_unsafe_argument_is_a_value_error():
    assert issubclass(UnsafeImapArgument, ValueError)


def test_eight_bit_values_go_out_as_literals_and_are_allowed():
    c = _client()
    with contextlib.suppress(IMAPClientError, AttributeError, KeyError):
        c.search(["TEXT", "přílohá\r\nZ1 NOOP"], charset="UTF-8")
    sent = c._imap.sent
    assert b"{" in sent  # sent as a literal, so the CRLF is data, not a command end
    assert not sent.split(b"\r\n")[0].endswith(b"NOOP")


def test_plain_searches_still_work():
    c = _client()
    with contextlib.suppress(IMAPClientError, AttributeError, KeyError):
        c.search(["FROM", "jan@example.com", "SUBJECT", "faktura 2026"])
    assert c._imap.sent.startswith(b"K001 UID SEARCH FROM")
    assert c._imap.sent.count(b"\r\n") == 1


class _AppendStub:
    """The two imaplib.IMAP4 members that APPEND uses."""

    def __init__(self):
        self.literal = None
        self.calls = []

    def _simple_command(self, name, *args):
        self.calls.append((name, args, self.literal))
        self.literal = None
        return "OK", [b"[APPENDUID 1 7] done"]


def _append_client():
    c = _client()
    c._imap = _AppendStub()
    return c


def test_append_of_a_crlf_message_sends_it_as_given_without_a_copy():
    msg = b"From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n.line\r\n"
    when = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
    c = _append_client()
    assert c.append("Sent", msg, flags=(b"\\Seen",), msg_time=when) == b"[APPENDUID 1 7] done"
    (name, args, literal) = c._imap.calls[0]
    assert literal is msg  # no re.sub copy

    # The same command imaplib's own append would issue.
    stock = _AppendStub()
    imaplib.IMAP4.append(stock, *_stock_args(c, "Sent", (b"\\Seen",), when), msg)
    assert (name, args) == stock.calls[0][:2]
    assert stock.calls[0][2] == msg


def _stock_args(c, folder, flags, when):
    return (
        c._normalise_folder(folder),
        seq_to_parenstr(flags),
        f'"{datetime_to_INTERNALDATE(when)}"',
    )


def test_append_of_a_message_with_bare_line_endings_is_normalised_by_imaplib():
    c = _append_client()
    c._imap.append = lambda *a: imaplib.IMAP4.append(c._imap, *a)
    c.append("Sent", b"Subject: x\n\nbody\rmore\n")
    assert c._imap.calls[0][2] == b"Subject: x\r\n\r\nbody\r\nmore\r\n"


def test_append_refuses_an_unsafe_folder_name():
    c = _append_client()
    with pytest.raises(UnsafeImapArgument):
        c.append(PAYLOAD, b"x\r\n")
    assert c._imap.calls == []
