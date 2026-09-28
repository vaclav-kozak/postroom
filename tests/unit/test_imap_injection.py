"""CR/LF/NUL in an inline IMAP argument would end the command and inject new ones."""

import contextlib

import pytest
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError

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
