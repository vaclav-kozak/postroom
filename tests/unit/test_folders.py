import pytest

from postroom.mail.folders import FolderNotFound, resolve_folder, special_use_of

GMAIL = [
    ((b"\\HasNoChildren",), b"/", "INBOX"),
    ((b"\\HasChildren", b"\\Noselect"), b"/", "[Gmail]"),
    ((b"\\All", b"\\HasNoChildren"), b"/", "[Gmail]/Všechny zprávy"),
    ((b"\\Drafts", b"\\HasNoChildren"), b"/", "[Gmail]/Koncepty"),
    ((b"\\HasNoChildren", b"\\Sent"), b"/", "[Gmail]/Odeslaná pošta"),
]
PLAIN = [
    ((), b".", "INBOX"),
    ((), b".", "INBOX.Sent"),
    ((), b".", "INBOX.Drafts"),
    ((), b".", "Archiv"),
]


def test_special_use():
    assert special_use_of((b"\\HasNoChildren", b"\\Sent")) == "sent"
    assert special_use_of((b"\\HasNoChildren",)) is None


@pytest.mark.parametrize(
    "wanted,expected",
    [
        (None, "INBOX"),
        ("inbox", "INBOX"),
        ("INBOX", "INBOX"),
        ("all", "[Gmail]/Všechny zprávy"),
        ("drafts", "[Gmail]/Koncepty"),
        ("sent", "[Gmail]/Odeslaná pošta"),
        ("[Gmail]/Koncepty", "[Gmail]/Koncepty"),
    ],
)
def test_gmail(wanted, expected):
    assert resolve_folder(GMAIL, wanted) == expected


@pytest.mark.parametrize(
    "wanted,expected",
    [
        ("sent", "INBOX.Sent"),
        ("drafts", "INBOX.Drafts"),
        ("archive", "Archiv"),
        ("inbox.sent", "INBOX.Sent"),
    ],
)
def test_name_fallback(wanted, expected):
    assert resolve_folder(PLAIN, wanted) == expected


def test_missing():
    with pytest.raises(FolderNotFound):
        resolve_folder(PLAIN, "junk")
    with pytest.raises(FolderNotFound):
        resolve_folder(GMAIL, "[Gmail]")  # \Noselect is not a real mailbox


# A plain folder merely named "Drafts" next to the real SPECIAL-USE \Drafts one
# (e.g. left behind by another client): the draft must land in the \Drafts folder.
TWO_DRAFTS = [
    ((), b"/", "INBOX"),
    ((), b"/", "Drafts"),
    ((b"\\Drafts",), b"/", "Koncepty"),
]


def test_special_use_first_prefers_the_drafts_flag_over_the_name():
    assert resolve_folder(TWO_DRAFTS, "drafts", special_use_first=True) == "Koncepty"


def test_special_use_first_falls_back_to_names():
    assert resolve_folder(PLAIN, "drafts", special_use_first=True) == "INBOX.Drafts"


def test_default_resolution_keeps_exact_names_first():
    assert resolve_folder(TWO_DRAFTS, "drafts") == "Drafts"
