from datetime import date

from postroom.mail.models import SearchCriteria
from postroom.mail.service import gmail_query, imap_criteria


def test_empty():
    assert imap_criteria(SearchCriteria()) == ["ALL"]
    assert gmail_query(SearchCriteria()) == ""


def test_full_imap():
    c = SearchCriteria(
        query="faktura",
        sender="a@x.example.com",
        recipient="b@y.example.org",
        subject="Objednávka",
        since=date(2026, 9, 1),
        before=date(2026, 9, 10),
        unread_only=True,
    )
    assert imap_criteria(c) == [
        "FROM",
        "a@x.example.com",
        "TO",
        "b@y.example.org",
        "SUBJECT",
        "Objednávka",
        "SINCE",
        date(2026, 9, 1),
        "BEFORE",
        date(2026, 9, 10),
        "UNSEEN",
        "TEXT",
        "faktura",
    ]


def test_full_gmail():
    c = SearchCriteria(
        query="label:work",
        sender="a@x.example.com",
        subject="two words",
        since=date(2026, 9, 1),
        unread_only=True,
        has_attachment=True,
    )
    assert gmail_query(c) == (
        'from:a@x.example.com subject:"two words" after:2026/09/01 is:unread has:attachment label:work'
    )
