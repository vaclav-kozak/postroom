from datetime import UTC, datetime

import pytest
from imapclient.response_types import Address, Envelope

from postroom.accounts import AccountStatus, Provider
from postroom.mail.imap import FETCH_BODY
from postroom.mail.models import SearchCriteria
from postroom.mail.service import MailService


def env(subject, sender):
    return Envelope(
        datetime(2026, 9, 25),  # noqa: DTZ001 -- envelope date is unused by the code under test
        subject.encode(),
        (Address(None, None, sender.encode(), b"x.cz"),),
        None,
        None,
        (Address(None, None, b"me", b"x.cz"),),
        None,
        None,
        None,
        b"<id>",
    )


class Fake:
    def __init__(self, msgs):
        self.msgs = msgs  # uid -> (date, subject, sender, seen)
        self.selected = []
        self.appended = []

    def list_folders(self):
        return [((), b"/", "INBOX"), ((b"\\Drafts",), b"/", "Drafts"), ((b"\\Sent",), b"/", "Sent")]

    def select_folder(self, name, readonly=False):
        assert readonly is True
        self.selected.append(name)

    def search(self, criteria, charset=None):
        return list(self.msgs)

    def fetch(self, uids, fields):
        out = {}
        for u in uids:
            d, s, snd, seen = self.msgs[u]
            out[u] = {
                b"ENVELOPE": env(s, snd),
                b"INTERNALDATE": d,
                b"FLAGS": (b"\\Seen",) if seen else (),
                b"RFC822.SIZE": 100,
                b"BODYSTRUCTURE": (b"text", b"plain", None, None, None, b"7bit", 1, 1),
            }
        return out

    def append(self, folder, msg, flags=(), msg_time=None):
        self.appended.append((folder, msg, flags))


class StubPool:
    def __init__(self, clients):
        self.clients = clients

    def session(self, email, manual=False):
        import contextlib

        @contextlib.contextmanager
        def cm():
            c = self.clients[email]
            if isinstance(c, Exception):
                raise c
            yield c

        return cm()


@pytest.fixture
def two_accounts(repo):
    for e in ("a@x.cz", "b@x.cz"):
        repo.upsert(
            email=e,
            provider=Provider.IMAP,
            imap_host="h",
            imap_port=993,
            imap_security="ssl",
            secret="p",
            status=AccountStatus.CONNECTED,
        )
    repo.upsert(
        email="g@gmail.com", provider=Provider.GOOGLE, status=AccountStatus.NEEDS_GOOGLE_CONNECT
    )


async def test_search_merges_and_reports_errors(repo, two_accounts):
    t = lambda h: datetime(2026, 9, 25, h, tzinfo=UTC)
    pool = StubPool(
        {
            "a@x.cz": Fake({1: (t(8), "old a", "p", True), 2: (t(12), "new a", "q", False)}),
            "b@x.cz": Fake({7: (t(10), "mid b", "r", True)}),
        }
    )
    svc = MailService(repo, pool)
    res = await svc.search(None, None, SearchCriteria(), limit=10)
    assert [m.subject for m in res.results] == ["new a", "mid b", "old a"]
    assert res.results[0].seen is False and res.results[0].account == "a@x.cz"
    assert [e.account for e in res.errors] == ["g@gmail.com"]


async def test_search_limit_and_offset(repo, two_accounts):
    t = lambda h: datetime(2026, 9, 25, h, tzinfo=UTC)
    pool = StubPool(
        {"a@x.cz": Fake({i: (t(i), f"s{i}", "p", True) for i in range(1, 6)}), "b@x.cz": Fake({})}
    )
    res = await MailService(repo, pool).search(
        ["a@x.cz"], "inbox", SearchCriteria(), limit=2, offset=1
    )
    assert [m.subject for m in res.results] == ["s4", "s3"]


async def test_one_account_failure_does_not_fail_call(repo, two_accounts):
    t = datetime(2026, 9, 25, tzinfo=UTC)
    pool = StubPool({"a@x.cz": Fake({1: (t, "ok", "p", True)}), "b@x.cz": OSError("boom")})
    res = await MailService(repo, pool).search(["a@x.cz", "b@x.cz"], None, SearchCriteria())
    assert len(res.results) == 1 and res.errors[0].account == "b@x.cz"


async def test_create_draft_appends_to_drafts(repo, two_accounts):
    fake = Fake({})
    res = await MailService(repo, StubPool({"a@x.cz": fake, "b@x.cz": Fake({})})).create_draft(
        "a@x.cz", to=["z@y.cz"], subject="Hi", body="Body"
    )
    folder, raw, flags = fake.appended[0]
    assert folder == "Drafts" and flags == (b"\\Draft",) and b"Subject: Hi" in raw
    assert res.folder == "Drafts" and res.message_id.startswith("<")


async def test_create_draft_requires_recipient(repo, two_accounts):
    with pytest.raises(ValueError):
        await MailService(repo, StubPool({"a@x.cz": Fake({})})).create_draft(
            "a@x.cz", to=[], subject="x", body="y"
        )


async def test_get_message_too_large_never_fetches_body(repo, two_accounts):
    # Fetch SUMMARY_FIELDS first and decide on RFC822.SIZE before ever issuing the
    # (potentially huge) BODY.PEEK[] fetch; an oversized message is read part by part
    # from its BODYSTRUCTURE instead (final fix round). This fake's `fetch` asserts the
    # whole-body fetch is never attempted.
    t = datetime(2026, 9, 25, tzinfo=UTC)

    class HugeSizeFake(Fake):
        def fetch(self, uids, fields):
            if fields == [FETCH_BODY]:
                raise AssertionError("body must not be fetched for an oversized message")
            out = super().fetch(uids, fields)
            for data in out.values():
                data[b"RFC822.SIZE"] = 26 * 1024 * 1024
            return out

    fake = HugeSizeFake({1: (t, "big", "p", True)})
    svc = MailService(repo, StubPool({"a@x.cz": fake, "b@x.cz": Fake({})}))
    detail = await svc.get_message("a@x.cz", "inbox", 1)
    assert detail.message.body_text == ""  # the fake serves no section data


async def test_account_error_message_never_empty(repo, two_accounts):
    # A timeout (asyncio.wait_for) stringifies to "", which told the model nothing.
    t = datetime(2026, 9, 25, tzinfo=UTC)
    pool = StubPool({"a@x.cz": Fake({1: (t, "ok", "p", True)}), "b@x.cz": TimeoutError()})
    res = await MailService(repo, pool).search(["a@x.cz", "b@x.cz"], None, SearchCriteria())
    assert [(e.account, e.error) for e in res.errors] == [("b@x.cz", "TimeoutError")]


async def test_create_draft_uses_the_special_use_drafts_folder(repo, two_accounts):
    class TwoDrafts(Fake):
        def list_folders(self):
            return [((), b"/", "INBOX"), ((), b"/", "Drafts"), ((b"\\Drafts",), b"/", "Koncepty")]

    fake = TwoDrafts({})
    svc = MailService(repo, StubPool({"a@x.cz": fake, "b@x.cz": Fake({})}))
    res = await svc.create_draft("a@x.cz", to=["z@y.cz"], subject="S", body="B")
    assert res.folder == "Koncepty" and fake.appended[0][0] == "Koncepty"
