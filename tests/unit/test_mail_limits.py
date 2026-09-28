"""Final fix round: upper bounds on tool arguments and on how much one search fetches."""

from datetime import UTC, datetime

import pytest
from fastmcp import Client, FastMCP

from postroom.accounts import AccountStatus, Provider
from postroom.mail import service
from postroom.mail.models import SearchCriteria
from postroom.mail.service import MailService
from postroom.tools.mail_tools import register_mail_tools
from tests.unit.test_mail_service import Fake, StubPool
from tests.unit.test_mail_tools import FakeMail, FakeReader


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


@pytest.fixture
def reader(repo):
    mcp = FastMCP("t")
    mail = FakeReader()
    register_mail_tools(mcp, repo, mail)
    return mcp, mail


@pytest.fixture
def searcher(repo):
    mcp = FastMCP("t")
    mail = FakeMail()
    register_mail_tools(mcp, repo, mail)
    return mcp, mail


@pytest.mark.parametrize("tool", ["get_email", "get_attachment"])
async def test_max_chars_has_an_upper_bound(reader, tool):
    mcp, mail = reader
    mail.error = LookupError("message not found")
    args = {"account": "a@x.cz", "folder": "inbox", "uid": 1}
    if tool == "get_attachment":
        args["index"] = 0
    async with Client(mcp) as c:
        res = await c.call_tool(tool, {**args, "max_chars": 200_001}, raise_on_error=False)
        assert res.is_error and "200000" in res.content[0].text
        assert mail.calls == []
        res = await c.call_tool(tool, {**args, "max_chars": 200_000}, raise_on_error=False)
    assert res.is_error and "message not found" in res.content[0].text
    assert len(mail.calls) == 1


async def test_search_offset_has_an_upper_bound(searcher):
    mcp, mail = searcher
    async with Client(mcp) as c:
        res = await c.call_tool("search_emails", {"offset": 1001}, raise_on_error=False)
        assert res.is_error and "1000" in res.content[0].text
        assert mail.calls == []
        await c.call_tool("search_emails", {"offset": 1000})
    assert mail.calls[0][-1] == 1000


class CountingFake(Fake):
    """Records the size of every FETCH so tests can bound how much one search pulls."""

    def __init__(self, msgs):
        super().__init__(msgs)
        self.fetch_sizes = []

    def fetch(self, uids, fields):
        self.fetch_sizes.append(len(uids))
        return super().fetch(uids, fields)


def _many(n):
    # INTERNALDATE grows with the UID, so "newest first" is also "highest UID first".
    t = datetime(2026, 1, 1, tzinfo=UTC).timestamp()
    return {
        i: (datetime.fromtimestamp(t + 60 * i, UTC), f"s{i}", "p", True) for i in range(1, n + 1)
    }


async def test_search_one_account_fetches_only_the_page(repo, two_accounts):
    fake = CountingFake(_many(1500))
    svc = MailService(repo, StubPool({"a@x.cz": fake}))
    res = await svc.search(["a@x.cz"], "inbox", SearchCriteria(), limit=100, offset=900)
    assert [m.uid for m in res.results] == list(range(600, 500, -1))
    assert sum(fake.fetch_sizes) == 100


async def test_search_many_accounts_fetches_in_chunks(repo, two_accounts):
    fakes = {"a@x.cz": CountingFake(_many(1500)), "b@x.cz": CountingFake(_many(1500))}
    svc = MailService(repo, StubPool(fakes))
    res = await svc.search(["a@x.cz", "b@x.cz"], "inbox", SearchCriteria(), limit=100, offset=1000)
    assert len(res.results) == 100
    for fake in fakes.values():
        assert max(fake.fetch_sizes) <= service.FETCH_CHUNK
        assert sum(fake.fetch_sizes) == 1100


async def test_search_attachment_filter_stops_when_it_has_enough(repo, two_accounts):
    class AttachmentFake(CountingFake):
        def fetch(self, uids, fields):
            out = super().fetch(uids, fields)
            for u, data in out.items():
                if u % 2:  # every odd UID has an attachment
                    data[b"BODYSTRUCTURE"] = (
                        b"application",
                        b"pdf",
                        None,
                        None,
                        None,
                        b"base64",
                        9,
                    )
            return out

    fake = AttachmentFake(_many(3000))
    svc = MailService(repo, StubPool({"a@x.cz": fake}))
    res = await svc.search(
        ["a@x.cz"], "inbox", SearchCriteria(has_attachment=True), limit=10, offset=20
    )
    assert [m.uid for m in res.results] == list(range(2959, 2939, -2))
    assert sum(fake.fetch_sizes) <= service.FETCH_CHUNK  # ~60 needed, not 3 x (offset + limit)


async def test_search_offset_is_capped_in_the_service(repo, two_accounts):
    fake = CountingFake(_many(3000))
    svc = MailService(repo, StubPool({"a@x.cz": fake, "b@x.cz": CountingFake({})}))
    await svc.search(["a@x.cz", "b@x.cz"], "inbox", SearchCriteria(), limit=100, offset=50_000)
    assert sum(fake.fetch_sizes) <= 1100
