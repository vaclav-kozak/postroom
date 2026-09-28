"""MailService organising: flags, move, trash, create folder, and the access levels."""

import contextlib
import time

import pytest
from imapclient.exceptions import IMAPClientError

from postroom.accounts import AccountStatus, MailAccess, MailAccessDenied, Provider
from postroom.mail.imap import AccountUnavailable
from postroom.mail.models import MessageRef
from postroom.mail.service import (
    MAX_BATCH_REFS,
    MESSAGE_NOT_FOUND,
    MOVE_UNSUPPORTED,
    PARTIAL_TIMEOUT,
    MailService,
)

SEEN, FLAGGED, DELETED = b"\\Seen", b"\\Flagged", b"\\Deleted"
A, B, G = "user@example.com", "other@example.org", "me@gmail.com"


class OrgFake:
    """An IMAP client over in-memory folders: name -> {uid: set of flags}."""

    def __init__(self, boxes, caps=("MOVE", "UIDPLUS"), special=None, noselect=(), delim=b"/"):
        self.boxes = {name: {u: set(f) for u, f in msgs.items()} for name, msgs in boxes.items()}
        self.caps = {c.upper() for c in caps}
        self.special = special or {}
        self.noselect = list(noselect)
        self.delim = delim
        self.calls = []
        self.selected = None
        self.readonly = None
        self.next_uid = 1000
        self.msgids = {}  # (folder, uid) -> Gmail X-GM-MSGID

    def list_folders(self):
        out = [(tuple(self.special.get(n, ())), self.delim, n) for n in self.boxes]
        return out + [((b"\\Noselect",), self.delim, n) for n in self.noselect]

    def select_folder(self, name, readonly=False):
        assert name in self.boxes
        self.calls.append(("select", name, readonly))
        self.selected, self.readonly = name, readonly

    def fetch(self, uids, fields):
        box = self.boxes[self.selected]
        if fields == ["X-GM-MSGID"]:
            assert "X-GM-EXT-1" in self.caps
            return {u: {b"X-GM-MSGID": self.msgids[(self.selected, u)]} for u in uids if u in box}
        return {u: {b"FLAGS": tuple(box[u])} for u in uids if u in box}

    def search(self, criteria, charset=None):
        assert criteria[0] == "X-GM-MSGID"
        self.calls.append(("search", self.selected, criteria[1]))
        return [
            u
            for u in self.boxes[self.selected]
            if self.msgids.get((self.selected, u)) == criteria[1]
        ]

    def _writable(self):
        assert self.readonly is False, "write on a folder opened read-only"
        return self.boxes[self.selected]

    def add_flags(self, uids, flags, silent=False):
        box = self._writable()
        self.calls.append(("add_flags", list(uids), tuple(flags)))
        for u in uids:
            box[u] |= set(flags)

    def remove_flags(self, uids, flags, silent=False):
        box = self._writable()
        self.calls.append(("remove_flags", list(uids), tuple(flags)))
        for u in uids:
            box[u] -= set(flags)

    def has_capability(self, cap):
        return cap.upper() in self.caps

    def _add(self, folder, flags, msgid=None):
        # Like a real server, a copy or move keeps every flag, \Deleted included.
        self.next_uid += 1
        self.boxes[folder][self.next_uid] = set(flags)
        if msgid is not None:
            self.msgids[(folder, self.next_uid)] = msgid

    def move(self, uids, folder):
        box = self._writable()
        assert "MOVE" in self.caps
        self.calls.append(("move", list(uids), folder))
        for u in uids:
            self._add(folder, box.pop(u), self.msgids.get((self.selected, u)))

    def copy(self, uids, folder):
        box = self.boxes[self.selected]
        self.calls.append(("copy", list(uids), folder))
        for u in uids:
            self._add(folder, box[u], self.msgids.get((self.selected, u)))

    def uid_expunge(self, uids):
        box = self._writable()
        assert "UIDPLUS" in self.caps
        self.calls.append(("uid_expunge", list(uids)))
        for u in uids:
            if DELETED in box.get(u, ()):
                del box[u]

    def expunge(self, *args):
        raise AssertionError("a plain EXPUNGE must never be issued")

    def create_folder(self, name):
        self.calls.append(("create_folder", name))
        self.boxes[name] = {}

    def subscribe_folder(self, name):
        self.calls.append(("subscribe_folder", name))

    def ops(self, *kinds):
        return [c for c in self.calls if c[0] in kinds]


class StubPool:
    def __init__(self, clients):
        self.clients = clients
        self.sessions = []

    @contextlib.contextmanager
    def session(self, email, manual=False):
        self.sessions.append(email)
        c = self.clients[email]
        if isinstance(c, Exception):
            raise c
        yield c


@pytest.fixture
def accounts(repo):
    for email in (A, B):
        repo.upsert(
            email=email,
            provider=Provider.IMAP,
            imap_host="imap.example.com",
            imap_port=993,
            imap_security="ssl",
            secret="p",
            status=AccountStatus.CONNECTED,
            smtp_host="smtp.example.com",
        )
    repo.upsert(email=G, provider=Provider.GOOGLE, status=AccountStatus.CONNECTED)


def refs(account, folder, *uids):
    return [MessageRef(account, folder, u) for u in uids]


def standard_boxes():
    return {
        "INBOX": {1: set(), 2: {SEEN}, 3: set()},
        "Work": {10: set(), 11: set()},
        "Archive": {},
        "Trash": {50: {SEEN}},
    }


def standard_special():
    return {"Archive": (b"\\Archive",), "Trash": (b"\\Trash",)}


def fake(**kw):
    return OrgFake(standard_boxes(), special=standard_special(), **kw)


# -- access levels -----------------------------------------------------------------------


def test_capabilities_follow_the_access_level(repo, accounts):
    assert repo.get(A).mail_access == MailAccess.ORGANIZE  # the default
    repo.set_mail_access(A, MailAccess.ORGANIZE)
    assert repo.get(A).capabilities == ["mail", "mail.organize"]
    assert repo.get(A).can_send is False
    repo.set_mail_access(A, "read")
    assert repo.get(A).capabilities == ["mail"]
    repo.set_mail_access(A, MailAccess.FULL)
    assert repo.get(A).capabilities == ["mail", "mail.organize", "mail.send"]
    assert repo.get(A).can_send is True


def test_set_mail_access_unknown_account_and_level(repo, accounts):
    assert repo.set_mail_access("nobody@example.com", MailAccess.READ) is False
    with pytest.raises(ValueError):
        repo.set_mail_access(A, "admin")


def test_upsert_keeps_mail_access_unless_given(repo, accounts):
    repo.set_mail_access(A, MailAccess.READ)
    acc = repo.upsert(email=A, provider=Provider.IMAP, display_name="Renamed")
    assert acc.mail_access == MailAccess.READ and acc.display_name == "Renamed"
    acc = repo.upsert(email=A, provider=Provider.IMAP, mail_access=MailAccess.ORGANIZE)
    assert acc.mail_access == MailAccess.ORGANIZE
    new = repo.upsert(email="new@example.com", provider=Provider.IMAP)
    assert new.mail_access == MailAccess.ORGANIZE


async def test_read_only_account_is_refused_and_not_contacted(repo, accounts):
    repo.set_mail_access(A, MailAccess.READ)
    fa, fb = fake(), fake()
    pool = StubPool({A: fa, B: fb})
    res = await MailService(repo, pool).set_flags(
        refs(A, "inbox", 1, 3) + refs(A, "Work", 10) + refs(B, "inbox", 1), read=True
    )
    assert res.updated == 1
    message = f"account {A} is set to read-only mail access; the owner can change this in the admin UI (the account's access level) or with the `postroom set-access` command"
    assert [(f.account, f.folder, f.uids, f.message) for f in res.failed] == [
        (A, "inbox", [1, 3], message),
        (A, "Work", [10], message),
    ]
    assert pool.sessions == [B] and fa.calls == []
    assert SEEN in fb.boxes["INBOX"][1]


async def test_organize_level_may_organise(repo, accounts):
    repo.set_mail_access(A, MailAccess.ORGANIZE)
    f = fake()
    res = await MailService(repo, StubPool({A: f})).trash(refs(A, "inbox", 1))
    assert res.updated == 1 and not res.failed


async def test_read_only_account_cannot_move_trash_or_create(repo, accounts):
    repo.set_mail_access(A, MailAccess.READ)
    f = fake()
    svc = MailService(repo, StubPool({A: f}))
    for res in (
        await svc.move(refs(A, "inbox", 1), "archive"),
        await svc.trash(refs(A, "inbox", 1)),
    ):
        assert res.updated == 0 and "read-only mail access" in res.failed[0].message
    with pytest.raises(MailAccessDenied, match="read-only mail access"):
        await svc.create_folder(A, "New")
    assert f.calls == []


# -- batches -----------------------------------------------------------------------------


async def test_flags_grouped_across_accounts_and_folders(repo, accounts):
    fa, fb = fake(), fake()
    batch = (
        refs(A, "inbox", 1, 2)
        + refs(B, "Work", 11)
        + refs(A, "Work", 10)
        + refs(A, "INBOX", 1)  # same folder under another spelling, same uid twice
        + refs(B.upper(), "inbox", 3)
    )
    res = await MailService(repo, StubPool({A: fa, B: fb})).set_flags(
        batch, read=True, flagged=True
    )
    assert res.updated == 5 and res.failed == [] and res.skipped == []
    # One read-write select per folder, the flags stored once per folder for all its UIDs.
    assert fa.ops("select") == [("select", "INBOX", False), ("select", "Work", False)]
    assert fa.ops("add_flags") == [
        ("add_flags", [1, 2], (SEEN,)),
        ("add_flags", [1, 2], (FLAGGED,)),
        ("add_flags", [10], (SEEN,)),
        ("add_flags", [10], (FLAGGED,)),
    ]
    assert fb.boxes["Work"][11] == {SEEN, FLAGGED} and fb.boxes["INBOX"][3] == {SEEN, FLAGGED}


async def test_unflag_and_mark_unread(repo, accounts):
    f = fake()
    f.boxes["INBOX"][2] = {SEEN, FLAGGED}
    res = await MailService(repo, StubPool({A: f})).set_flags(
        refs(A, "inbox", 2), read=False, flagged=False
    )
    assert res.updated == 1 and f.boxes["INBOX"][2] == set()


async def test_only_the_given_flag_changes(repo, accounts):
    f = fake()
    await MailService(repo, StubPool({A: f})).set_flags(refs(A, "inbox", 1), flagged=True)
    assert f.ops("add_flags", "remove_flags") == [("add_flags", [1], (FLAGGED,))]


async def test_missing_uids_and_folders_are_reported(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).set_flags(
        refs(A, "inbox", 1, 99, 98) + refs(A, "Nope", 5), read=True
    )
    assert res.updated == 1
    assert [(g.folder, g.uids, g.message) for g in res.failed] == [
        ("Nope", [5], "folder not found: 'Nope'"),
        ("INBOX", [99, 98], MESSAGE_NOT_FOUND),
    ]
    assert f.ops("add_flags") == [("add_flags", [1], (SEEN,))]


async def test_account_level_errors_fail_all_its_refs(repo, accounts):
    pool = StubPool({A: AccountUnavailable("account needs reconnect: bad login"), B: fake()})
    res = await MailService(repo, pool).set_flags(
        refs(A, "inbox", 1, 2)
        + refs(A, "Work", 10)
        + refs(B, "inbox", 1)
        + refs("nobody@example.com", "inbox", 1),
        read=True,
    )
    assert res.updated == 1
    assert [(g.account, g.folder, g.uids, g.message) for g in res.failed] == [
        (A, "inbox", [1, 2], "account needs reconnect: bad login"),
        (A, "Work", [10], "account needs reconnect: bad login"),
        ("nobody@example.com", "inbox", [1], "unknown account: nobody@example.com"),
    ]
    assert res.to_dict()["failed"][0] == {
        "account": A,
        "folder": "inbox",
        "uids": [1, 2],
        "error": "account needs reconnect: bad login",
    }


async def test_server_refusal_fails_one_folder_and_carries_on(repo, accounts):
    class Refuses(OrgFake):
        def add_flags(self, uids, flags, silent=False):
            if self.selected == "INBOX":
                raise IMAPClientError("STORE failed: NO [READ-ONLY] mailbox is read-only")
            super().add_flags(uids, flags, silent)

    f = Refuses(standard_boxes(), special=standard_special())
    res = await MailService(repo, StubPool({A: f})).set_flags(
        refs(A, "inbox", 1) + refs(A, "Work", 10), read=True
    )
    assert res.updated == 1 and SEEN in f.boxes["Work"][10]
    assert res.failed[0].folder == "INBOX" and "READ-ONLY" in res.failed[0].message


async def test_timeout_fails_the_pending_refs_as_maybe_applied(repo, accounts):
    class Slow(OrgFake):
        def list_folders(self):
            time.sleep(0.5)
            return super().list_folders()

    svc = MailService(repo, StubPool({A: Slow(standard_boxes()), B: fake()}), account_timeout=0.1)
    res = await svc.set_flags(refs(A, "inbox", 1) + refs(B, "inbox", 1), read=True)
    assert res.updated == 1
    assert [(g.account, g.message) for g in res.failed] == [(A, PARTIAL_TIMEOUT)]
    assert "partially applied" in PARTIAL_TIMEOUT and "search_emails" in PARTIAL_TIMEOUT


async def test_batch_limits(repo, accounts):
    svc = MailService(repo, StubPool({A: fake()}))
    too_many = [MessageRef(A, "inbox", u) for u in range(1, MAX_BATCH_REFS + 2)]
    with pytest.raises(ValueError, match="at most 500 emails .* split"):
        await svc.set_flags(too_many, read=True)
    with pytest.raises(ValueError, match="no emails"):
        await svc.move([], "archive")
    with pytest.raises(ValueError, match="read, flagged or both"):
        await svc.set_flags(refs(A, "inbox", 1))
    with pytest.raises(ValueError, match="invalid uid"):
        await svc.set_flags(refs(A, "inbox", 0), read=True)
    res = await svc.set_flags(too_many[:MAX_BATCH_REFS], read=True)
    assert res.updated == 3  # the others do not exist
    assert len(res.failed) == 1 and len(res.failed[0].uids) == MAX_BATCH_REFS - 3


# -- move / trash ----------------------------------------------------------------------------


async def test_move_uses_uid_move(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).move(
        refs(A, "inbox", 1, 3) + refs(A, "Work", 10), "archive"
    )
    assert res.updated == 3 and res.destinations == {A: "Archive"}
    assert f.ops("move") == [("move", [1, 3], "Archive"), ("move", [10], "Archive")]
    assert f.ops("copy", "uid_expunge", "add_flags") == []
    assert set(f.boxes["INBOX"]) == {2} and len(f.boxes["Archive"]) == 3
    assert res.to_dict()["moved_to"] == {A: "Archive"}


async def test_move_without_move_uses_copy_and_uid_expunge_of_exactly_those(repo, accounts):
    f = fake(caps=("UIDPLUS",))
    f.boxes["INBOX"][7] = {DELETED}  # marked deleted by someone else: must survive
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1, 3, 99), "Work")
    assert res.updated == 2
    assert [(g.uids, g.message) for g in res.failed] == [([99], MESSAGE_NOT_FOUND)]
    assert f.ops("copy", "add_flags", "uid_expunge") == [
        ("copy", [1, 3], "Work"),
        ("add_flags", [1, 3], (DELETED,)),
        ("uid_expunge", [1, 3]),
    ]
    assert set(f.boxes["INBOX"]) == {2, 7} and len(f.boxes["Work"]) == 4


async def test_move_refused_without_move_or_uidplus(repo, accounts):
    f = fake(caps=())
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1), "Work")
    assert res.updated == 0 and res.failed[0].message == MOVE_UNSUPPORTED
    assert f.ops("move", "copy", "add_flags", "uid_expunge") == []
    assert set(f.boxes["INBOX"]) == {1, 2, 3}


async def test_failed_expunge_after_copy_says_so(repo, accounts):
    class NoExpunge(OrgFake):
        def uid_expunge(self, uids):
            raise IMAPClientError("EXPUNGE failed: NO")

    f = NoExpunge(standard_boxes(), caps=("UIDPLUS",), special=standard_special())
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1), "Work")
    assert res.updated == 0
    assert res.failed[0].message.startswith("copied to 'Work', but the originals could not")


async def test_move_to_the_same_folder_is_a_no_op(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).move(
        refs(A, "Work", 10, 99) + refs(A, "inbox", 1), "work"
    )
    assert res.updated == 1
    assert [(g.folder, g.uids, g.message) for g in res.skipped] == [
        ("Work", [10], "already in Work")
    ]
    assert [(g.folder, g.uids) for g in res.failed] == [("Work", [99])]
    assert ("select", "Work", True) in f.calls and ("select", "Work", False) not in f.calls
    assert f.ops("move") == [("move", [1], "Work")]


async def test_move_to_unknown_folder_fails_the_account(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1), "Nowhere")
    assert res.updated == 0 and res.failed[0].message == "folder not found: 'Nowhere'"
    assert f.ops("select", "move") == []


async def test_move_prefers_special_use_destination(repo, accounts):
    f = OrgFake(
        {"INBOX": {1: set()}, "Trash": {}, "Koš": {}},
        special={"Koš": (b"\\Trash",)},
    )
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1), "trash")
    assert res.destinations == {A: "Koš"}


def gmail_fake(with_archive=False):
    special = {"[Gmail]/All Mail": (b"\\All",), "[Gmail]/Trash": (b"\\Trash",)}
    boxes = {"INBOX": {1: set(), 2: set()}, "[Gmail]/All Mail": {}, "[Gmail]/Trash": {}}
    boxes["Archive"] = {}  # a user label that merely looks like an archive
    if with_archive:
        boxes["[Gmail]/Archive"] = {}
        special["[Gmail]/Archive"] = (b"\\Archive",)
    return OrgFake(boxes, special=special, noselect=["[Gmail]"])


async def test_gmail_archive_moves_to_all_mail(repo, accounts):
    f = gmail_fake()
    res = await MailService(repo, StubPool({G: f})).move(refs(G, "inbox", 1), "Archive")
    assert res.destinations == {G: "[Gmail]/All Mail"}
    assert f.ops("move") == [("move", [1], "[Gmail]/All Mail")]


async def test_gmail_archive_uses_a_real_archive_folder_when_there_is_one(repo, accounts):
    f = gmail_fake(with_archive=True)
    res = await MailService(repo, StubPool({G: f})).move(refs(G, "inbox", 1), "archive")
    assert res.destinations == {G: "[Gmail]/Archive"}


async def test_non_gmail_archive_is_the_archive_folder(repo, accounts):
    f = OrgFake({"INBOX": {1: set()}, "Archiv": {}, "All": {}})
    res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1), "archive")
    assert res.destinations == {A: "Archiv"}


async def test_trash_skips_what_is_already_in_trash(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).trash(
        refs(A, "trash", 50) + refs(A, "inbox", 1)
    )
    assert res.updated == 1 and res.destinations == {A: "Trash"}
    assert [(g.folder, g.uids, g.message) for g in res.skipped] == [
        ("Trash", [50], "already in trash")
    ]
    assert f.ops("move") == [("move", [1], "Trash")]
    assert ("select", "Trash", False) not in f.calls
    assert 50 in f.boxes["Trash"]  # trash never deletes permanently


async def test_gmail_trash(repo, accounts):
    f = gmail_fake()
    res = await MailService(repo, StubPool({G: f})).trash(refs(G, "INBOX", 1, 2))
    assert res.updated == 2 and f.ops("move") == [("move", [1, 2], "[Gmail]/Trash")]


async def test_reads_after_a_write_reopen_the_folder_read_only(repo, accounts):
    """The pool reuses a connection a write left with a folder selected read-write: every
    read selects its folder again, read-only."""
    from postroom.mail.models import SearchCriteria
    from tests.unit.test_mail_service import Fake

    class Both(Fake, OrgFake):
        def __init__(self):
            Fake.__init__(self, {})
            OrgFake.__init__(self, {"INBOX": {1: set()}, "Drafts": {}, "Sent": {}})

        def list_folders(self):
            return OrgFake.list_folders(self)

        def select_folder(self, name, readonly=False):
            OrgFake.select_folder(self, name, readonly)

        def fetch(self, uids, fields):
            return OrgFake.fetch(self, uids, fields) if fields == ["FLAGS"] else {}

    f = Both()
    svc = MailService(repo, StubPool({A: f}))
    await svc.set_flags(refs(A, "inbox", 1), read=True)
    await svc.search([A], "inbox", SearchCriteria())
    assert f.ops("select") == [("select", "INBOX", False), ("select", "INBOX", True)]


# -- create folder ---------------------------------------------------------------------------


async def test_create_folder_top_level_and_subscribed(repo, accounts):
    f = fake()
    name = await MailService(repo, StubPool({A: f})).create_folder(A, "  Projekty 2026 ")
    assert name == "Projekty 2026"
    assert f.ops("create_folder", "subscribe_folder") == [
        ("create_folder", "Projekty 2026"),
        ("subscribe_folder", "Projekty 2026"),
    ]


async def test_create_folder_under_a_parent_uses_the_delimiter(repo, accounts):
    f = fake(delim=b".")
    name = await MailService(repo, StubPool({A: f})).create_folder(A, "Clients", parent="work")
    assert name == "Work.Clients" and "Work.Clients" in f.boxes
    name = await MailService(repo, StubPool({A: f})).create_folder(A, "Old", parent="inbox")
    assert name == "INBOX.Old"


async def test_create_folder_under_a_noselect_parent(repo, accounts):
    f = gmail_fake()
    name = await MailService(repo, StubPool({G: f})).create_folder(G, "Receipts", parent="[Gmail]")
    assert name == "[Gmail]/Receipts"


async def test_create_folder_errors(repo, accounts):
    f = fake()
    svc = MailService(repo, StubPool({A: f}))
    with pytest.raises(ValueError, match="already exists"):
        await svc.create_folder(A, "work")
    with pytest.raises(ValueError, match="already exists"):
        await svc.create_folder(A, "INBOX")
    for bad in ("", "   ", "x" * 201, "a\r\nb", "a\x00b"):
        with pytest.raises(ValueError):
            await svc.create_folder(A, bad)
    with pytest.raises(Exception, match="folder not found"):
        await svc.create_folder(A, "x", parent="Nope")
    assert f.ops("create_folder") == []
    await svc.create_folder(A, "x" * 200)


async def test_create_folder_server_refusal_is_a_clean_error(repo, accounts):
    class Refuses(OrgFake):
        def create_folder(self, name):
            raise IMAPClientError("create failed: NO [CANNOT] invalid name")

    svc = MailService(repo, StubPool({A: Refuses(standard_boxes())}))
    with pytest.raises(Exception, match="the server refused to create the folder"):
        await svc.create_folder(A, "Bad")


# -- fix round 1 -------------------------------------------------------------------------------


async def test_nothing_is_written_after_the_caller_timed_out(repo, accounts):
    """A folder whose change has begun is finished; no further folder is started."""
    import asyncio

    class SlowMove(OrgFake):
        def move(self, uids, folder):
            time.sleep(0.3)
            super().move(uids, folder)

    f = SlowMove(standard_boxes(), special=standard_special())
    svc = MailService(repo, StubPool({A: f}), account_timeout=0.1)
    res = await svc.move(refs(A, "inbox", 1) + refs(A, "Work", 10), "archive")
    assert res.updated == 0 and {g.folder for g in res.failed} == {"inbox", "Work"}
    assert all(g.message == PARTIAL_TIMEOUT for g in res.failed)
    assert res.destinations == {}  # nothing reported as moved
    await asyncio.sleep(0.6)  # let the abandoned thread run out
    # The folder under way when the caller gave up is finished (under heavy load the
    # timeout may even fire before it starts); the next folder is never started.
    assert f.ops("move") in ([], [("move", [1], "Archive")])
    assert set(f.boxes["Work"]) == {10, 11}


async def test_a_batch_queued_past_the_timeout_does_nothing(repo, accounts):
    """The thread waited for the account's connection (held by a long read) until after
    the caller gave up: it must not start the change then."""
    import asyncio

    f = fake()

    class BusyPool(StubPool):
        @contextlib.contextmanager
        def session(self, email, manual=False):
            time.sleep(0.3)  # entry.lock held by another operation
            with super().session(email, manual) as c:
                yield c

    svc = MailService(repo, BusyPool({A: f}), account_timeout=0.1)
    res = await svc.set_flags(refs(A, "inbox", 1), read=True)
    assert res.failed[0].message == PARTIAL_TIMEOUT
    await asyncio.sleep(0.5)
    assert f.calls == [] and f.boxes["INBOX"][1] == set()


def gmail_archive_fake(caps=("MOVE", "UIDPLUS", "X-GM-EXT-1")):
    """Gmail: message 101 is in the Inbox and labelled Clients, 102 only in All Mail."""
    f = OrgFake(
        {
            "INBOX": {1: set()},
            "Clients": {5: set()},
            "[Gmail]/All Mail": {20: set(), 21: set()},
            "[Gmail]/Trash": {},
        },
        caps=caps,
        special={"[Gmail]/All Mail": (b"\\All",), "[Gmail]/Trash": (b"\\Trash",)},
        noselect=["[Gmail]"],
    )
    f.msgids = {
        ("INBOX", 1): 101,
        ("Clients", 5): 101,
        ("[Gmail]/All Mail", 20): 101,
        ("[Gmail]/All Mail", 21): 102,
    }
    return f


async def test_gmail_archive_of_all_mail_refs_removes_them_from_the_inbox(repo, accounts):
    # A get_thread result: every message is referenced from All Mail.
    f = gmail_archive_fake()
    res = await MailService(repo, StubPool({G: f})).move(
        refs(G, "[Gmail]/All Mail", 20, 21, 99), "archive"
    )
    assert res.updated == 1 and res.destinations == {G: "[Gmail]/All Mail"}
    assert [(g.folder, g.uids, g.message) for g in res.skipped] == [
        ("[Gmail]/All Mail", [21], "not in the Inbox")
    ]
    assert [(g.uids, g.message) for g in res.failed] == [([99], MESSAGE_NOT_FOUND)]
    assert f.ops("move") == [("move", [1], "[Gmail]/All Mail")]
    assert f.boxes["INBOX"] == {}
    # The ref's own folder is only read.
    assert ("select", "[Gmail]/All Mail", False) not in f.calls


async def test_gmail_archive_of_a_label_ref_keeps_the_label(repo, accounts):
    f = gmail_archive_fake()
    res = await MailService(repo, StubPool({G: f})).move(refs(G, "Clients", 5), "archive")
    assert res.updated == 1
    assert f.ops("move") == [("move", [1], "[Gmail]/All Mail")]  # from INBOX, not Clients
    assert 5 in f.boxes["Clients"] and f.boxes["INBOX"] == {}


async def test_gmail_archive_of_inbox_refs_moves_them(repo, accounts):
    f = gmail_archive_fake()
    res = await MailService(repo, StubPool({G: f})).move(refs(G, "inbox", 1), "archive")
    assert res.updated == 1 and f.ops("move") == [("move", [1], "[Gmail]/All Mail")]
    assert f.ops("search") == []


async def test_gmail_archive_without_message_ids_skips_non_inbox_refs(repo, accounts):
    f = gmail_archive_fake(caps=("MOVE", "UIDPLUS"))
    res = await MailService(repo, StubPool({G: f})).move(
        refs(G, "[Gmail]/All Mail", 20) + refs(G, "INBOX", 1), "archive"
    )
    assert res.updated == 1
    assert [(g.folder, g.uids, g.message) for g in res.skipped] == [
        (
            "[Gmail]/All Mail",
            [20],
            "on Gmail, archive works on Inbox emails; search folder=inbox and pass those uids",
        )
    ]


async def test_read_only_folder_fails_only_that_folder(repo, accounts):
    from imapclient.exceptions import IMAPClientReadOnlyError

    from postroom.mail.service import FOLDER_READ_ONLY

    class SharedReadOnly(OrgFake):
        def select_folder(self, name, readonly=False):
            super().select_folder(name, readonly)
            if name == "INBOX" and not readonly:  # SELECT answered [READ-ONLY]
                raise IMAPClientReadOnlyError("INBOX is not writable")

    f = SharedReadOnly(standard_boxes(), special=standard_special())
    res = await MailService(repo, StubPool({A: f})).set_flags(
        refs(A, "inbox", 1) + refs(A, "Work", 10), read=True
    )
    assert res.updated == 1 and SEEN in f.boxes["Work"][10]
    assert [(g.folder, g.message) for g in res.failed] == [("INBOX", FOLDER_READ_ONLY)]


class _Connector:
    """ImapConnector stand-in handing out the given fake clients."""

    def __init__(self, clients):
        self.clients = clients
        self.connects = []

    def connect(self, account, secret):
        self.connects.append(account.email)
        c = self.clients[account.email]
        if isinstance(c, Exception):
            raise c
        return c


class PooledFake(OrgFake):
    def noop(self):
        pass

    def logout(self):
        self.calls.append(("logout",))


async def test_lost_connection_mid_change_through_the_real_pool(repo, accounts):
    from imapclient.exceptions import IMAPClientAbortError

    from postroom.mail.imap import ImapPool

    class DropsOnMove(PooledFake):
        def move(self, uids, folder):
            raise IMAPClientAbortError("socket error: EOF")

    fa = DropsOnMove(standard_boxes(), special=standard_special())
    fb = PooledFake(standard_boxes(), special=standard_special())
    connector = _Connector({A: fa, B: fb})
    pool = ImapPool(repo, connector)
    res = await MailService(repo, pool).move(
        refs(A, "inbox", 1) + refs(A, "Work", 10) + refs(B, "inbox", 1), "archive"
    )
    assert res.updated == 1 and res.destinations == {B: "Archive"}
    failed = {g.folder: g.message for g in res.failed if g.account == A}
    assert set(failed) == {"inbox", "Work"}  # pending folders keep the given spelling
    for message in failed.values():
        assert "EOF" in message and "may have been partially applied" in message
    assert ("logout",) in fa.calls  # the broken connection was dropped
    assert pool._entries[A].client is None and pool._entries[B].client is fb


async def test_failed_connect_is_not_reported_as_maybe_applied(repo, accounts):
    from postroom.mail.imap import ImapPool

    pool = ImapPool(repo, _Connector({A: OSError("connection refused")}))
    res = await MailService(repo, pool).trash(refs(A, "inbox", 1))
    assert "connection refused" in res.failed[0].message
    assert "partially applied" not in res.failed[0].message


async def test_a_message_marked_deleted_elsewhere_arrives_undeleted(repo, accounts):
    for caps in (("MOVE",), ("UIDPLUS",)):
        f = fake(caps=caps)
        f.boxes["INBOX"][2] = {SEEN, DELETED}
        res = await MailService(repo, StubPool({A: f})).move(refs(A, "inbox", 1, 2), "Work")
        assert res.updated == 2
        assert f.ops("remove_flags") == [("remove_flags", [2], (DELETED,))]
        new = sorted(set(f.boxes["Work"]) - {10, 11})
        assert [f.boxes["Work"][u] for u in new] == [set(), {SEEN}], caps
        assert set(f.boxes["INBOX"]) == {3}


async def test_create_folder_rejects_the_hierarchy_delimiter(repo, accounts):
    for delim, name in ((b".", "v1.2 notes"), (b"/", "Clients/"), (b"/", "a/b")):
        f = fake(delim=delim)
        with pytest.raises(ValueError, match="use parent"):
            await MailService(repo, StubPool({A: f})).create_folder(A, name)
        with pytest.raises(ValueError, match="use parent"):
            await MailService(repo, StubPool({A: f})).create_folder(A, name, parent="Work")
        assert f.ops("create_folder") == []


def test_an_account_built_without_a_level_may_only_read():
    from postroom.accounts import Account

    acc = Account(
        id=0,
        email=A,
        display_name=None,
        provider=Provider.IMAP,
        imap_host="imap.example.com",
        imap_port=993,
        imap_security="ssl",
        imap_username=None,
        caldav_url=None,
        carddav_url=None,
        has_secret=True,
        enabled=True,
        status=AccountStatus.PENDING,
        last_error=None,
        last_ok_at=None,
        last_check_at=None,
    )
    assert acc.mail_access == MailAccess.READ and acc.capabilities == ["mail"]
    assert acc.can_send is False


async def test_moved_to_only_where_something_moved(repo, accounts):
    f = fake()
    res = await MailService(repo, StubPool({A: f})).trash(refs(A, "trash", 50))
    assert res.updated == 0 and "moved_to" not in res.to_dict()
