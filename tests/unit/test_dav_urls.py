"""CalDAV/CardDAV send the mailbox password as Basic auth: https only (http on loopback)."""

import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.dav.caldav_backend import CalDavBackend
from postroom.dav.carddav import CardDavBackend
from postroom.dav.urls import dav_url_ok
from postroom.importer.emclient import parse_emclient_export
from postroom.pim.models import PimError
from postroom.pim.service import PimService
from tests.unit.test_emclient import PASS, account, build, enc, proto

INSECURE = [
    "http://mail.example.com/SOGo/dav/a@example.com/",
    "HTTP://mail.example.com/",
    "http://127.0.0.2/",
    "http://localhost.evil.cz/",
    "ftp://mail.example.com/",
    "mail.example.com/SOGo/dav/",
    "https:///no-host",
    "http://[::1",
    "",
]
SECURE = [
    "https://mail.example.com/SOGo/dav/a@example.com/",
    "HTTPS://mail.example.com/",
    "http://localhost:5232/alice/",
    "http://127.0.0.1:5232/alice/",
    "http://[::1]:5232/alice/",
]


@pytest.mark.parametrize("url", SECURE)
def test_secure_urls(url):
    assert dav_url_ok(url)


@pytest.mark.parametrize("url", INSECURE)
def test_insecure_urls(url):
    assert not dav_url_ok(url)


@pytest.mark.parametrize("cls", [CalDavBackend, CardDavBackend])
def test_backends_refuse_cleartext_urls(cls):
    with pytest.raises(PimError, match="must use https"):
        cls("a@example.com", "http://mail.example.com/SOGo/dav/a@example.com/", "a", "pw")


@pytest.mark.parametrize("capability", ["calendar", "contacts"])
async def test_service_refuses_cleartext_url_before_reading_the_password(repo, capability):
    repo.upsert(
        email="a@example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        caldav_url="http://mail.example.com/SOGo/dav/a@example.com/",
        carddav_url="http://mail.example.com/SOGo/dav/a@example.com/",
        secret="pw",
        status=AccountStatus.CONNECTED,
    )
    svc = PimService(repo, None)
    with pytest.raises(PimError, match="must use https"):
        svc.backend(repo.get("a@example.com"), capability)
    if capability == "contacts":
        _, errors = await svc.search_contacts("jan", "a@example.com", 5)
    else:
        _, errors = await svc.list_calendars("a@example.com")
    assert [e.error for e in errors] == [
        "CalDAV/CardDAV URL must use https (http only on localhost)"
    ]


def test_import_drops_cleartext_dav_urls():
    xml = build(
        accounts=[
            account(
                "a@example.com",
                "a@example.com",
                [
                    proto("IMAP", "mail.example.com", "993", "SSL"),
                    proto("CalDav", "http://mail.example.com/SOGo/dav/a@example.com/"),
                    proto("CardDav", "https://mail.example.com/SOGo/dav/a@example.com/"),
                ],
                password=enc("pw"),
            )
        ]
    )
    (a,) = parse_emclient_export(xml, PASS)
    assert a.caldav_url is None
    assert a.carddav_url == "https://mail.example.com/SOGo/dav/a@example.com/"
