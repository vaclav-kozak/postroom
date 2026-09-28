import httpx
import pytest
import respx

from postroom.dav.carddav import CardDavBackend
from postroom.pim.models import PimError

BASE = "https://dav.example.com/SOGo/dav/me/"


def _ms(*responses: str) -> str:
    return (
        f'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">{"".join(responses)}</D:multistatus>'
    )


def _resp(href: str, props: str) -> str:
    return (
        f"<D:response><D:href>{href}</D:href><D:propstat><D:prop>{props}</D:prop>"
        "<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
    )


HOME = _resp(
    "/SOGo/dav/me/",
    '<C:addressbook-home-set xmlns:C="urn:ietf:params:xml:ns:carddav">'
    "<D:href>/SOGo/dav/me/Contacts/</D:href></C:addressbook-home-set>",
)
BOOKS = "".join(
    [
        _resp("/SOGo/dav/me/Contacts/", "<D:resourcetype><D:collection/></D:resourcetype>"),
        _resp(
            "/SOGo/dav/me/Contacts/personal/",
            '<D:resourcetype><D:collection/><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>'
            "</D:resourcetype>",
        ),
        _resp(
            "https://evil.example/book/",
            '<D:resourcetype><D:collection/><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>'
            "</D:resourcetype>",
        ),
    ]
)
CARDS = "".join(
    _resp(
        f"/SOGo/dav/me/Contacts/personal/{uid}.vcf",
        '<C:address-data xmlns:C="urn:ietf:params:xml:ns:carddav">'
        f"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:{fn}\r\nEMAIL:{email}\r\nEND:VCARD\r\n"
        "</C:address-data>",
    )
    for uid, fn, email in [("a", "Jan Novák", "jan@example.com"), ("b", "Eva", "eva@x.cz")]
)


def _propfind(request):
    if request.url.path.endswith("/Contacts/"):
        return httpx.Response(207, text=_ms(BOOKS))
    return httpx.Response(207, text=_ms(HOME))


PERSONAL_LISTING = "".join(
    [
        _resp(
            "/SOGo/dav/me/Contacts/personal/", "<D:resourcetype><D:collection/></D:resourcetype>"
        ),
        _resp("/SOGo/dav/me/Contacts/personal/a.vcf", "<D:resourcetype/>"),
        _resp("/SOGo/dav/me/Contacts/personal/b.vcf", "<D:resourcetype/>"),
    ]
)


def _personal_propfind(request):
    if request.url.path.endswith("/Contacts/personal/"):
        return httpx.Response(207, text=_ms(PERSONAL_LISTING))
    return _propfind(request)


@respx.mock
def test_filter_fallback_refilters_locally_and_ignores_foreign_hrefs():
    """A rejected query falls back to the bounded PROPFIND + multiget listing, never to
    an unfiltered addressbook-query (which returns the whole book in one response)."""
    respx.route(method="PROPFIND", host="dav.example.com").mock(side_effect=_personal_propfind)
    report = respx.route(method="REPORT", url=f"{BASE}Contacts/personal/")
    report.side_effect = [httpx.Response(400), httpx.Response(207, text=_ms(CARDS))]
    evil = respx.route(host="evil.example")
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    res = cd.search_contacts("NOVÁK")
    assert [(c.name, c.emails) for c in res] == [("Jan Novák", ["jan@example.com"])]
    assert report.call_count == 2
    bodies = [c.request.content.decode() for c in report.calls]
    assert all("<C:filter/>" not in b for b in bodies)
    assert "addressbook-multiget" in bodies[1]
    assert not evil.called


@respx.mock
def test_query_is_xml_escaped():
    respx.route(method="PROPFIND", host="dav.example.com").mock(side_effect=_propfind)
    report = respx.route(method="REPORT", url=f"{BASE}Contacts/personal/").respond(207, text=_ms())
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    assert cd.search_contacts("<a&b>") == []
    assert "&lt;a&amp;b&gt;" in report.calls[0].request.content.decode()


@respx.mock
def test_401_trips_breaker_once_and_stops_contacting_the_server():
    route = respx.route(method="PROPFIND", host="dav.example.com").respond(401)
    hits = []
    cd = CardDavBackend(
        "me@example.com",
        BASE,
        "me",
        "pw",
        http=httpx.Client(),
        on_auth_failure=lambda: hits.append(1),
    )
    for _ in range(2):
        with pytest.raises(PimError, match="CardDAV login failed"):
            cd.search_contacts("x")
    assert hits == [1] and route.call_count == 1


@respx.mock
def test_other_http_errors():
    respx.route(method="PROPFIND", host="dav.example.com").respond(500)
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    with pytest.raises(PimError, match="CardDAV error 500"):
        cd.search_contacts("x")


GAL = f"{BASE}Contacts/example.com/"
GAL_LISTING = "".join(
    [
        _resp(
            "/SOGo/dav/me/Contacts/example.com/",
            '<D:resourcetype><D:collection/><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>'
            "</D:resourcetype>",
        ),
        _resp("/SOGo/dav/me/Contacts/example.com/jan@example.com", "<D:resourcetype/>"),
        _resp("/SOGo/dav/me/Contacts/example.com/a&amp;b", "<D:resourcetype/>"),
        _resp("https://evil.example/card.vcf", "<D:resourcetype/>"),
    ]
)
GAL_BOOKS = _resp(
    "/SOGo/dav/me/Contacts/example.com/",
    '<D:resourcetype><D:collection/><C:addressbook xmlns:C="urn:ietf:params:xml:ns:carddav"/>'
    "</D:resourcetype>",
)


def _gal_propfind(request):
    if request.url.path.endswith("/Contacts/example.com/"):
        return httpx.Response(207, text=_ms(GAL_LISTING))
    if request.url.path.endswith("/Contacts/"):
        return httpx.Response(207, text=_ms(GAL_BOOKS))
    return httpx.Response(207, text=_ms(HOME))


def _gal_report(request):
    body = request.content.decode()
    if "addressbook-multiget" in body:
        return httpx.Response(207, text=_ms(CARDS))
    return httpx.Response(501)


@respx.mock
def test_book_that_rejects_queries_is_listed_and_fetched_with_multiget():
    """SOGo's global address list answers every addressbook-query with 501."""
    respx.route(method="PROPFIND", host="dav.example.com").mock(side_effect=_gal_propfind)
    report = respx.route(method="REPORT", url=GAL).mock(side_effect=_gal_report)
    evil = respx.route(host="evil.example")
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    res = cd.search_contacts("novák")
    assert [(c.name, c.emails) for c in res] == [("Jan Novák", ["jan@example.com"])]
    multiget = report.calls[-1].request.content.decode()
    assert "addressbook-multiget" in multiget
    assert "<D:href>/SOGo/dav/me/Contacts/example.com/jan@example.com</D:href>" in multiget
    assert "<D:href>/SOGo/dav/me/Contacts/example.com/a&amp;b</D:href>" in multiget
    assert "evil.example" not in multiget
    assert "<D:href>/SOGo/dav/me/Contacts/example.com/</D:href>" not in multiget
    assert not evil.called


@respx.mock
def test_empty_query_result_falls_back_to_listing():
    """SOGo's global address list answers an `anyof` query with an empty 207."""
    respx.route(method="PROPFIND", host="dav.example.com").mock(side_effect=_gal_propfind)

    def report(request):
        if "addressbook-multiget" in request.content.decode():
            return httpx.Response(207, text=_ms(CARDS))
        return httpx.Response(207, text=_ms())

    respx.route(method="REPORT", url=GAL).mock(side_effect=report)
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    assert [c.name for c in cd.search_contacts("eva")] == ["Eva"]


@respx.mock
def test_empty_book_needs_no_multiget():
    respx.route(method="PROPFIND", host="dav.example.com").mock(side_effect=_propfind)
    report = respx.route(method="REPORT", url=f"{BASE}Contacts/personal/").respond(207, text=_ms())
    cd = CardDavBackend("me@example.com", BASE, "me", "pw", http=httpx.Client())
    assert cd.search_contacts("x") == []
    assert all("addressbook-multiget" not in c.request.content.decode() for c in report.calls)
