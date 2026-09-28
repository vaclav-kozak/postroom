"""CardDAV contact search (read-only) over plain httpx.

Discovery: current-user-principal -> addressbook-home-set -> address book collections.
Search: an `addressbook-query` REPORT with a text-match filter, re-filtered locally
because servers differ in how (and whether) they apply it. A book that rejects the query
or returns nothing (SOGo's global address list does both) is listed with PROPFIND and
its cards fetched with `addressbook-multiget`, at most `MAX_BOOK_CARDS` of them in
chunks of `MULTIGET_CHUNK` (never with an unfiltered query, which would return the whole
book in one response).

fail2ban safety: an HTTP 401 calls `on_auth_failure()` (which trips the account's
circuit breaker) and this instance refuses to contact the server again. Credentials
are only ever sent to the configured server's origin; hrefs pointing elsewhere are
ignored.
"""

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit
from xml.sax.saxutils import escape

import httpx
import vobject

from postroom.dav.urls import require_dav_url
from postroom.pim.models import ContactInfo, PimError

DAV = "DAV:"
CARD = "urn:ietf:params:xml:ns:carddav"

_CARD_RE = re.compile(
    r"^BEGIN:VCARD[ \t]*\r?$.*?^END:VCARD[ \t]*\r?$", re.MULTILINE | re.DOTALL | re.IGNORECASE
)
_XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_STATUS_2XX = re.compile(r"^\s*HTTP/\S+\s+2\d\d\b")

_SEARCHED_PROPS = ("FN", "EMAIL", "ORG", "NICKNAME")

MAX_BOOK_CARDS = 2000
MULTIGET_CHUNK = 100


def _text(value) -> str:
    if isinstance(value, list | tuple):
        return " ".join(_text(v) for v in value if _text(v))
    return str(value).strip() if value is not None else ""


def _first(comp, key: str) -> str:
    for line in comp.contents.get(key, []):
        s = _text(line.value)
        if s:
            return s
    return ""


def _all(comp, key: str) -> list[str]:
    return [s for s in (_text(line.value) for line in comp.contents.get(key, [])) if s]


def _name_from_n(comp) -> str:
    for line in comp.contents.get("n", []):
        n = line.value
        parts = [getattr(n, a, "") for a in ("prefix", "given", "additional", "family", "suffix")]
        name = " ".join(p for p in (_text(x) for x in parts) if p)
        if name:
            return name
    return ""


def _card_to_dict(comp) -> dict | None:
    if (comp.name or "").upper() != "VCARD":
        return None
    orgs = [
        ", ".join(p for p in (_text(x) for x in line.value) if p)
        if isinstance(line.value, list)
        else _text(line.value)
        for line in comp.contents.get("org", [])
    ]
    return {
        "name": _first(comp, "fn") or _name_from_n(comp),
        "emails": _all(comp, "email"),
        "phones": _all(comp, "tel"),
        "organization": next((o for o in orgs if o), None),
        "nickname": _first(comp, "nickname") or None,
    }


def parse_vcards(text: str) -> list[dict]:
    """Parse the vCards in `text`; cards that fail to parse are skipped, not fatal."""
    cards = []
    for block in _CARD_RE.findall(text or ""):
        try:
            for comp in vobject.readComponents(block):
                card = _card_to_dict(comp)
                if card is not None:
                    cards.append(card)
        except Exception:  # noqa: BLE001, S112 -- one malformed card must not hide the others
            continue
    return cards


def _matches(card: dict, needle: str) -> bool:
    if not needle:
        return True
    hay = [card["name"], *card["emails"], card["organization"] or "", card["nickname"] or ""]
    return any(needle in h.casefold() for h in hay)


def _query_body(query: str) -> str:
    q = escape(_XML_INVALID.sub("", query))
    prop_filters = "".join(
        f'<C:prop-filter name="{p}"><C:text-match collation="i;unicode-casemap" '
        f'match-type="contains">{q}</C:text-match></C:prop-filter>'
        for p in _SEARCHED_PROPS
    )
    filt = f'<C:filter test="anyof">{prop_filters}</C:filter>'
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<C:addressbook-query xmlns:D="{DAV}" xmlns:C="{CARD}">'
        "<D:prop><D:getetag/><C:address-data/></D:prop>"
        f"{filt}</C:addressbook-query>"
    )


def _multiget_body(hrefs: list[str]) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<C:addressbook-multiget xmlns:D="{DAV}" xmlns:C="{CARD}">'
        "<D:prop><D:getetag/><C:address-data/></D:prop>"
        + "".join(f"<D:href>{escape(h)}</D:href>" for h in hrefs)
        + "</C:addressbook-multiget>"
    )


def _cards_from(body: bytes) -> list[dict]:
    cards = []
    for _, props in _multistatus(body):
        for prop in props:
            data = prop.findtext(f"{{{CARD}}}address-data")
            if data:
                cards.extend(parse_vcards(data))
    return cards


def _propfind_body(props: list[tuple[str, str]]) -> str:
    inner = "".join(
        f'<x:{name} xmlns:x="{ns}"/>' if ns != DAV else f"<D:{name}/>" for ns, name in props
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<D:propfind xmlns:D="{DAV}"><D:prop>{inner}</D:prop></D:propfind>'
    )


def _multistatus(body: bytes) -> list[tuple[str, list[ET.Element]]]:
    """(href, [prop elements with a 2xx status]) for each `DAV:response`."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise PimError("CardDAV error: malformed XML response") from e
    out = []
    for resp in root.iter(f"{{{DAV}}}response"):
        href = (resp.findtext(f"{{{DAV}}}href") or "").strip()
        props = []
        for ps in resp.findall(f"{{{DAV}}}propstat"):
            status = ps.findtext(f"{{{DAV}}}status") or ""
            if _STATUS_2XX.search(status):
                props.extend(ps.findall(f"{{{DAV}}}prop"))
        out.append((href, props))
    return out


def _prop_href(props: list[ET.Element], tag: str) -> str | None:
    for prop in props:
        el = prop.find(tag)
        if el is not None:
            href = (el.findtext(f"{{{DAV}}}href") or "").strip()
            if href:
                return href
    return None


class CardDavBackend:
    def __init__(
        self,
        account: str,
        url: str,
        username: str,
        password: str,
        http: httpx.Client | None = None,
        on_auth_failure: Callable[[], None] = lambda: None,
    ):
        self.account = account
        self._url = require_dav_url(url)  # the password goes out as Basic auth
        self._auth = (username, password)
        self._owns_http = http is None
        self._http = http or httpx.Client(auth=(username, password), timeout=30)
        self._on_auth_failure = on_auth_failure
        self._origin = self._origin_of(url)
        self._books: list[str] | None = None
        self._auth_failed = False

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    @staticmethod
    def _origin_of(url: str) -> tuple[str, str]:
        parts = urlsplit(url)
        return parts.scheme.lower(), parts.netloc.lower()

    def _resolve(self, base: str, href: str) -> str | None:
        """Absolute URL for `href`, or None when it points off the configured server."""
        url = urljoin(base, href)
        return url if self._origin_of(url) == self._origin else None

    def _request(self, method: str, url: str, depth: str, body: str) -> httpx.Response:
        if self._auth_failed:
            raise PimError("CardDAV login failed")
        try:
            resp = self._http.request(
                method,
                url,
                content=body.encode("utf-8"),
                headers={"Depth": depth, "Content-Type": "application/xml; charset=utf-8"},
                auth=self._auth,
            )
        except httpx.HTTPError as e:
            raise PimError(f"CardDAV error: {type(e).__name__}") from e
        if resp.status_code == 401:
            self._auth_failed = True
            self._on_auth_failure()
            raise PimError("CardDAV login failed")
        return resp

    def _propfind(self, url: str, depth: str, props: list[tuple[str, str]]):
        resp = self._request("PROPFIND", url, depth, _propfind_body(props))
        if resp.status_code >= 400:
            raise PimError(f"CardDAV error {resp.status_code}")
        return _multistatus(resp.content)

    def _addressbooks(self) -> list[str]:
        if self._books is not None:
            return self._books
        home_tag, principal_tag = (
            f"{{{CARD}}}addressbook-home-set",
            f"{{{DAV}}}current-user-principal",
        )
        results = self._propfind(
            self._url, "0", [(DAV, "current-user-principal"), (CARD, "addressbook-home-set")]
        )
        props = [p for _, ps in results for p in ps]
        home_href = _prop_href(props, home_tag)
        home = self._resolve(self._url, home_href) if home_href else None
        principal_href = _prop_href(props, principal_tag)
        principal = self._resolve(self._url, principal_href) if principal_href else None
        if home is None and principal is not None:
            results = self._propfind(principal, "0", [(CARD, "addressbook-home-set")])
            home_href = _prop_href([p for _, ps in results for p in ps], home_tag)
            home = self._resolve(principal, home_href) if home_href else None
        home = home or self._url

        books = []
        for href, ps in self._propfind(home, "1", [(DAV, "resourcetype"), (DAV, "displayname")]):
            is_book = any(
                p.find(f"{{{DAV}}}resourcetype/{{{CARD}}}addressbook") is not None for p in ps
            )
            url = self._resolve(home, href) if href else None
            if is_book and url and url not in books:
                books.append(url)
        self._books = books
        return books

    def _cards_in(self, book: str, query: str) -> list[dict]:
        """Cards of `book` matching `query`, or (fallback) its first MAX_BOOK_CARDS cards.

        A book that rejects the filtered query or answers it with nothing is listed with
        PROPFIND and read in multiget chunks. There is deliberately no unfiltered
        addressbook-query: it would return the whole book, photos included, in one
        response that is read and parsed whole.
        """
        resp = self._request("REPORT", book, "1", _query_body(query))
        cards = _cards_from(resp.content) if resp.status_code == 207 else []
        return cards or self._all_cards(book)

    def _all_cards(self, book: str) -> list[dict]:
        """Every card in `book` (up to MAX_BOOK_CARDS), via PROPFIND + addressbook-multiget."""
        book_path = urlsplit(book).path
        hrefs = []
        for href, props in self._propfind(book, "1", [(DAV, "resourcetype")]):
            url = self._resolve(book, href) if href else None
            if url is None or not url.startswith(book) or urlsplit(url).path == book_path:
                continue
            if any(p.find(f"{{{DAV}}}resourcetype/{{{DAV}}}collection") is not None for p in props):
                continue
            hrefs.append(href)
            if len(hrefs) >= MAX_BOOK_CARDS:
                break
        cards = []
        for i in range(0, len(hrefs), MULTIGET_CHUNK):
            resp = self._request("REPORT", book, "1", _multiget_body(hrefs[i : i + MULTIGET_CHUNK]))
            if resp.status_code != 207:
                raise PimError(f"CardDAV error {resp.status_code}")
            cards.extend(_cards_from(resp.content))
        return cards

    def search_contacts(self, query: str, limit: int = 20) -> list[ContactInfo]:
        if limit <= 0:
            return []
        needle = (query or "").strip().casefold()
        out: list[ContactInfo] = []
        for book in self._addressbooks():
            for card in self._cards_in(book, (query or "").strip()):
                if not _matches(card, needle):
                    continue
                out.append(
                    ContactInfo(
                        account=self.account,
                        name=card["name"],
                        emails=card["emails"],
                        phones=card["phones"],
                        organization=card["organization"],
                    )
                )
                if len(out) >= limit:
                    return out
        return out
