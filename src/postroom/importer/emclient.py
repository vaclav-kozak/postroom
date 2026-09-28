import base64
import binascii
from dataclasses import dataclass
from xml.etree import ElementTree as ET

from postroom.accounts import AccountRepo, AccountStatus, Provider
from postroom.dav.urls import dav_url_ok

NS_PROTO = "{http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a}"
NS_ACC = "{http://licensing.emclient.com/XSD/accounts}"
DEFAULT_KEY = "DefaultAhojClient"

# End of Latin Extended-B: covers ASCII plus every European Latin-script diacritic
# (accented French/German/Czech/Polish/etc. letters). A password decoded with the
# wrong passphrase can still happen to be valid, printable UTF-8 (e.g. it lands on an
# Arabic or Cyrillic letter) even though str.isprintable() alone would not catch it, so
# this range check is a second, cheap signal that a decoded secret is implausible.
_MAX_SECRET_CODEPOINT = 0x24F


class EmClientImportError(Exception):
    pass


@dataclass
class ImportedAccount:
    email: str
    display_name: str | None
    provider: Provider
    imap_host: str | None
    imap_port: int | None
    imap_security: str | None
    imap_username: str | None
    password: str | None
    caldav_url: str | None
    carddav_url: str | None


def _xor(value: str, key: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as e:
        raise EmClientImportError("secret is not base64") from e
    k = key.encode("ascii")
    try:
        return bytes(c ^ k[i % len(k)] for i, c in enumerate(raw)).decode("utf-8")
    except UnicodeDecodeError as e:
        raise EmClientImportError("secrets did not decode — wrong passphrase?") from e


def decode_secret(value: str, mode: str, passphrase: str | None) -> str:
    if mode == "plain":
        return value
    if mode == "yes":
        return _xor(value, DEFAULT_KEY)
    if mode == "custom":
        if not passphrase:
            raise EmClientImportError("export is passphrase-protected; passphrase required")
        return _xor(value, passphrase)
    raise EmClientImportError(f"unsupported crypted mode: {mode!r}")


def _security(value: str | None) -> str:
    return "ssl" if (value or "").upper() == "SSL" else "starttls"


def parse_emclient_export(xml: bytes, passphrase: str | None) -> list[ImportedAccount]:
    try:
        root = ET.fromstring(xml.decode("utf-8-sig"))
    except (ET.ParseError, UnicodeDecodeError) as e:
        raise EmClientImportError("not a valid XML document") from e
    if root.tag != "settings" or root.find("accounts") is None:
        raise EmClientImportError("not an eM Client settings export")
    mode = (root.findtext("crypted") or "plain").strip()
    result: list[ImportedAccount] = []
    for node in root.find("accounts"):
        acc = node.find("Account")
        if acc is None:
            continue
        login = (acc.findtext("LoginName") or node.findtext("AccountName") or "").strip()
        email = (acc.findtext("Addresses/Address") or login).strip().lower()
        protos = {}
        for p in acc.findall(f"{NS_PROTO}Protocol"):
            protos.setdefault((p.findtext(f"{NS_PROTO}Type") or "").strip(), p)
        imap = protos.get("IMAP")
        is_google = (acc.findtext("ProviderName") or "") == "Gmail" or (
            imap is not None
            and (imap.findtext(f"{NS_PROTO}Server") or "").lower() == "imap.gmail.com"
        )
        password = None
        pw_node = acc.findtext("Password")
        if imap is not None and imap.findtext(f"{NS_ACC}Password"):
            pw_node = imap.findtext(f"{NS_ACC}Password")
        if pw_node and not is_google:
            password = decode_secret(pw_node.strip(), mode, passphrase)
            if not password.isprintable() or any(
                ord(ch) > _MAX_SECRET_CODEPOINT for ch in password
            ):
                raise EmClientImportError("secrets did not decode — wrong passphrase?")
        if imap is None and not is_google:
            continue  # accounts without IMAP (e.g. pure CalDAV) are out of scope
        cal = protos.get("CalDav")
        card = protos.get("CardDav")
        login_name = (imap.findtext(f"{NS_ACC}LoginName") if imap is not None else None) or login
        result.append(
            ImportedAccount(
                email=email,
                display_name=(acc.findtext("PersonName") or None),
                provider=Provider.GOOGLE if is_google else Provider.IMAP,
                imap_host="imap.gmail.com" if is_google else imap.findtext(f"{NS_PROTO}Server"),
                imap_port=993 if is_google else int(imap.findtext(f"{NS_PROTO}Port") or 993),
                imap_security="ssl"
                if is_google
                else _security(imap.findtext(f"{NS_PROTO}Encryption")),
                imap_username=login_name,
                password=password,
                caldav_url=None if is_google else _dav_url(cal),
                carddav_url=None if is_google else _dav_url(card),
            )
        )
    return result


def _dav_url(proto) -> str | None:
    """The protocol's server URL, dropped unless it is https (http only on loopback):
    DAV calls send the mailbox password as Basic auth."""
    if proto is None:
        return None
    url = proto.findtext(f"{NS_PROTO}Server")
    return url if url and dav_url_ok(url) else None


def apply_import(repo: AccountRepo, accounts: list[ImportedAccount]) -> list[tuple[str, str]]:
    actions = []
    for a in accounts:
        existing = repo.get(a.email)
        status = None
        if a.provider == Provider.GOOGLE:
            if existing is None or not existing.has_secret:
                status = AccountStatus.NEEDS_GOOGLE_CONNECT
        else:
            status = AccountStatus.PENDING
        repo.upsert(
            email=a.email,
            provider=a.provider,
            display_name=a.display_name,
            imap_host=a.imap_host,
            imap_port=a.imap_port,
            imap_security=a.imap_security,
            imap_username=a.imap_username,
            caldav_url=a.caldav_url,
            carddav_url=a.carddav_url,
            secret=a.password,
            status=status,
        )
        actions.append((a.email, "updated" if existing else "created"))
    return actions
