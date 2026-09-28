import base64

import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.importer.emclient import (
    EmClientImportError,
    apply_import,
    decode_secret,
    parse_emclient_export,
)

PASS = "fixture-pass"
A = "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
E = "http://licensing.emclient.com/XSD/accounts"


def enc(s: str, key: str = PASS) -> str:
    k = key.encode()
    b = s.encode()
    return base64.b64encode(bytes(c ^ k[i % len(k)] for i, c in enumerate(b))).decode()


def proto(type_, server="", port="", enc_="", extra=""):
    return (
        f'<Protocol xmlns="{A}" uid="x"><Type>{type_}</Type><Server>{server}</Server>'
        f"<Port>{port}</Port><Encryption>{enc_}</Encryption><DomainRequired>off</DomainRequired>"
        f'<CredentialsMode xmlns="{E}">UseBindingAccount</CredentialsMode>'
        f'<Enabled xmlns="{E}">true</Enabled>{extra}</Protocol>'
    )


def account(name, login, protos, password=None, provider=None, token=None, person="Test User"):
    pw = f"<Password>{password}</Password>" if password else ""
    pv = f"<ProviderName>{provider}</ProviderName>" if provider else ""
    tk = f"<CryptedOAuthRefreshToken>{token}</CryptedOAuthRefreshToken>" if token else ""
    return (
        f"<account><AccountName>{name}</AccountName><Account uid='u'>"
        f"<PersonName>{person}</PersonName>{pv}<LoginName>{login}</LoginName>{pw}"
        f"<Authentication>Stored</Authentication>{tk}"
        f"<Addresses><Address>{login}</Address></Addresses>{''.join(protos)}</Account></account>"
    )


def build(crypted="custom", accounts=()):
    return (
        f'﻿<?xml version="1.0" encoding="utf-8"?><settings><format-version>15</format-version>'
        f"<crypted>{crypted}</crypted><general-settings/><accounts>{''.join(accounts)}</accounts>"
        f"</settings>"
    ).encode()


XML = build(
    accounts=[
        account(
            "a@example.com",
            "a@example.com",
            [
                proto("SMTP", "mail.example.com", "465", "SSL"),
                proto("IMAP", "mail.example.com", "993", "SSL"),
                proto("CalDav", "https://mail.example.com/SOGo/dav/a@example.com/"),
                proto("CardDav", "https://mail.example.com/SOGo/dav/a@example.com/"),
            ],
            password=enc("pässword1"),
        ),
        account(
            "b@example.org",
            "b@example.org",
            [
                proto("IMAP", "imap.example.org", "143", "TLS"),
            ],
            password=enc("pw-b"),
        ),
        account(
            "me@gmail.com",
            "me@gmail.com",
            [
                proto("IMAP", "imap.gmail.com", "993", "SSL"),
                proto("GDATA"),
            ],
            provider="Gmail",
            token=enc("1//refresh"),
        ),
    ]
)


def test_decode_secret_modes():
    assert decode_secret(enc("abc"), "custom", PASS) == "abc"
    assert decode_secret(enc("abc", "DefaultAhojClient"), "yes", None) == "abc"
    assert decode_secret("abc", "plain", None) == "abc"
    with pytest.raises(EmClientImportError):
        decode_secret(enc("abc"), "custom", None)


def test_parse_accounts():
    accs = {a.email: a for a in parse_emclient_export(XML, PASS)}
    a = accs["a@example.com"]
    assert (a.provider, a.imap_host, a.imap_port, a.imap_security) == (
        Provider.IMAP,
        "mail.example.com",
        993,
        "ssl",
    )
    assert a.password == "pässword1" and a.imap_username == "a@example.com"
    assert a.caldav_url == a.carddav_url == "https://mail.example.com/SOGo/dav/a@example.com/"
    assert a.display_name == "Test User"
    b = accs["b@example.org"]
    assert (b.imap_port, b.imap_security, b.caldav_url) == (143, "starttls", None)
    g = accs["me@gmail.com"]
    assert g.provider == Provider.GOOGLE and g.password is None
    # SMTP comes along when the export has it (same login and password as IMAP).
    assert (a.smtp_host, a.smtp_port, a.smtp_security, a.smtp_username) == (
        "mail.example.com",
        465,
        "ssl",
        None,
    )
    assert b.smtp_host is None
    assert g.smtp_host is None


def _smtp_only(*protos, password="pw"):
    xml = build(accounts=[account("c@example.com", "c@example.com", list(protos), enc(password))])
    (c,) = parse_emclient_export(xml, PASS)
    return c


def test_smtp_import_variants():
    imap = proto("IMAP", "imap.example.com", "993", "SSL")
    login = f'<LoginName xmlns="{E}">c-sender</LoginName>'
    c = _smtp_only(imap, proto("SMTP", "SMTP.example.com", "", "TLS", extra=login))
    assert (c.smtp_host, c.smtp_port, c.smtp_security, c.smtp_username) == (
        "smtp.example.com",
        587,
        "starttls",
        "c-sender",
    )
    # Its own, different password: the stored IMAP password would not work; skipped.
    other = f'<Password xmlns="{E}">{enc("another")}</Password>'
    assert (
        _smtp_only(imap, proto("SMTP", "smtp.example.com", "465", "SSL", extra=other)).smtp_host
        is None
    )
    same = f'<Password xmlns="{E}">{enc("pw")}</Password>'
    assert _smtp_only(imap, proto("SMTP", "smtp.example.com", "465", "SSL", extra=same)).smtp_host
    # Unusable values are skipped rather than stored.
    assert _smtp_only(imap, proto("SMTP", "smtp example.com", "465", "SSL")).smtp_host is None
    assert _smtp_only(imap, proto("SMTP", "smtp.example.com", "99999", "SSL")).smtp_host is None


def test_apply_import_stores_smtp(repo):
    apply_import(repo, parse_emclient_export(XML, PASS))
    a = repo.get("a@example.com")
    assert (a.smtp_host, a.smtp_port, a.smtp_security) == ("mail.example.com", 465, "ssl")
    assert a.can_send and not repo.get("b@example.org").can_send


def test_wrong_passphrase_detected():
    with pytest.raises(EmClientImportError, match="passphrase"):
        parse_emclient_export(XML, "wrong-pass")


def test_rejects_non_emclient_xml():
    with pytest.raises(EmClientImportError):
        parse_emclient_export(b"<foo/>", PASS)


def test_apply_import_idempotent(repo):
    accs = parse_emclient_export(XML, PASS)
    first = dict(apply_import(repo, accs))
    assert first == {
        "a@example.com": "created",
        "b@example.org": "created",
        "me@gmail.com": "created",
    }
    second = dict(apply_import(repo, accs))
    assert set(second.values()) == {"updated"}
    assert len(repo.list()) == 3
    assert repo.get_secret("a@example.com") == "pässword1"
    assert repo.get("a@example.com").status == AccountStatus.PENDING
    assert repo.get("me@gmail.com").status == AccountStatus.NEEDS_GOOGLE_CONNECT
    assert repo.get_secret("me@gmail.com") is None


def test_apply_import_does_not_downgrade_connected_google(repo):
    repo.upsert(
        email="me@gmail.com",
        provider=Provider.GOOGLE,
        secret="real-refresh",
        status=AccountStatus.CONNECTED,
    )
    apply_import(repo, parse_emclient_export(XML, PASS))
    g = repo.get("me@gmail.com")
    assert g.status == AccountStatus.CONNECTED and repo.get_secret("me@gmail.com") == "real-refresh"
