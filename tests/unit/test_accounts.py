from postroom.accounts import AccountStatus, MailAccess, Provider


def test_upsert_and_get_case_insensitive(repo):
    a = repo.upsert(
        email="Foo@Example.cz",
        provider=Provider.IMAP,
        imap_host="imap.example.cz",
        imap_port=993,
        imap_security="ssl",
        secret="pw1",
    )
    assert a.email == "foo@example.cz"
    assert a.status == AccountStatus.PENDING and a.enabled and a.has_secret
    assert repo.get("FOO@example.CZ").id == a.id
    assert repo.get_secret("foo@example.cz") == "pw1"


def test_upsert_updates_without_duplicating(repo):
    repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="old",
    )
    b = repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h2",
        imap_port=143,
        imap_security="starttls",
        secret="new",
    )
    assert len(repo.list()) == 1
    assert b.imap_host == "h2" and b.imap_security == "starttls"
    assert repo.get_secret("a@x.cz") == "new"


def test_upsert_keeps_secret_when_none(repo):
    repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="keep",
    )
    repo.upsert(
        email="a@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        display_name="A",
    )
    assert repo.get_secret("a@x.cz") == "keep"


def test_secret_not_stored_in_plaintext(repo, db):
    repo.upsert(email="a@x.cz", provider=Provider.IMAP, secret="VERY-SECRET")
    raw = db.one("SELECT secret_enc FROM accounts")[0]
    assert b"VERY-SECRET" not in raw


def test_status_transitions(repo):
    repo.upsert(email="a@x.cz", provider=Provider.IMAP)
    repo.set_status("a@x.cz", AccountStatus.NEEDS_RECONNECT, "AUTHENTICATIONFAILED")
    a = repo.get("a@x.cz")
    assert a.status == AccountStatus.NEEDS_RECONNECT and a.last_error == "AUTHENTICATIONFAILED"
    assert a.last_check_at is not None and a.last_ok_at is None
    repo.set_status("a@x.cz", AccountStatus.CONNECTED)
    a = repo.get("a@x.cz")
    assert a.status == AccountStatus.CONNECTED and a.last_error is None and a.last_ok_at


def test_enable_disable_delete(repo):
    repo.upsert(email="a@x.cz", provider=Provider.IMAP)
    repo.set_enabled("a@x.cz", False)
    assert repo.get("a@x.cz").enabled is False
    assert repo.list(include_disabled=False) == []
    repo.delete("a@x.cz")
    assert repo.get("a@x.cz") is None


def test_capabilities(repo):
    g = repo.upsert(
        email="g@gmail.com",
        provider=Provider.GOOGLE,
        imap_host="imap.gmail.com",
        imap_port=993,
        imap_security="ssl",
    )
    # Sending is opt-in: a new account may read and organise, not send.
    assert g.mail_access == MailAccess.ORGANIZE and not g.can_send
    assert g.capabilities == ["mail", "mail.organize", "calendar", "tasks", "contacts"]
    g = repo.upsert(email="g@gmail.com", provider=Provider.GOOGLE, mail_access=MailAccess.FULL)
    assert g.is_gmail and g.capabilities == [
        "mail",
        "mail.organize",
        "mail.send",
        "calendar",
        "tasks",
        "contacts",
    ]
    s = repo.upsert(
        email="s@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        caldav_url="https://h/SOGo/dav/s@x.cz/",
        carddav_url="https://h/SOGo/dav/s@x.cz/",
        smtp_host="smtp.example.org",
        mail_access=MailAccess.FULL,
    )
    assert s.capabilities == [
        "mail",
        "mail.organize",
        "mail.send",
        "calendar",
        "tasks",
        "contacts",
    ]
    f = repo.upsert(
        email="f@y.cz",
        provider=Provider.IMAP,
        imap_host="imap.example.org",
        imap_port=143,
        imap_security="starttls",
        mail_access=MailAccess.FULL,
    )
    # No outgoing server: no sending, whatever the access level.
    assert f.capabilities == ["mail", "mail.organize"] and not f.is_gmail
    assert f.mail_access == "full" and not f.can_send


def test_mark_connected_is_conditional_on_the_expected_status(repo):
    repo.upsert(email="a@x.cz", provider=Provider.IMAP, status=AccountStatus.PENDING)
    assert repo.mark_connected("a@x.cz", expected=AccountStatus.ERROR) is False
    assert repo.get("a@x.cz").status == AccountStatus.PENDING
    assert repo.mark_connected("a@x.cz", expected=AccountStatus.PENDING) is True
    acc = repo.get("a@x.cz")
    assert acc.status == AccountStatus.CONNECTED and acc.last_ok_at is not None
