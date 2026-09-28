# ruff: noqa: F811 -- the env/settings/reset_fake fixtures are imported from other test modules
"""Admin UI for sending: the SMTP section and its test login, the access level (also for
Google accounts), the dashboard row, and "Test now" checking SMTP (never the background
checker). smtplib is faked (tests.unit.test_smtp)."""

import smtplib

import pytest

from postroom.accounts import AccountStatus, MailAccess, Provider, SmtpStatus
from postroom.web.pages import consent_grants
from tests.unit.test_admin import _account_form, csrf, env, settings  # noqa: F401
from tests.unit.test_smtp import FakeSMTP, FakeSMTPSSL, reset_fake  # noqa: F401

G = "me@gmail.com"


class PasswordSMTP(FakeSMTPSSL):
    """Accepts only the password "good"."""

    def login(self, user, password):
        self.calls.append(("login", user, password))
        if password != "good":
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")


@pytest.fixture
def smtp(env):
    _, services, _ = env
    connector = services.mail.smtp.connector
    connector.smtp_class = FakeSMTP
    connector.smtp_ssl_class = PasswordSMTP
    return FakeSMTP.instances


def smtp_form(token, email, **extra):
    data = {
        "smtp_host": "smtp.example.com",
        "smtp_port": "465",
        "smtp_security": "ssl",
        "smtp_username": "",
        "mail_access": "full",
    }
    data.update(extra)
    return _account_form(token, email, **data)


async def add(c, email, **extra):
    page = await c.get("/admin/accounts/new")
    return await c.post("/admin/accounts", data=smtp_form(csrf(page.text), email, **extra))


# -- the form ------------------------------------------------------------------------------


async def test_form_has_smtp_and_access_sections(env):
    c, _, _ = env
    page = (await c.get("/admin/accounts/new")).text
    assert "Outgoing mail (SMTP)" in page
    assert "Leave the host empty to disable sending for this account" in page
    assert "same password as incoming mail" in page
    assert 'placeholder="same as IMAP username"' in page
    assert "SSL/TLS (port 465)" in page and "STARTTLS (port 587)" in page
    assert 'id="smtp-suggest"' in page and "hidden" in page  # filled in by app.js
    for value in ("read", "organize", "full"):
        assert f'name="mail_access" value="{value}"' in page
    assert "Search and read mail, and create drafts." in page
    assert "mark read or unread, star, move, archive, trash, and create folders" in page
    assert "Also send mail" in page
    assert 'value="full" checked' in page


async def test_add_account_with_smtp(env, smtp):
    c, services, _ = env
    r = await add(c, "s@example.com", smtp_username="sender", mail_access="organize")
    assert r.status_code == 303
    a = services.repo.get("s@example.com")
    assert (a.smtp_host, a.smtp_port, a.smtp_security, a.smtp_username) == (
        "smtp.example.com",
        465,
        "ssl",
        "sender",
    )
    assert a.smtp_status == SmtpStatus.OK and a.smtp_checked_at is not None
    assert a.mail_access == MailAccess.ORGANIZE and not a.can_send
    # One SMTP login with the account password, then QUIT; nothing sent.
    (s,) = smtp
    assert s.names() == ["ehlo", "login", "quit"]
    assert s.calls[1] == ("login", "sender", "good")


async def test_add_account_full_access_can_send(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com")
    a = services.repo.get("s@example.com")
    assert a.can_send and "mail.send" in a.capabilities


async def test_bad_smtp_login_saves_nothing(env, smtp, monkeypatch):
    c, services, _ = env
    monkeypatch.setattr(PasswordSMTP, "login", _always_fail)
    r = await add(c, "s@example.com")
    assert r.status_code == 200
    assert "SMTP test failed — SMTP: authentication failed (535 5.7.8 bad credentials)" in r.text
    assert "good" not in r.text.split("SMTP test failed")[1][:200]
    assert services.repo.get("s@example.com") is None


def _always_fail(self, user, password):
    raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")


async def test_no_smtp_host_means_no_smtp_login(env, smtp):
    c, services, _ = env
    r = await add(c, "s@example.com", smtp_host="", smtp_port="")
    assert r.status_code == 303 and smtp == []
    a = services.repo.get("s@example.com")
    assert a.smtp_host is None and a.smtp_port is None and not a.can_send


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("smtp_host", "smtp example.com", "Enter the SMTP server host name"),
        ("smtp_host", "user@smtp.example.com", "Enter the SMTP server host name"),
        ("smtp_port", "0", "SMTP port must be a number between 1 and 65535"),
        ("smtp_port", "70000", "SMTP port must be a number between 1 and 65535"),
        ("smtp_port", "25a", "SMTP port must be a number between 1 and 65535"),
        ("smtp_security", "tls", "SMTP security must be SSL/TLS or STARTTLS"),
        ("smtp_username", "a b", "must not contain spaces"),
        ("mail_access", "admin", "Choose an access level"),
    ],
)
async def test_smtp_and_access_validation(env, smtp, field, value, message):
    c, services, attempts = env
    r = await add(c, "s@example.com", **{field: value})
    assert r.status_code == 400 and message in r.text
    assert services.repo.get("s@example.com") is None
    assert attempts == [] and smtp == []


async def test_edit_clears_smtp_and_changes_access(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com")
    a = services.repo.get("s@example.com")
    page = await c.get(f"/admin/accounts/{a.id}/edit")
    assert 'value="smtp.example.com"' in page.text and 'value="full" checked' in page.text
    r = await c.post(
        f"/admin/accounts/{a.id}",
        data=smtp_form(csrf(page.text), a.email, password="", smtp_host="", mail_access="read"),
    )
    assert r.status_code == 303
    a = services.repo.get("s@example.com")
    assert a.smtp_host is None and a.smtp_status is None and a.mail_access == MailAccess.READ


async def test_edit_without_an_access_field_keeps_the_level(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com", mail_access="organize")
    a = services.repo.get("s@example.com")
    page = await c.get(f"/admin/accounts/{a.id}/edit")
    data = smtp_form(csrf(page.text), a.email, password="")
    del data["mail_access"]
    r = await c.post(f"/admin/accounts/{a.id}", data=data)
    assert r.status_code == 303
    assert services.repo.get("s@example.com").mail_access == MailAccess.ORGANIZE


async def test_starttls_default_port(env, smtp):
    c, services, _ = env
    FakeSMTP.extensions = {"starttls": "", "auth": "PLAIN"}

    class Plain(FakeSMTP):
        def login(self, user, password):
            self.calls.append(("login", user, password))

    services.mail.smtp.connector.smtp_class = Plain
    r = await add(c, "s@example.com", smtp_security="starttls", smtp_port="")
    assert r.status_code == 303
    a = services.repo.get("s@example.com")
    assert (a.smtp_port, a.smtp_security) == (587, "starttls")
    assert "starttls" in smtp[0].names()


# -- Google accounts ----------------------------------------------------------------------------


@pytest.fixture
def google_account(env):
    _, services, _ = env
    services.repo.upsert(
        email=G,
        provider=Provider.GOOGLE,
        imap_host="imap.gmail.com",
        imap_port=993,
        imap_security="ssl",
        secret="refresh",
        status=AccountStatus.CONNECTED,
    )
    return services.repo.get(G)


async def test_google_edit_page_has_name_and_access_only(env, google_account):
    c, _, _ = env
    r = await c.get(f"/admin/accounts/{google_account.id}/edit")
    assert r.status_code == 200
    assert 'name="display_name"' in r.text and 'name="mail_access"' in r.text
    assert "imap_host" not in r.text and "smtp_host" not in r.text
    assert 'name="password"' not in r.text
    assert "smtp.gmail.com" in r.text
    assert f"/admin/google/connect?account_id={google_account.id}" in r.text


async def test_google_edit_saves_access_and_name_without_logging_in(env, google_account, smtp):
    c, services, attempts = env
    page = await c.get(f"/admin/accounts/{google_account.id}/edit")
    r = await c.post(
        f"/admin/accounts/{google_account.id}",
        data={"csrf": csrf(page.text), "display_name": "Me", "mail_access": "organize"},
    )
    assert r.status_code == 303
    a = services.repo.get(G)
    assert a.display_name == "Me" and a.mail_access == MailAccess.ORGANIZE
    assert "mail.send" not in a.capabilities
    assert attempts == [] and smtp == []
    assert services.repo.get_secret(G) == "refresh"


async def test_google_edit_rejects_a_bad_level(env, google_account):
    c, services, _ = env
    page = await c.get(f"/admin/accounts/{google_account.id}/edit")
    r = await c.post(
        f"/admin/accounts/{google_account.id}",
        data={"csrf": csrf(page.text), "display_name": "", "mail_access": "root"},
    )
    assert r.status_code == 400 and "Choose an access level" in r.text
    assert services.repo.get(G).mail_access == MailAccess.FULL


# -- dashboard and Test now ------------------------------------------------------------------


async def test_dashboard_shows_access_and_sending(env, smtp, google_account):
    c, services, _ = env
    await add(c, "s@example.com")
    await add(c, "r@example.com", mail_access="read")
    await add(c, "n@example.com", smtp_host="")
    services.repo.set_mail_access(G, MailAccess.READ)
    page = (await c.get("/admin")).text
    assert page.count("Full access") == 2 and page.count("Read only") == 2
    assert page.count("Sends mail") == 1
    assert "No SMTP server" in page
    assert "SMTP OK" in page
    assert f'href="/admin/accounts/{google_account.id}/edit"' in page


async def test_test_now_checks_smtp_and_reports_it_separately(env, smtp, monkeypatch):
    c, services, _ = env
    await add(c, "s@example.com")
    a = services.repo.get("s@example.com")
    monkeypatch.setattr(PasswordSMTP, "login", _always_fail)
    page = await c.get("/admin")
    r = await c.post(f"/admin/accounts/{a.id}/test", data={"csrf": csrf(page.text)})
    assert r.headers["location"] == "/admin?msg=check_smtp_failed"
    a = services.repo.get("s@example.com")
    assert a.status == AccountStatus.CONNECTED  # IMAP is fine
    assert a.smtp_status == SmtpStatus.AUTH_FAILED
    page = (await c.get("/admin?msg=check_smtp_failed")).text
    assert "the SMTP test failed" in page
    assert "SMTP: authentication failed (535 5.7.8 bad credentials)" in page
    assert 'class="row-warn"' in page

    # Fixed on the server: the next Test now clears it.
    monkeypatch.undo()
    smtp_count = len(smtp)
    r = await c.post(f"/admin/accounts/{a.id}/test", data={"csrf": csrf(page)})
    assert r.headers["location"] == "/admin?msg=check_ok"
    assert len(smtp) == smtp_count + 1
    assert services.repo.get("s@example.com").smtp_status == SmtpStatus.OK


async def test_test_now_skips_smtp_when_imap_fails(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com")
    before = len(smtp)
    a = services.repo.get("s@example.com")
    services.repo.upsert(email=a.email, provider=Provider.IMAP, secret="bad")
    services.pool.drop(a.email)
    page = await c.get("/admin")
    r = await c.post(f"/admin/accounts/{a.id}/test", data={"csrf": csrf(page.text)})
    assert r.headers["location"] == "/admin?msg=check_failed"
    assert len(smtp) == before


async def test_test_now_without_smtp_does_not_touch_smtp(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com", smtp_host="")
    a = services.repo.get("s@example.com")
    page = await c.get("/admin")
    r = await c.post(f"/admin/accounts/{a.id}/test", data={"csrf": csrf(page.text)})
    assert r.headers["location"] == "/admin?msg=check_ok" and smtp == []


async def test_background_checks_never_log_in_to_smtp(env, smtp):
    c, services, _ = env
    await add(c, "s@example.com")
    before = len(smtp)
    await services.checker.check_account("s@example.com", False)
    await services.checker.check_account("s@example.com", True)
    assert len(smtp) == before


# -- consent page ---------------------------------------------------------------------------


def test_consent_grants_follow_the_account_levels(env, smtp, google_account):
    _, services, _ = env
    for email, level, host in (
        ("a@example.com", MailAccess.FULL, "smtp.example.com"),
        ("b@example.com", MailAccess.READ, "smtp.example.com"),
        ("c@example.com", MailAccess.FULL, None),
    ):
        services.repo.upsert(email=email, provider=Provider.IMAP, mail_access=level, smtp_host=host)
    services.repo.set_enabled("c@example.com", False)
    grants = consent_grants(services.repo.list(include_disabled=False))
    assert grants["read"] == "Read and search mail and save drafts in 3 accounts."
    assert grants["organize"].endswith("in 2 of them.")
    # The Google account (full) and a@ (full + SMTP); b@ is read-only, c@ is disabled.
    assert grants["send"] == "Sending is enabled on 2 accounts: it can send email as you there."
    services.repo.set_mail_access(G, MailAccess.READ)
    grants = consent_grants(services.repo.list(include_disabled=False))
    assert grants["send"].startswith("Sending is enabled on 1 account:")
