"""Security tests for the admin UI (beyond the brief)."""

import base64
import re
from urllib.parse import parse_qs, urlparse

import httpx
import itsdangerous
import pytest
import respx

from postroom.accounts import AccountStatus, Provider
from postroom.app import build_services, create_app
from postroom.crypto import hash_password
from postroom.google.oauth import REVOKE_URL, TOKEN_URL
from postroom.mail.imap import AuthFailed
from tests.unit.test_google_oauth import id_token

PASSWORD = "pw-for-tests-123"


class OkClient:
    def logout(self):
        pass

    def noop(self):
        pass


@pytest.fixture
def settings(settings):
    settings.public_url = "http://localhost"
    settings.admin_password_hash_b64 = base64.b64encode(hash_password(PASSWORD).encode()).decode()
    return settings


@pytest.fixture
async def app(settings, monkeypatch):
    services = build_services(settings)
    attempts = []

    def fake_connect(account, secret):
        attempts.append((account.email, secret))
        if secret != "good":
            raise AuthFailed("login failed: AUTHENTICATIONFAILED")
        return OkClient()

    monkeypatch.setattr(services.pool.connector, "connect", fake_connect)
    app = create_app(settings, services)
    app.state.attempts = attempts
    async with app.router.lifespan_context(app):
        yield app


def client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost")


def csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def put_cookie(c, name, value, path="/"):
    """Replace every cookie called `name` in the client's jar with exactly one new value."""
    for ck in list(c.cookies.jar):
        if ck.name == name:
            c.cookies.jar.clear(ck.domain, ck.path, ck.name)
    c.cookies.set(name, value, path=path)


async def log_in(c):
    page = await c.get("/login")
    r = await c.post("/login", data={"password": PASSWORD, "csrf": csrf(page.text), "next": "/"})
    assert r.status_code == 303


@pytest.fixture
async def anon(app):
    async with client(app) as c:
        yield c


@pytest.fixture
async def owner(app):
    async with client(app) as c:
        await log_in(c)
        c.token = csrf((await c.get("/admin")).text)
        yield c


@pytest.fixture
def services(app):
    return app.state.services


@pytest.fixture
def imap_account(services):
    return services.repo.upsert(
        email="d@x.example.com",
        provider=Provider.IMAP,
        display_name="D",
        imap_host="imap.x.example.com",
        imap_port=993,
        imap_security="ssl",
        secret="good",
        status=AccountStatus.CONNECTED,
    )


def form(**over):
    data = {
        "email": "n@x.example.com",
        "display_name": "N",
        "imap_host": "imap.x.example.com",
        "imap_port": "993",
        "imap_security": "ssl",
        "imap_username": "",
        "password": "good",
        "caldav_url": "",
        "carddav_url": "",
    }
    data.update(over)
    return data


GET_ROUTES = [
    "/admin",
    "/admin/accounts/new",
    "/admin/accounts/{id}/edit",
    "/admin/google/connect",
    "/admin/google/callback?code=c&state=s",
]
POST_ROUTES = [
    "/admin/accounts",
    "/admin/accounts/{id}",
    "/admin/accounts/{id}/test",
    "/admin/accounts/{id}/toggle",
    "/admin/accounts/{id}/delete",
    "/admin/api-keys",
    "/admin/api-keys/1/revoke",
    "/admin/clients/some-client/revoke",
]


# ----- authentication + CSRF on every route -------------------------------------------------


async def test_every_admin_get_requires_owner(anon, imap_account):
    for route in GET_ROUTES:
        r = await anon.get(route.format(id=imap_account.id))
        assert r.status_code == 302, route
        assert r.headers["location"].startswith("/login?next=%2Fadmin"), route


async def test_every_admin_post_requires_owner_and_changes_nothing(
    anon, app, services, imap_account
):
    key = services.provider.create_api_key("k")
    for route in POST_ROUTES:
        r = await anon.post(
            route.format(id=imap_account.id),
            data={**form(), "confirm": "d@x.example.com", "name": "evil", "csrf": "x"},
        )
        assert r.status_code in (302, 401, 403), route
        if r.status_code == 302:
            assert r.headers["location"].startswith("/login?next="), route
    a = services.repo.get("d@x.example.com")
    assert a is not None and a.enabled and services.repo.get_secret("d@x.example.com") == "good"
    assert services.repo.get("n@x.example.com") is None
    assert [k.name for k in services.provider.list_api_keys()] == ["k"]
    assert await services.provider.load_access_token(key) is not None
    assert app.state.attempts == []


@pytest.mark.parametrize("token", [None, "", "bogus"])
async def test_every_admin_post_requires_csrf(owner, app, services, imap_account, token):
    key = services.provider.create_api_key("k")
    for route in POST_ROUTES:
        data = {**form(), "confirm": "d@x.example.com", "name": "evil"}
        if token is not None:
            data["csrf"] = token
        r = await owner.post(route.format(id=imap_account.id), data=data)
        assert r.status_code == 403, route
    a = services.repo.get("d@x.example.com")
    assert a is not None and a.enabled and services.repo.get_secret("d@x.example.com") == "good"
    assert services.repo.get("n@x.example.com") is None
    assert [k.name for k in services.provider.list_api_keys()] == ["k"]
    assert await services.provider.load_access_token(key) is not None
    assert app.state.attempts == []


async def test_pre_login_token_is_not_accepted_as_admin_csrf(app):
    async with client(app) as c:
        page = await c.get("/login")
        pre = csrf(page.text)
        await log_in(c)
        r = await c.post("/admin/api-keys", data={"name": "x", "csrf": pre})
        assert r.status_code == 403


# ----- accounts -------------------------------------------------------------------------------


async def test_add_account_validation_makes_no_login_attempt(owner, app, services):
    bad = [
        {"email": "no-at-sign"},
        {"imap_host": ""},
        {"imap_port": "0"},
        {"imap_port": "65536"},
        {"imap_port": "abc"},
        {"imap_security": "plain"},
        {"password": ""},
        {"caldav_url": "javascript:alert(1)"},
        # Basic auth over plain http would send the mailbox password in cleartext.
        {"caldav_url": "http://dav.example/cal/"},
        {"carddav_url": "http://dav.example/card/"},
    ]
    for over in bad:
        r = await owner.post("/admin/accounts", data={**form(**over), "csrf": owner.token})
        assert r.status_code == 400, over
    assert app.state.attempts == [] and services.repo.list() == []


def test_dav_urls_must_be_https_except_loopback():
    from postroom.web.admin import AccountForm

    base = {
        "email": "a@x.example.com",
        "imap_host": "imap.x.example.com",
        "imap_port": "993",
        "imap_security": "ssl",
    }
    for url in (
        "https://dav.x.example.com/",
        "http://localhost:5232/",
        "http://127.0.0.1/",
        "http://[::1]/",
    ):
        f = AccountForm.from_form({**base, "caldav_url": url, "carddav_url": url})
        assert f.validate("pw", True) is None, url
    for url in (
        "http://dav.x.example.com/",
        "http://localhost.evil.example/",
        "ftp://dav.x.example.com/",
    ):
        assert AccountForm.from_form({**base, "caldav_url": url}).validate("pw", True), url


async def test_failed_add_does_not_echo_password(owner, services):
    pw = "Unique-Pw-8d7c6b"
    r = await owner.post("/admin/accounts", data={**form(password=pw), "csrf": owner.token})
    assert r.status_code == 200 and pw not in r.text
    assert services.repo.get("n@x.example.com") is None


async def test_add_existing_email_goes_to_edit(owner, app, imap_account):
    r = await owner.post(
        "/admin/accounts", data={**form(email="D@x.example.com", password="x"), "csrf": owner.token}
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"/admin/accounts/{imap_account.id}/edit"
    assert app.state.attempts == []


async def test_edit_keeps_secret_when_password_empty(owner, app, services, imap_account):
    page = await owner.get(f"/admin/accounts/{imap_account.id}/edit")
    assert page.status_code == 200 and "good" not in page.text  # secret never rendered
    r = await owner.post(
        f"/admin/accounts/{imap_account.id}",
        data={
            **form(email="d@x.example.com", display_name="New", password=""),
            "csrf": owner.token,
        },
    )
    assert r.status_code == 303 and "account_updated" in r.headers["location"]
    assert app.state.attempts == [("d@x.example.com", "good")]
    a = services.repo.get("d@x.example.com")
    assert a.display_name == "New" and services.repo.get_secret("d@x.example.com") == "good"


async def test_edit_with_bad_password_changes_nothing(owner, services, imap_account):
    r = await owner.post(
        f"/admin/accounts/{imap_account.id}",
        data={
            **form(email="d@x.example.com", display_name="New", password="bad"),
            "csrf": owner.token,
        },
    )
    assert r.status_code == 200 and "AUTHENTICATIONFAILED" in r.text
    a = services.repo.get("d@x.example.com")
    assert a.display_name == "D" and services.repo.get_secret("d@x.example.com") == "good"


async def test_edit_cannot_rename_account(owner, services, imap_account):
    r = await owner.post(
        f"/admin/accounts/{imap_account.id}",
        data={**form(email="other@x.example.com", password=""), "csrf": owner.token},
    )
    assert r.status_code == 303
    assert services.repo.get("other@x.example.com") is None and services.repo.get("d@x.example.com")


async def test_toggle_test_and_unknown_ids(owner, services, imap_account):
    r = await owner.post(f"/admin/accounts/{imap_account.id}/toggle", data={"csrf": owner.token})
    assert "account_toggled" in r.headers["location"]
    assert services.repo.get("d@x.example.com").enabled is False
    await owner.post(f"/admin/accounts/{imap_account.id}/toggle", data={"csrf": owner.token})
    assert services.repo.get("d@x.example.com").enabled is True
    r = await owner.post(f"/admin/accounts/{imap_account.id}/test", data={"csrf": owner.token})
    assert "check_ok" in r.headers["location"]
    for route in ("/admin/accounts/999/test", "/admin/accounts/999/toggle"):
        r = await owner.post(route, data={"csrf": owner.token})
        assert r.status_code == 404
    assert (await owner.get("/admin/accounts/999/edit")).status_code == 404


async def test_check_failed_message(owner, services):
    a = services.repo.upsert(
        email="b@x.example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="bad",
    )
    r = await owner.post(f"/admin/accounts/{a.id}/test", data={"csrf": owner.token})
    assert "check_failed" in r.headers["location"]
    assert services.repo.get("b@x.example.com").status == AccountStatus.NEEDS_RECONNECT


@respx.mock
async def test_delete_google_account_revokes_token(owner, services):
    revoke = respx.post(REVOKE_URL).respond(200)
    a = services.repo.upsert(email="g@gmail.com", provider=Provider.GOOGLE, secret="rt-old")
    r = await owner.post(
        f"/admin/accounts/{a.id}/delete", data={"csrf": owner.token, "confirm": "g@gmail.com"}
    )
    assert "account_removed" in r.headers["location"]
    assert services.repo.get("g@gmail.com") is None
    assert revoke.called and "rt-old" in revoke.calls[0].request.content.decode()


async def test_admin_output_is_escaped(owner, services):
    services.repo.upsert(
        email="x@x.example.com",
        provider=Provider.IMAP,
        display_name="<script>alert('name')</script>",
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
    )
    services.repo.set_status("x@x.example.com", AccountStatus.ERROR, "<img src=x onerror=alert(1)>")
    services.provider.create_api_key("<b>key</b>")
    reg = await owner.post(
        "/register",
        json={
            "redirect_uris": ["https://claude.ai/cb"],
            "client_name": "<script>alert('client')</script>",
            "token_endpoint_auth_method": "none",
        },
    )
    assert reg.status_code == 201
    page = await owner.get("/admin")
    for raw in ("<script>alert(", "<img src=x", "<b>key</b>"):
        assert raw not in page.text
    assert "&lt;script&gt;" in page.text


async def test_admin_page_shows_mcp_url_and_known_flash(owner):
    page = await owner.get("/admin?msg=account_added")
    assert "http://localhost/mcp" in page.text and "Account added." in page.text
    advanced = page.text.index('<details class="advanced">')
    assert page.text.index("import-emclient - --passphrase-first-line") > advanced
    assert "ssh " not in page.text
    page = await owner.get("/admin?msg=unknown_key")
    assert "unknown_key" not in page.text


# ----- API keys + OAuth clients ---------------------------------------------------------------


async def test_api_key_name_validation(owner, services):
    for name in ("", "   ", "x" * 61):
        r = await owner.post("/admin/api-keys", data={"name": name, "csrf": owner.token})
        assert r.status_code == 303 and "key_name_invalid" in r.headers["location"]
    assert services.provider.list_api_keys() == []


async def test_api_key_revoke(owner, services):
    key = services.provider.create_api_key("k")
    key_id = services.provider.list_api_keys()[0].id
    r = await owner.post(f"/admin/api-keys/{key_id}/revoke", data={"csrf": owner.token})
    assert "key_revoked" in r.headers["location"]
    assert await services.provider.load_access_token(key) is None


async def test_client_revoke(owner, services):
    reg = await owner.post(
        "/register",
        json={"redirect_uris": ["https://claude.ai/cb"], "token_endpoint_auth_method": "none"},
    )
    client_id = reg.json()["client_id"]
    page = await owner.get("/admin")
    assert "claude.ai" in page.text
    r = await owner.post(f"/admin/clients/{client_id}/revoke", data={"csrf": owner.token})
    assert "client_revoked" in r.headers["location"]
    assert services.provider.list_clients() == []


# ----- Google connect -------------------------------------------------------------------------


def gstate_cookie(r) -> str:
    return next(c for c in r.headers.get_list("set-cookie") if c.startswith("postroom_gstate="))


async def test_google_state_cookie_flags_and_login_hint(owner, services):
    a = services.repo.upsert(email="me@gmail.com", provider=Provider.GOOGLE)
    r = await owner.get("/admin/google/connect", params={"account_id": a.id})
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["login_hint"] == ["me@gmail.com"] and q["code_challenge_method"] == ["S256"]
    cookie = gstate_cookie(r)
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "Max-Age=600" in cookie and "Path=/admin/google" in cookie


async def test_google_disabled(owner, services):
    services.google = None
    r = await owner.get("/admin/google/connect")
    assert r.status_code == 303 and "google_disabled" in r.headers["location"]


async def test_google_callback_without_cookie_is_rejected(owner, services):
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": "s"})
    assert r.status_code == 400 and services.repo.list() == []


async def test_google_callback_error_param(owner):
    r = await owner.get("/admin/google/callback", params={"error": "access_denied", "state": "s"})
    assert r.status_code == 303 and "google_denied" in r.headers["location"]


@respx.mock
async def test_google_callback_rejects_forged_and_expired_state(owner, services, monkeypatch):
    token = respx.post(TOKEN_URL).respond(
        json={
            "refresh_token": "rt",
            "scope": "https://mail.google.com/",
            "id_token": id_token("evil@gmail.com"),
        }
    )
    r = await owner.get("/admin/google/connect")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    # A cookie signed with a different key/salt carrying the attacker's own state.
    forged = itsdangerous.URLSafeTimedSerializer("test-session-secret", salt="postroom-pre").dumps(
        {"state": "attacker", "verifier": "v"}
    )
    real = owner.cookies.get("postroom_gstate", path="/admin/google")
    put_cookie(owner, "postroom_gstate", forged, path="/admin/google")
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": "attacker"})
    assert r.status_code == 400

    put_cookie(owner, "postroom_gstate", real, path="/admin/google")
    import time as real_time

    class Later:
        @staticmethod
        def time():
            return real_time.time() + 601

    monkeypatch.setattr(itsdangerous.timed, "time", Later)
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 400
    assert not token.called and services.repo.list() == []


@respx.mock
async def test_google_state_is_bound_to_session_and_owner(app, owner, services):
    respx.post(TOKEN_URL).respond(
        json={
            "refresh_token": "rt",
            "scope": "https://mail.google.com/",
            "id_token": id_token("me@gmail.com"),
        }
    )
    r = await owner.get("/admin/google/connect")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    gcookie = owner.cookies.get("postroom_gstate", path="/admin/google")

    # Another owner session (e.g. a new login) cannot complete this flow with the cookie.
    async with client(app) as other:
        await log_in(other)
        put_cookie(other, "postroom_gstate", gcookie, path="/admin/google")
        r = await other.get("/admin/google/callback", params={"code": "abc", "state": state})
        assert r.status_code == 400

    # Positive control: the same injected cookie works in the session that started the flow.
    put_cookie(owner, "postroom_gstate", gcookie, path="/admin/google")
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 303 and "google_connected" in r.headers["location"]
    assert "postroom_gstate=" in gstate_cookie(r) and "Max-Age=0" in gstate_cookie(r)
    put_cookie(owner, "postroom_gstate", gcookie, path="/admin/google")
    services.repo.delete("me@gmail.com")
    # A replayed cookie + state can't be used once the owner session has ended.
    await owner.post("/logout", data={"csrf": owner.token})
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 302 and services.repo.get("me@gmail.com") is None


@respx.mock
async def test_google_exchange_error_is_shown_escaped(owner, services):
    respx.post(TOKEN_URL).respond(400, json={"error": "invalid_grant"})
    r = await owner.get("/admin/google/connect")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    r = await owner.get("/admin/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 400 and "invalid_grant" in r.text
    assert "gsecret" not in r.text and services.repo.list() == []


@pytest.mark.parametrize(
    "change",
    [
        {"imap_host": "imap.attacker.example"},
        {"smtp_host": "smtp.attacker.example", "smtp_port": "465", "smtp_security": "ssl"},
        {"caldav_url": "https://dav.attacker.example/cal/"},
        {"carddav_url": "https://dav.attacker.example/card/"},
    ],
)
async def test_edit_to_a_new_server_needs_the_password_again(
    owner, app, services, imap_account, change
):
    r = await owner.post(
        f"/admin/accounts/{imap_account.id}",
        data={**form(email="d@x.example.com", password=""), **change, "csrf": owner.token},
    )
    assert r.status_code == 400
    assert "Re-enter the password when changing a server address." in r.text
    assert app.state.attempts == []  # the stored password went nowhere
    a = services.repo.get("d@x.example.com")
    assert a.imap_host == "imap.x.example.com" and a.smtp_host is None and a.caldav_url is None


async def test_edit_to_a_new_server_with_the_password_typed_is_saved(
    owner, app, services, imap_account
):
    r = await owner.post(
        f"/admin/accounts/{imap_account.id}",
        data={
            **form(email="d@x.example.com", imap_host="imap2.x.example.com"),
            "csrf": owner.token,
        },
    )
    assert r.status_code == 303 and "account_updated" in r.headers["location"]
    assert app.state.attempts == [("d@x.example.com", "good")]
    assert services.repo.get("d@x.example.com").imap_host == "imap2.x.example.com"


async def test_edit_keeps_the_stored_password_for_the_same_servers(
    owner, app, services, imap_account
):
    services.repo.upsert(
        email="d@x.example.com",
        provider=Provider.IMAP,
        imap_host="imap.x.example.com",
        imap_port=993,
        imap_security="ssl",
        caldav_url="https://dav.x.example.com/cal/",
        carddav_url="https://dav.x.example.com/card/",
    )
    data = form(
        email="d@x.example.com",
        password="",
        imap_host="IMAP.x.example.com",
        imap_port="143",
        imap_security="starttls",
        caldav_url="https://DAV.x.example.com/other/path/",
        carddav_url="",  # removing a server is fine
    )
    r = await owner.post(f"/admin/accounts/{imap_account.id}", data={**data, "csrf": owner.token})
    assert r.status_code == 303, r.text
    assert app.state.attempts == [("d@x.example.com", "good")]
