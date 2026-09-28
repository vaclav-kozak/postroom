import base64
import re

import httpx
import pytest
import respx

from postroom.accounts import AccountStatus, Provider
from postroom.app import build_services, create_app
from postroom.crypto import hash_password
from postroom.google.oauth import TOKEN_URL
from tests.unit.test_google_oauth import id_token

PASSWORD = "pw-for-tests-123"


class OkClient:
    def logout(self):
        pass

    def noop(self):
        pass


@pytest.fixture
def settings(settings):
    # The MCP SDK's route builder refuses an issuer that is neither https nor localhost,
    # so app-level tests run against http://localhost instead of http://testserver.
    settings.public_url = "http://localhost"
    return settings


@pytest.fixture
async def env(settings, monkeypatch):
    settings.admin_password_hash_b64 = base64.b64encode(hash_password(PASSWORD).encode()).decode()
    services = build_services(settings)
    attempts = []

    def fake_connect(account, secret):
        attempts.append((account.email, secret))
        if secret != "good":
            from postroom.mail.imap import AuthFailed

            raise AuthFailed("login failed: AUTHENTICATIONFAILED")
        return OkClient()

    monkeypatch.setattr(services.pool.connector, "connect", fake_connect)
    app = create_app(settings, services)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c,
    ):
        page = await c.get("/login")
        tok = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        await c.post("/login", data={"password": PASSWORD, "csrf": tok, "next": "/admin"})
        yield c, services, attempts


def csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


async def test_admin_requires_login(settings):
    app = create_app(settings, build_services(settings))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as c:
        r = await c.get("/admin")
    assert r.status_code == 302 and "/login?next=" in r.headers["location"]


async def test_add_account_bad_password_stores_nothing(env):
    c, services, _ = env
    page = await c.get("/admin/accounts/new")
    r = await c.post(
        "/admin/accounts",
        data={
            "csrf": csrf(page.text),
            "email": "n@x.cz",
            "display_name": "N",
            "imap_host": "imap.x.cz",
            "imap_port": "993",
            "imap_security": "ssl",
            "imap_username": "",
            "password": "bad",
            "caldav_url": "",
            "carddav_url": "",
        },
    )
    assert r.status_code == 200 and "AUTHENTICATIONFAILED" in r.text
    assert services.repo.get("n@x.cz") is None


def _account_form(csrf_token: str, email: str, **extra: str) -> dict[str, str]:
    data = {
        "csrf": csrf_token,
        "email": email,
        "display_name": "",
        "imap_host": "mail.example.com",
        "imap_port": "993",
        "imap_security": "ssl",
        "imap_username": "",
        "password": "good",
        "caldav_url": "",
        "carddav_url": "",
    }
    data.update(extra)
    return data


async def test_add_account_blank_dav_urls_stay_blank(env):
    c, services, _ = env
    page = await c.get("/admin/accounts/new")
    r = await c.post("/admin/accounts", data=_account_form(csrf(page.text), "s@example.com"))
    assert r.status_code == 303
    a = services.repo.get("s@example.com")
    assert a.status == AccountStatus.CONNECTED
    assert a.caldav_url is None and a.carddav_url is None
    assert services.repo.get_secret("s@example.com") == "good"


async def test_add_account_with_manual_dav_urls(env):
    c, services, _ = env
    page = await c.get("/admin/accounts/new")
    dav = "https://mail.example.com/SOGo/dav/s@example.com/"
    r = await c.post(
        "/admin/accounts",
        data=_account_form(csrf(page.text), "s@example.com", caldav_url=dav, carddav_url=dav),
    )
    assert r.status_code == 303
    a = services.repo.get("s@example.com")
    assert a.caldav_url == dav and a.carddav_url == dav


async def test_account_form_explains_dav_urls(env):
    c, _, _ = env
    page = await c.get("/admin/accounts/new")
    assert "/SOGo/dav/&lt;email&gt;/" in page.text
    assert "Google accounts need no DAV URLs" in page.text


async def test_post_without_csrf_is_forbidden(env):
    c, _, _ = env
    r = await c.post("/admin/api-keys", data={"name": "x"})
    assert r.status_code == 403


async def test_api_key_shown_once(env):
    c, services, _ = env
    page = await c.get("/admin")
    r = await c.post("/admin/api-keys", data={"name": "cli", "csrf": csrf(page.text)})
    key = re.search(r"(prm_[A-Za-z0-9_\-]+)", r.text).group(1)
    assert r.headers["cache-control"] == "no-store"
    assert await services.provider.load_access_token(key) is not None
    page = await c.get("/admin")
    assert key not in page.text and "cli" in page.text


async def test_delete_requires_confirmation(env):
    c, services, _ = env
    a = services.repo.upsert(
        email="d@x.cz",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        secret="p",
    )
    page = await c.get("/admin")
    r = await c.post(
        f"/admin/accounts/{a.id}/delete", data={"csrf": csrf(page.text), "confirm": "nope"}
    )
    assert "confirm_mismatch" in r.headers["location"] and services.repo.get("d@x.cz")
    r = await c.post(
        f"/admin/accounts/{a.id}/delete", data={"csrf": csrf(page.text), "confirm": "d@x.cz"}
    )
    assert services.repo.get("d@x.cz") is None


async def test_flash_messages_are_not_reflected(env):
    c, _, _ = env
    r = await c.get("/admin?msg=<script>alert(1)</script>")
    assert "<script>alert(1)" not in r.text


@respx.mock
async def test_google_connect_flow(env):
    c, services, _ = env
    respx.post(TOKEN_URL).respond(
        json={
            "access_token": "at",
            "expires_in": 3599,
            "refresh_token": "rt-new",
            "scope": "openid email https://mail.google.com/",
            "id_token": id_token("me@gmail.com"),
        }
    )
    r = await c.get("/admin/google/connect")
    assert r.status_code == 302 and r.headers["location"].startswith("https://accounts.google.com/")
    state = re.search(r"state=([^&]+)", r.headers["location"]).group(1)
    r = await c.get("/admin/google/callback", params={"code": "abc", "state": "wrong"})
    assert r.status_code == 400
    r = await c.get("/admin/google/callback", params={"code": "abc", "state": state})
    assert r.status_code == 303 and "google_connected" in r.headers["location"]
    a = services.repo.get("me@gmail.com")
    assert a.provider == Provider.GOOGLE and services.repo.get_secret("me@gmail.com") == "rt-new"
