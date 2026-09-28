"""Security tests for the owner login, consent page and security headers (beyond the brief)."""

import base64
import hashlib
import logging
import re
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import itsdangerous
import pytest
from starlette.responses import Response

from postroom.app import build_services, create_app
from postroom.auth.owner import LoginGuard, OwnerAuth, client_ip
from postroom.crypto import hash_password
from postroom.web.security import ROBOTS_TXT

PASSWORD = "correct horse battery staple"
CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"


@pytest.fixture
def settings(settings):
    settings.public_url = "http://localhost"
    settings.admin_password_hash_b64 = base64.b64encode(hash_password(PASSWORD).encode()).decode()
    return settings


@pytest.fixture
async def app(settings):
    app = create_app(settings, build_services(settings))
    async with app.router.lifespan_context(app):
        yield app


def client(app, **kw) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost", **kw
    )


@pytest.fixture
async def http(app):
    async with client(app) as c:
        yield c


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


async def login(http, next_="/admin", password=PASSWORD, headers=None):
    page = await http.get("/login", params={"next": next_}, headers=headers)
    return await http.post(
        "/login",
        data={"password": password, "csrf": csrf(page.text), "next": next_},
        headers=headers,
    )


async def start_authorization(http, client_name="Claude", redirect="https://claude.ai/cb"):
    reg = await http.post(
        "/register",
        json={
            "redirect_uris": [redirect],
            "client_name": client_name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert reg.status_code == 201, reg.text
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    r = await http.get(
        "/authorize",
        params={
            "client_id": reg.json()["client_id"],
            "redirect_uri": redirect,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st",
            "resource": "http://localhost/mcp",
        },
    )
    loc = urlparse(r.headers["location"])
    return f"{loc.path}?{loc.query}", parse_qs(loc.query)["txn"][0]


# ----- LoginGuard -----------------------------------------------------------------------------


def test_ip_lockout_exact_threshold_and_success_does_not_reset(db):
    now = [50_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    for _ in range(4):
        g.record("1.1.1.1", False)
    g.record("1.1.1.1", True)
    assert g.blocked_for("1.1.1.1") == 0
    now[0] += 10
    g.record("1.1.1.1", False)  # 5th failure within 900 s -> blocked
    # blocked until the 5th-newest failure (the first one, at 50_000) + 900
    assert g.blocked_for("1.1.1.1") == 890
    now[0] += 889
    assert g.blocked_for("1.1.1.1") == 1
    now[0] += 1
    assert g.blocked_for("1.1.1.1") == 0


def test_ip_failures_spread_over_window_do_not_block(db):
    now = [50_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    for _ in range(5):
        g.record("1.1.1.1", False)
        now[0] += 250  # 5 failures spread over 1000 s: never 5 within 900 s
    assert g.blocked_for("1.1.1.1") == 0


def test_global_lockout_exact_threshold(db):
    now = [50_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    for i in range(19):
        g.record(f"10.0.0.{i}", False)
    assert g.blocked_for("9.9.9.9") == 0
    g.record("10.0.1.1", False)
    assert g.blocked_for("9.9.9.9") == 3600
    now[0] += 3599
    assert g.blocked_for("9.9.9.9") == 1
    now[0] += 1
    assert g.blocked_for("9.9.9.9") == 0


def test_old_attempts_are_pruned(db):
    now = [50_000.0]
    g = LoginGuard(db, clock=lambda: now[0])
    g.record("1.1.1.1", False)
    now[0] += 86_401
    g.record("2.2.2.2", False)
    rows = db.query("SELECT ip FROM login_attempts")
    assert [r["ip"] for r in rows] == ["2.2.2.2"]


# ----- OwnerAuth ------------------------------------------------------------------------------


def test_empty_password_hash_never_matches(settings, db):
    settings.admin_password_hash_b64 = ""
    owner = OwnerAuth(settings, LoginGuard(db))
    assert owner.check_password("") is False
    assert owner.check_password("anything") is False


def test_check_password(settings, db):
    owner = OwnerAuth(settings, LoginGuard(db))
    assert owner.check_password(PASSWORD) is True
    assert owner.check_password(PASSWORD + "x") is False


def test_password_change_ends_existing_sessions(settings, db):
    """Break-glass: a new admin password hash (applied on restart) must kill stolen cookies."""
    resp = Response()
    OwnerAuth(settings, LoginGuard(db)).start_session(resp)
    cookie = resp.headers["set-cookie"].split(";")[0].split("=", 1)[1]

    class Req:
        def __init__(self):
            self.cookies = {"postroom_session": cookie}

    # A restart with the same password keeps the session.
    assert OwnerAuth(settings, LoginGuard(db)).session(Req()) is not None
    settings.admin_password_hash_b64 = base64.b64encode(hash_password("new pw").encode()).decode()
    assert OwnerAuth(settings, LoginGuard(db)).session(Req()) is None


@pytest.mark.parametrize(
    "url,secure", [("https://imap.example", True), ("http://localhost", False)]
)
def test_session_cookie_flags(settings, db, url, secure):
    settings.public_url = url
    owner = OwnerAuth(settings, LoginGuard(db))
    resp = Response()
    owner.start_session(resp)
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith("postroom_session=")
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "Max-Age=43200" in cookie and "Path=/" in cookie
    assert ("Secure" in cookie) is secure


def test_client_ip_prefers_x_real_ip():
    class Req:
        def __init__(self, headers, host):
            self.headers = headers
            self.client = type("C", (), {"host": host})() if host else None

    assert client_ip(Req({"x-real-ip": "203.0.113.9"}, "10.0.0.2")) == "203.0.113.9"
    assert client_ip(Req({}, "10.0.0.2")) == "10.0.0.2"
    assert client_ip(Req({}, None)) == "unknown"


# ----- headers --------------------------------------------------------------------------------


async def test_security_headers_on_every_response(http):
    responses = [
        await http.get("/"),
        await http.get("/robots.txt"),
        await http.get("/healthz"),
        await http.get("/static/app.css"),
        await http.get("/login"),
        await http.get("/no-such-page"),
        await http.post("/mcp", json={}),
        await http.get("/.well-known/oauth-authorization-server"),
        await http.post("/token", data={"grant_type": "nope"}),
        await http.post("/consent", data={}),
    ]
    for r in responses:
        assert r.headers["x-robots-tag"] == "noindex, nofollow, noarchive", r.url
        assert r.headers["x-content-type-options"] == "nosniff", r.url
        assert r.headers["referrer-policy"] == "no-referrer", r.url
        assert r.headers["x-frame-options"] == "DENY", r.url
        assert r.headers["content-security-policy"] == CSP, r.url


async def test_robots_and_healthz(http):
    r = await http.get("/robots.txt")
    assert r.text == ROBOTS_TXT and r.headers["content-type"].startswith("text/plain")
    r = await http.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    r = await http.get("/static/app.css")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css")


# ----- login ----------------------------------------------------------------------------------


async def test_login_sets_session_cookie_with_flags(http):
    r = await login(http)
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    cookies = r.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("postroom_session="))
    assert "HttpOnly" in session and "SameSite=lax" in session and "Max-Age=43200" in session
    assert "Secure" not in session  # http://localhost -> not Secure (https would be)


async def test_login_csrf_needs_the_pre_login_cookie(app):
    # A token scraped from someone else's login page is useless without the matching cookie.
    async with client(app) as a:
        page = await a.get("/login")
        token = csrf(page.text)
    async with client(app) as b:
        r = await b.post("/login", data={"password": PASSWORD, "csrf": token, "next": "/admin"})
        assert r.status_code == 400 and "postroom_session" not in r.cookies
        r = await b.post("/login", data={"password": PASSWORD, "next": "/admin"})
        assert r.status_code == 400


async def test_pre_login_cookie_is_not_a_session(http):
    page = await http.get("/login")
    pre = http.cookies["postroom_pre"]
    http.cookies.set("postroom_session", pre)
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 302 and "/login?next=" in r.headers["location"]
    assert csrf(page.text)


async def test_forged_or_expired_session_rejected(http, settings, monkeypatch):
    forged = itsdangerous.URLSafeTimedSerializer("other-secret", salt="postroom-session").dumps(
        {"sid": "s", "csrf": "c"}
    )
    http.cookies.set("postroom_session", forged)
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 302 and "/login" in r.headers["location"]

    http.cookies.clear()
    await login(http)
    # Positive control: a genuine session cookie injected the same way is accepted.
    genuine = http.cookies["postroom_session"]
    http.cookies.clear()
    http.cookies.set("postroom_session", genuine)
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 400  # logged in: unknown txn page

    import time as real_time

    class Later:
        @staticmethod
        def time():
            return real_time.time() + 43_201

    monkeypatch.setattr(itsdangerous.timed, "time", Later)
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 302 and "/login" in r.headers["location"]


async def test_wrong_password_not_echoed_or_logged(http, caplog):
    guess = "Sup3r-secret-guess-9f8e"
    with caplog.at_level(logging.WARNING):
        r = await login(http, password=guess)
    assert r.status_code == 401
    assert guess not in r.text
    assert "login failed ip=127.0.0.1" in caplog.text
    assert guess not in caplog.text


async def test_lockout_is_per_ip_via_x_real_ip(http):
    for _ in range(5):
        await login(http, password="nope", headers={"X-Real-IP": "198.51.100.7"})
    r = await login(http, headers={"X-Real-IP": "198.51.100.7"})
    assert r.status_code == 429 and "try again in 15 minutes" in r.text
    assert "postroom_session" not in r.cookies
    r = await login(http, headers={"X-Real-IP": "198.51.100.8"})
    assert r.status_code == 303


async def test_global_lockout_blocks_every_ip(http):
    for i in range(20):
        await login(http, password="nope", headers={"X-Real-IP": f"198.51.100.{i}"})
    r = await login(http, headers={"X-Real-IP": "192.0.2.1"})
    assert r.status_code == 429


@pytest.mark.parametrize(
    "bad", ["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)"]
)
async def test_login_next_is_not_an_open_redirect(http, bad):
    r = await login(http, next_=bad)
    assert r.status_code == 303 and r.headers["location"] == "/admin"


async def test_login_next_is_not_reflected_unescaped(http):
    r = await http.get("/login", params={"next": '/"><script>alert(1)</script>'})
    assert "<script>alert(1)" not in r.text


async def test_login_page_redirects_owner(http):
    await login(http)
    r = await http.get("/login", params={"next": "/consent?txn=abc"})
    assert r.status_code in (302, 303) and r.headers["location"] == "/consent?txn=abc"


async def test_logout_requires_csrf_and_ends_session(http):
    await login(http)
    r = await http.post("/logout", data={})
    assert r.status_code == 403
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 400  # still logged in
    r = await http.post("/logout", data={"csrf": csrf(r.text)})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = await http.get("/consent", params={"txn": "x"})
    assert r.status_code == 302 and "/login" in r.headers["location"]


# ----- consent --------------------------------------------------------------------------------


async def test_consent_escapes_client_metadata(http):
    path, _ = await start_authorization(
        http, client_name="<script>alert(1)</script>", redirect="https://claude.com/other/cb"
    )
    await login(http, next_=path)
    page = await http.get(path)
    assert page.status_code == 200
    assert "<script>alert(1)" not in page.text and "&lt;script&gt;" in page.text
    assert "claude.com" in page.text and "https://claude.com/other/cb" in page.text


async def test_consent_bad_csrf_is_forbidden_and_txn_survives(http):
    path, txn = await start_authorization(http)
    await login(http, next_=path)
    r = await http.post("/consent", data={"txn": txn, "action": "allow", "csrf": "bogus"})
    assert r.status_code == 403
    page = await http.get(path)
    r = await http.post("/consent", data={"txn": txn, "action": "allow", "csrf": csrf(page.text)})
    assert r.status_code == 303 and r.headers["location"].startswith("https://claude.ai/cb?")


async def test_consent_deny_and_single_use(http):
    path, txn = await start_authorization(http)
    await login(http, next_=path)
    page = await http.get(path)
    token = csrf(page.text)
    r = await http.post("/consent", data={"txn": txn, "action": "deny", "csrf": token})
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["error"] == ["access_denied"] and "code" not in q
    r = await http.post("/consent", data={"txn": txn, "action": "allow", "csrf": token})
    assert r.status_code == 400
    r = await http.get(path)
    assert r.status_code == 400 and "start again from Claude" in r.text


async def test_consent_unknown_action_rejected(http):
    path, txn = await start_authorization(http)
    await login(http, next_=path)
    page = await http.get(path)
    r = await http.post("/consent", data={"txn": txn, "action": "hmm", "csrf": csrf(page.text)})
    assert r.status_code == 400
    assert (await http.get(path)).status_code == 200  # txn untouched


# ----- /mcp -----------------------------------------------------------------------------------


async def test_mcp_rejects_bad_and_revoked_bearers(app, http):
    services = app.state.services
    key = services.provider.create_api_key("k")
    services.provider.revoke_api_key(services.provider.list_api_keys()[0].id)
    for bearer in ("nope", "prm_nope", key):
        r = await http.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={
                "Authorization": f"Bearer {bearer}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]


async def test_owner_session_does_not_grant_mcp(http):
    await login(http)
    r = await http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401


# ----- security fix round: login serialization and server-side logout --------------------------


async def test_concurrent_wrong_passwords_cannot_bypass_lockout(app):
    import asyncio

    async with client(app) as c:
        page = await c.get("/login")
        token = csrf(page.text)
        form = {"password": "nope", "csrf": token, "next": "/admin"}
        results = await asyncio.gather(*(c.post("/login", data=form) for _ in range(30)))
    codes = [r.status_code for r in results]
    assert codes.count(401) <= 5
    assert codes.count(401) + codes.count(429) == 30
    db = app.state.services.db
    assert db.one("SELECT count(*) FROM login_attempts WHERE ok = 0")[0] <= 5


async def test_copied_session_cookie_fails_after_logout(app):
    async with client(app) as owner_browser:
        await login(owner_browser)
        stolen = owner_browser.cookies["postroom_session"]
        r = await owner_browser.get("/consent", params={"txn": "x"})
        assert r.status_code == 400  # logged in
        r = await owner_browser.post("/logout", data={"csrf": csrf(r.text)})
        assert r.status_code == 303
    async with client(app) as attacker:
        attacker.cookies.set("postroom_session", stolen)
        r = await attacker.get("/consent", params={"txn": "x"})
        assert r.status_code == 302 and "/login" in r.headers["location"]
    async with client(app) as again:  # a fresh login works after logout
        await login(again)
        r = await again.get("/consent", params={"txn": "x"})
        assert r.status_code == 400


async def test_logout_without_session_does_not_end_owner_sessions(app):
    async with client(app) as owner_browser:
        await login(owner_browser)
        async with client(app) as stranger:
            page = await stranger.get("/login")
            r = await stranger.post("/logout", data={"csrf": csrf(page.text)})
            assert r.status_code == 303
        r = await owner_browser.get("/consent", params={"txn": "x"})
        assert r.status_code == 400  # still logged in


async def test_register_rejects_redirect_outside_allowed_hosts(http):
    r = await http.post(
        "/register",
        json={
            "redirect_uris": ["https://attacker.example/cb"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri"
