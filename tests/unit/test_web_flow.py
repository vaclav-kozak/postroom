import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from postroom.accounts import AccountStatus, Provider
from postroom.app import build_services, create_app
from postroom.crypto import hash_password

PASSWORD = "correct horse battery staple"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def settings(settings):
    # The MCP SDK's route builder refuses an issuer that is neither https nor localhost,
    # so app-level tests run against http://localhost instead of http://testserver.
    settings.public_url = "http://localhost"
    return settings


@pytest.fixture
async def http(settings):
    settings.admin_password_hash_b64 = base64.b64encode(hash_password(PASSWORD).encode()).decode()
    services = build_services(settings)
    services.repo.upsert(
        email="a@x.example.com",
        provider=Provider.IMAP,
        imap_host="h",
        imap_port=993,
        imap_security="ssl",
        status=AccountStatus.CONNECTED,
    )
    app = create_app(settings, services)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c,
    ):
        yield c


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


async def login(http, next_="/admin"):
    page = await http.get(f"/login?next={next_}")
    return await http.post(
        "/login", data={"password": PASSWORD, "csrf": csrf(page.text), "next": next_}
    )


async def test_robots_and_headers(http):
    r = await http.get("/robots.txt")
    assert r.text == "User-agent: *\nDisallow: /\n"
    assert r.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    r = await http.get("/login")
    csp = r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "form-action" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert "noindex" in r.text


async def test_root_redirects_to_login(http):
    r = await http.get("/")
    assert r.status_code == 302 and r.headers["location"].endswith("/login")


async def test_mcp_requires_auth(http):
    r = await http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]


async def test_login_csrf_and_wrong_password(http):
    r = await http.post("/login", data={"password": PASSWORD, "csrf": "bogus", "next": "/admin"})
    assert r.status_code == 400
    page = await http.get("/login")
    r = await http.post(
        "/login", data={"password": "nope", "csrf": csrf(page.text), "next": "/admin"}
    )
    assert r.status_code == 401 and "postroom_session" not in r.cookies


async def test_login_lockout(http):
    for _ in range(5):
        page = await http.get("/login")
        await http.post("/login", data={"password": "nope", "csrf": csrf(page.text), "next": "/"})
    page = await http.get("/login")
    r = await http.post("/login", data={"password": PASSWORD, "csrf": csrf(page.text), "next": "/"})
    assert r.status_code == 429


async def test_full_oauth_flow_and_mcp_call(http):
    reg = await http.post(
        "/register",
        json={
            "redirect_uris": [REDIRECT],
            "client_name": "Claude",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    r = await http.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "resource": "http://localhost/mcp",
        },
    )
    assert r.status_code in (302, 307)
    consent_url = r.headers["location"]
    assert "/consent?txn=" in consent_url

    path = urlparse(consent_url).path + "?" + urlparse(consent_url).query
    r = await http.get(path)
    assert r.status_code == 302 and "/login?next=" in r.headers["location"]

    r = await login(http, next_=path)
    assert r.status_code == 303 and r.headers["location"] == path

    page = await http.get(path)
    assert "claude.ai" in page.text and "Claude" in page.text
    assert "Sending is not enabled on any account." in page.text
    txn = parse_qs(urlparse(consent_url).query)["txn"][0]
    r = await http.post("/consent", data={"txn": txn, "action": "allow", "csrf": csrf(page.text)})
    assert r.status_code == 303
    cb = urlparse(r.headers["location"])
    assert f"{cb.scheme}://{cb.netloc}{cb.path}" == REDIRECT
    q = parse_qs(cb.query)
    assert q["state"] == ["xyz"]

    tok = await http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": q["code"][0],
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": "http://localhost/mcp",
        },
    )
    assert tok.status_code == 200, tok.text
    access = tok.json()["access_token"]

    headers = {"Authorization": f"Bearer {access}", "Accept": "application/json, text/event-stream"}
    init = await http.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        },
    )
    assert init.status_code == 200, init.text
    r = await http.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    assert r.status_code == 200 and "search_emails" in r.text


async def test_consent_post_requires_owner_and_csrf(http):
    r = await http.post("/consent", data={"txn": "x", "action": "allow", "csrf": "x"})
    assert r.status_code == 403


async def test_api_key_works_on_mcp(http):
    app_services = http._transport.app.state.services
    key = app_services.provider.create_api_key("t")
    r = await http.post(
        "/mcp",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json, text/event-stream"},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        },
    )
    assert r.status_code == 200


CLAUDE_REGISTRATION = {
    "client_name": "Claude",
    "redirect_uris": [REDIRECT],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "mcp",
}


async def test_registration_keeps_only_used_metadata(http):
    body = {**CLAUDE_REGISTRATION, "jwks": {"keys": []}, "logo_uri": "https://claude.ai/l.png"}
    r = await http.post("/register", json=body)
    assert r.status_code == 201, r.text
    got = r.json()
    assert got["client_name"] == "Claude" and got["redirect_uris"] == [REDIRECT]
    assert got["scope"] == "mcp" and "jwks" not in got and "logo_uri" not in got


async def test_oauth_endpoints_reject_oversized_bodies(http):
    big = {**CLAUDE_REGISTRATION, "jwks": {"keys": ["k" * 20_000]}}
    r = await http.post("/register", json=big)
    assert r.status_code == 413
    r = await http.post("/register", json={**CLAUDE_REGISTRATION, "client_name": "n" * 201})
    assert r.status_code == 400 and r.json()["error"] == "invalid_client_metadata"
    for path in ("/authorize", "/token", "/revoke"):
        r = await http.post(path, data={"state": "s" * 20_000})
        assert r.status_code == 413, path


async def test_authorize_rejects_oversized_state(http):
    client_id = (await http.post("/register", json=CLAUDE_REGISTRATION)).json()["client_id"]
    r = await http.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "response_type": "code",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "state": "s" * 1001,
        },
    )
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith(REDIRECT + "?") and "error=invalid_request" in location
    assert "/consent" not in location


async def test_trailing_slash_redirect_ignores_host_header(http):
    r = await http.post("/mcp/", json={}, headers={"Host": "evil.example"})
    assert r.status_code == 307
    assert r.headers["location"] == "http://localhost/mcp"
