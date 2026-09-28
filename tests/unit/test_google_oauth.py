import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from postroom.accounts import AccountStatus, Provider
from postroom.google.oauth import GOOGLE_SCOPES, TOKEN_URL, GoogleOAuth, GoogleOAuthError
from postroom.mail.imap import AuthFailed


def id_token(email, verified=True):
    payload = (
        base64.urlsafe_b64encode(json.dumps({"email": email, "email_verified": verified}).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"h.{payload}.s"


@pytest.fixture
def g(settings, repo):
    return GoogleOAuth(settings, repo, http=httpx.Client())


def test_authorization_url(g):
    q = parse_qs(urlparse(g.authorization_url("st", "ch", "me@gmail.com")).query)
    assert q["client_id"] == ["gid"] and q["access_type"] == ["offline"]
    assert q["prompt"] == ["consent"] and q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == ["http://testserver/admin/google/callback"]
    assert set(q["scope"][0].split()) == set(GOOGLE_SCOPES)
    assert q["login_hint"] == ["me@gmail.com"]


@respx.mock
def test_exchange_code(g):
    route = respx.post(TOKEN_URL).respond(
        json={
            "access_token": "at",
            "expires_in": 3599,
            "refresh_token": "rt",
            "scope": " ".join(GOOGLE_SCOPES),
            "id_token": id_token("Me@Gmail.com"),
        }
    )
    grant = g.exchange_code("code", "verifier")
    assert grant.email == "me@gmail.com" and grant.refresh_token == "rt"
    body = parse_qs(route.calls[0].request.content.decode())
    assert body["code_verifier"] == ["verifier"] and body["grant_type"] == ["authorization_code"]


@respx.mock
def test_exchange_code_without_gmail_scope(g):
    respx.post(TOKEN_URL).respond(
        json={
            "access_token": "at",
            "expires_in": 1,
            "refresh_token": "rt",
            "scope": "openid email",
            "id_token": id_token("me@gmail.com"),
        }
    )
    with pytest.raises(GoogleOAuthError, match="Gmail"):
        g.exchange_code("code", "v")


@respx.mock
def test_access_token_cached_and_refreshed(settings, repo):
    now = [1000.0]
    repo.upsert(
        email="me@gmail.com", provider=Provider.GOOGLE, secret="rt", status=AccountStatus.CONNECTED
    )
    route = respx.post(TOKEN_URL).respond(json={"access_token": "at1", "expires_in": 3600})
    g = GoogleOAuth(settings, repo, http=httpx.Client(), clock=lambda: now[0])
    assert g.access_token("me@gmail.com") == "at1"
    assert g.access_token("me@gmail.com") == "at1"
    assert route.call_count == 1
    now[0] += 3590
    route.respond(json={"access_token": "at2", "expires_in": 3600})
    assert g.access_token("me@gmail.com") == "at2"


@respx.mock
def test_invalid_grant_marks_reconnect(g, repo):
    repo.upsert(
        email="me@gmail.com", provider=Provider.GOOGLE, secret="rt", status=AccountStatus.CONNECTED
    )
    respx.post(TOKEN_URL).respond(400, json={"error": "invalid_grant"})
    with pytest.raises(AuthFailed):
        g.access_token("me@gmail.com")
    assert repo.get("me@gmail.com").status == AccountStatus.NEEDS_RECONNECT


# -- additional coverage for brief-specified behaviour not exercised above -----------------


@respx.mock
def test_exchange_code_requires_verified_email(g):
    respx.post(TOKEN_URL).respond(
        json={
            "access_token": "at",
            "expires_in": 3599,
            "refresh_token": "rt",
            "scope": " ".join(GOOGLE_SCOPES),
            "id_token": id_token("me@gmail.com", verified=False),
        }
    )
    with pytest.raises(GoogleOAuthError):
        g.exchange_code("code", "v")


@respx.mock
def test_exchange_code_requires_refresh_token(g):
    respx.post(TOKEN_URL).respond(
        json={
            "access_token": "at",
            "expires_in": 3599,
            "scope": " ".join(GOOGLE_SCOPES),
            "id_token": id_token("me@gmail.com"),
        }
    )
    with pytest.raises(GoogleOAuthError):
        g.exchange_code("code", "v")


@respx.mock
def test_exchange_code_http_error_does_not_leak_client_secret(g):
    respx.post(TOKEN_URL).respond(400, json={"error": "invalid_grant"})
    with pytest.raises(GoogleOAuthError) as exc:
        g.exchange_code("code", "v")
    assert "gsecret" not in str(exc.value)


@respx.mock
def test_other_refresh_error_is_oauth_error_and_keeps_status(g, repo):
    repo.upsert(
        email="me@gmail.com",
        provider=Provider.GOOGLE,
        secret="rt-secret",
        status=AccountStatus.CONNECTED,
    )
    respx.post(TOKEN_URL).respond(500, json={"error": "backend_error"})
    with pytest.raises(GoogleOAuthError) as exc:
        g.access_token("me@gmail.com")
    assert repo.get("me@gmail.com").status == AccountStatus.CONNECTED
    assert "rt-secret" not in str(exc.value) and "gsecret" not in str(exc.value)


@respx.mock
def test_refresh_network_error_is_oauth_error(g, repo):
    repo.upsert(
        email="me@gmail.com", provider=Provider.GOOGLE, secret="rt", status=AccountStatus.CONNECTED
    )
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(GoogleOAuthError):
        g.access_token("me@gmail.com")


def test_access_token_without_stored_refresh_token_is_auth_failed(g, repo):
    repo.upsert(
        email="me@gmail.com", provider=Provider.GOOGLE, status=AccountStatus.NEEDS_GOOGLE_CONNECT
    )
    with pytest.raises(AuthFailed):
        g.access_token("me@gmail.com")


@respx.mock
def test_invalidate_forces_refresh(g, repo):
    repo.upsert(
        email="me@gmail.com", provider=Provider.GOOGLE, secret="rt", status=AccountStatus.CONNECTED
    )
    route = respx.post(TOKEN_URL).respond(json={"access_token": "at1", "expires_in": 3600})
    assert g.access_token("me@gmail.com") == "at1"
    g.invalidate("me@gmail.com")
    route.respond(json={"access_token": "at2", "expires_in": 3600})
    assert g.access_token("me@gmail.com") == "at2"
    assert route.call_count == 2
    body = parse_qs(route.calls[0].request.content.decode())
    assert body["grant_type"] == ["refresh_token"] and body["refresh_token"] == ["rt"]


@respx.mock
def test_revoke_is_best_effort(g):
    from postroom.google.oauth import REVOKE_URL

    route = respx.post(REVOKE_URL).respond(400, json={"error": "invalid_token"})
    g.revoke("rt")  # must not raise
    assert parse_qs(route.calls[0].request.content.decode())["token"] == ["rt"]
    route.mock(side_effect=httpx.ConnectError("down"))
    g.revoke("rt")  # network failures are swallowed too
