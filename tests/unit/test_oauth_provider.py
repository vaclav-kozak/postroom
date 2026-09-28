import logging

import pytest
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationParams,
    AuthorizeError,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyHttpUrl, AnyUrl

from postroom.auth import provider as provider_mod
from postroom.auth.provider import PostroomOAuthProvider
from postroom.crypto import hash_token


@pytest.fixture
def clock():
    return [1_000_000.0]


@pytest.fixture
def prov(settings, db, clock):
    return PostroomOAuthProvider(settings, db, clock=lambda: clock[0])


def client(cid="c1", uris=("https://claude.ai/api/mcp/auth_callback",)):
    return OAuthClientInformationFull(
        client_id=cid,
        redirect_uris=[AnyUrl(u) for u in uris],
        client_name="Claude",
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp",
    )


# RFC 7636 appendix B: an S256 challenge is always 43 base64url characters.
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def params(resource="http://testserver/mcp", state="st", challenge=CHALLENGE):
    return AuthorizationParams(
        state=state,
        scopes=["mcp"],
        code_challenge=challenge,
        redirect_uri=AnyUrl("https://claude.ai/api/mcp/auth_callback"),
        redirect_uri_provided_explicitly=True,
        resource=resource,
    )


async def full_flow(prov):
    c = client()
    await prov.register_client(c)
    url = await prov.authorize(c, params())
    txn = url.split("txn=")[1]
    redirect = prov.approve(txn)
    code = redirect.split("code=")[1].split("&")[0]
    ac = await prov.load_authorization_code(c, code)
    return c, await prov.exchange_authorization_code(c, ac)


async def test_register_rejects_non_https(prov):
    with pytest.raises(RegistrationError):
        await prov.register_client(client(uris=("http://evil.example/cb",)))
    await prov.register_client(client(cid="loop", uris=("http://127.0.0.1:33418/cb",)))
    assert (await prov.get_client("loop")).client_name == "Claude"


async def test_authorize_goes_to_consent_and_pending_expires(prov, clock):
    c = client()
    await prov.register_client(c)
    url = await prov.authorize(c, params())
    assert url.startswith("http://testserver/consent?txn=")
    txn = url.split("txn=")[1]
    got_client, got_params = prov.get_pending(txn)
    assert got_client.client_id == "c1" and got_params.state == "st"
    clock[0] += 601
    assert prov.get_pending(txn) is None
    with pytest.raises(LookupError):
        prov.approve(txn)


async def test_authorize_rejects_foreign_resource(prov):
    c = client()
    await prov.register_client(c)
    with pytest.raises(AuthorizeError):
        await prov.authorize(c, params(resource="https://other.example/mcp"))


async def test_deny_redirects_with_error(prov):
    c = client()
    await prov.register_client(c)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    url = prov.deny(txn)
    assert url.startswith("https://claude.ai/api/mcp/auth_callback?")
    assert "error=access_denied" in url and "state=st" in url


async def test_code_single_use_and_tokens_work(prov):
    _, tok = await full_flow(prov)
    assert tok.expires_in == 3600 and tok.refresh_token
    at = await prov.load_access_token(tok.access_token)
    assert at is not None and at.client_id == "c1"
    assert await prov.verify_token(tok.access_token) is not None


async def test_code_cannot_be_reused(prov):
    c = client()
    await prov.register_client(c)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    code = prov.approve(txn).split("code=")[1].split("&")[0]
    ac = await prov.load_authorization_code(c, code)
    await prov.exchange_authorization_code(c, ac)
    assert await prov.load_authorization_code(c, code) is None
    with pytest.raises(TokenError):
        await prov.exchange_authorization_code(c, ac)


async def test_access_token_expires(prov, clock):
    _, tok = await full_flow(prov)
    clock[0] += 3601
    assert await prov.load_access_token(tok.access_token) is None


async def test_refresh_rotation_and_reuse_detection(prov):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    tok2 = await prov.exchange_refresh_token(c, rt, [])
    assert await prov.load_access_token(tok.access_token) is None  # old access revoked
    assert await prov.load_access_token(tok2.access_token) is not None
    # replaying the old refresh token revokes the whole family
    assert await prov.load_refresh_token(c, tok.refresh_token) is None
    assert await prov.load_access_token(tok2.access_token) is None
    assert await prov.load_refresh_token(c, tok2.refresh_token) is None


async def test_refresh_token_bound_to_client(prov):
    _, tok = await full_flow(prov)
    other = client(cid="c2")
    await prov.register_client(other)
    assert await prov.load_refresh_token(other, tok.refresh_token) is None


async def test_revoke(prov):
    c, tok = await full_flow(prov)
    at = await prov.load_access_token(tok.access_token)
    await prov.revoke_token(at)
    assert await prov.load_access_token(tok.access_token) is None
    assert await prov.load_refresh_token(c, tok.refresh_token) is None


async def test_api_keys(prov, db):
    key = prov.create_api_key("claude-code")
    assert key.startswith("prm_")
    assert db.one("SELECT count(*) FROM api_keys WHERE key_hash LIKE ?", (f"%{key}%",))[0] == 0
    at = await prov.load_access_token(key)
    assert at.client_id.startswith("apikey:")
    [row] = prov.list_api_keys()
    assert row.name == "claude-code" and row.prefix == key[:8]
    prov.revoke_api_key(row.id)
    assert await prov.load_access_token(key) is None
    assert await prov.load_access_token("prm_bogus") is None


async def test_admin_list_and_revoke_client(prov):
    _, tok = await full_flow(prov)
    [row] = prov.list_clients()
    assert row.client_id == "c1" and row.redirect_hosts == ["claude.ai"] and row.active_tokens == 2
    prov.revoke_client("c1")
    assert await prov.get_client("c1") is None
    assert await prov.load_access_token(tok.access_token) is None


async def test_purge_removes_stale_clients(prov, clock):
    await prov.register_client(client(cid="old"))
    clock[0] += 31 * 86400
    prov.purge()
    assert await prov.get_client("old") is None


# --- Additional security tests: rules the brief states but the tests above don't cover. ---


async def issue_code(prov, c=None, p=None):
    """Register (if needed), authorize and approve; return the client and the plaintext code."""
    c = c or client()
    if await prov.get_client(c.client_id) is None:
        await prov.register_client(c)
    txn = (await prov.authorize(c, p or params())).split("txn=")[1]
    return c, prov.approve(txn).split("code=")[1].split("&")[0]


def table_dump(db) -> str:
    tables = ("oauth_clients", "oauth_pending", "oauth_codes", "oauth_tokens", "api_keys")
    return "\n".join(
        " ".join(str(v) for v in tuple(r)) for t in tables for r in db.query(f"SELECT * FROM {t}")
    )


async def test_secrets_are_stored_only_as_hashes(prov, db):
    c, code = await issue_code(prov)
    assert db.one("SELECT code_hash FROM oauth_codes")[0] == hash_token(code)
    assert code not in table_dump(db)
    tok = await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))
    key = prov.create_api_key("k")
    dump = table_dump(db)
    for secret in (code, tok.access_token, tok.refresh_token, key):
        assert secret not in dump
    hashes = {r[0] for r in db.query("SELECT token_hash FROM oauth_tokens")}
    assert hashes == {hash_token(tok.access_token), hash_token(tok.refresh_token)}
    assert db.one("SELECT key_hash FROM api_keys")[0] == hash_token(key)


async def test_register_redirect_uri_rules(prov):
    good = [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "http://localhost:8765/cb",
        "http://127.0.0.1/cb",
        "http://[::1]:8080/cb",
    ]
    for i, uri in enumerate(good):
        await prov.register_client(client(cid=f"ok{i}", uris=(uri,)))
    bad = [
        ("https://example.com/cb",),  # https, but not an allowed host
        ("https://evilclaude.ai/cb",),
        ("https://sub.claude.ai/cb",),  # hosts match exactly: no implicit subdomains
        ("https://docs.claude.com/cb",),
        ("https://claude.ai.evil.example/cb",),
        ("https://claude.ai@evil.example/cb",),
        ("http://claude.ai/cb",),  # allowed host, but not https
        ("http://localhost.evil.example/cb",),
        ("http://127.0.0.1.evil.example/cb",),
        ("http://127.0.0.1@evil.example/cb",),
        ("ftp://claude.ai/cb",),
        ("myapp://callback",),
        ("https://claude.ai/cb#fragment",),
        ("https://claude.ai/cb", "https://evil.example/cb"),  # every URI must pass
        (),
    ]
    for i, uris in enumerate(bad):
        with pytest.raises(RegistrationError) as err:
            await prov.register_client(client(cid=f"bad{i}", uris=uris))
        assert err.value.error == "invalid_redirect_uri"
        assert await prov.get_client(f"bad{i}") is None


async def test_redirect_hosts_setting(settings, db):
    settings.oauth_redirect_hosts = " Example.com, ,other.example "
    assert settings.redirect_hosts == ("example.com", "other.example")
    prov = PostroomOAuthProvider(settings, db)
    await prov.register_client(client(cid="a", uris=("https://example.com/cb",)))
    await prov.register_client(client(cid="b", uris=("https://other.example/cb",)))
    await prov.register_client(client(cid="c", uris=("http://localhost:1234/cb",)))
    with pytest.raises(RegistrationError):
        await prov.register_client(client(cid="d", uris=("https://claude.ai/cb",)))
    with pytest.raises(RegistrationError):
        await prov.register_client(client(cid="e", uris=("https://x.other.example/cb",)))


def test_redirect_hosts_default(settings):
    assert settings.redirect_hosts == ("claude.ai", "claude.com")


async def tokened(prov, cid):
    """Register `cid` and run a full code exchange for it; return its tokens."""
    c, code = await issue_code(prov, client(cid=cid))
    return await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))


async def test_register_client_limit(prov, monkeypatch, clock):
    monkeypatch.setattr(provider_mod, "MAX_CLIENTS", 2)
    await tokened(prov, "a")
    await tokened(prov, "b")
    with pytest.raises(RegistrationError) as err:
        await prov.register_client(client(cid="c"))
    assert err.value.error == "invalid_client_metadata"
    clock[0] += 31 * 86400  # a and b go stale -> purge() makes room
    await prov.register_client(client(cid="c"))
    assert await prov.get_client("c") is not None


async def test_register_evicts_oldest_never_tokened_clients(prov, monkeypatch, clock):
    monkeypatch.setattr(provider_mod, "MAX_CLIENTS", 3)
    await tokened(prov, "t")
    clock[0] += 1
    await prov.register_client(client(cid="n1"))
    await prov.authorize(client(cid="n1"), params())  # leaves a pending row for n1
    clock[0] += 1
    await prov.register_client(client(cid="n2"))
    clock[0] += 1
    await prov.register_client(client(cid="new"))
    ids = {c.client_id for c in prov.list_clients()}
    assert ids == {"t", "n2", "new"}
    assert prov._db.one("SELECT count(*) FROM oauth_pending WHERE client_id='n1'")[0] == 0


async def test_register_fails_only_when_every_client_has_tokens(prov, monkeypatch):
    monkeypatch.setattr(provider_mod, "MAX_CLIENTS", 2)
    await tokened(prov, "a")
    await prov.register_client(client(cid="n"))
    await prov.register_client(client(cid="x"))  # evicts n
    assert {c.client_id for c in prov.list_clients()} == {"a", "x"}
    await tokened(prov, "x")
    with pytest.raises(RegistrationError) as err:
        await prov.register_client(client(cid="y"))
    assert err.value.error == "invalid_client_metadata"
    assert {c.client_id for c in prov.list_clients()} == {"a", "x"}


async def test_purge_drops_never_tokened_clients_after_a_day(prov, db, clock):
    await tokened(prov, "t")
    await prov.register_client(client(cid="n"))
    clock[0] += 23 * 3600
    prov.purge()
    assert await prov.get_client("n") is not None
    clock[0] += 2 * 3600
    prov.purge()
    assert await prov.get_client("n") is None
    assert await prov.get_client("t") is not None
    # a client whose tokens were all purged still counts as tokened (not a 24 h drop)
    db.execute("DELETE FROM oauth_tokens")
    db.execute("UPDATE oauth_clients SET last_used_at=?", (int(clock[0]),))
    prov.purge()
    assert await prov.get_client("t") is not None


async def test_code_replay_revokes_the_issued_token_family(prov, caplog):
    c, code = await issue_code(prov)
    ac = await prov.load_authorization_code(c, code)
    tok = await prov.exchange_authorization_code(c, ac)
    assert await prov.load_access_token(tok.access_token) is not None
    with caplog.at_level(logging.WARNING):
        assert await prov.load_authorization_code(c, code) is None
    assert "authorization code reuse" in caplog.text and code not in caplog.text
    assert await prov.load_access_token(tok.access_token) is None
    assert await prov.load_refresh_token(c, tok.refresh_token) is None


async def test_concurrent_code_exchange_revokes_the_family(prov):
    # Two exchanges that both passed load_authorization_code: the loser revokes the winner's
    # tokens, since a code presented twice means it leaked.
    c, code = await issue_code(prov)
    ac = await prov.load_authorization_code(c, code)
    tok = await prov.exchange_authorization_code(c, ac)
    with pytest.raises(TokenError):
        await prov.exchange_authorization_code(c, ac)
    assert await prov.load_access_token(tok.access_token) is None


async def test_code_replay_does_not_touch_other_families(prov):
    _, other = await full_flow(prov)
    c, code = await issue_code(prov)
    await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))
    await prov.load_authorization_code(c, code)
    assert await prov.load_access_token(other.access_token) is not None


async def test_used_code_tombstone_expires(prov, db, clock):
    c, code = await issue_code(prov)
    await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))
    assert db.one("SELECT count(*) FROM oauth_used_codes")[0] == 1
    assert code not in table_dump(db) + str(tuple(db.one("SELECT * FROM oauth_used_codes")))
    clock[0] += 301
    prov.purge()
    assert db.one("SELECT count(*) FROM oauth_used_codes")[0] == 0


async def test_authorize_accepts_own_resource_variants(prov):
    c = client()
    await prov.register_client(c)
    for resource in (None, "http://testserver/mcp/", "http://testserver", "http://testserver/"):
        url = await prov.authorize(c, params(resource=resource))
        assert url.startswith("http://testserver/consent?txn=")
    for resource in ("", "http://testserver/mcpx", "http://testserver.evil.example/mcp"):
        with pytest.raises(AuthorizeError) as err:
            await prov.authorize(c, params(resource=resource))
        assert err.value.error == "invalid_request"


async def test_pending_requests_are_capped_per_client(prov, db, monkeypatch):
    monkeypatch.setattr(provider_mod, "MAX_PENDING_PER_CLIENT", 3)
    c = client()
    await prov.register_client(c)
    txns = [(await prov.authorize(c, params())).split("txn=")[1] for _ in range(5)]
    assert db.one("SELECT count(*) FROM oauth_pending")[0] == 3
    assert prov.get_pending(txns[0]) is None and prov.get_pending(txns[1]) is None
    assert prov.get_pending(txns[-1]) is not None  # the newest request always survives


async def test_consent_txn_is_single_use(prov):
    c = client()
    await prov.register_client(c)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    prov.approve(txn)
    assert prov.get_pending(txn) is None
    with pytest.raises(LookupError):
        prov.approve(txn)
    with pytest.raises(LookupError):
        prov.deny(txn)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    prov.deny(txn)
    with pytest.raises(LookupError):
        prov.approve(txn)
    assert prov.get_pending("unknown") is None
    with pytest.raises(LookupError):
        prov.deny("unknown")


async def test_deny_expired_txn(prov, clock):
    c = client()
    await prov.register_client(c)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    clock[0] += 601
    with pytest.raises(LookupError):
        prov.deny(txn)


async def test_code_carries_approved_params(prov):
    c = client()
    await prov.register_client(c)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    redirect = prov.approve(txn)
    assert (
        redirect.startswith("https://claude.ai/api/mcp/auth_callback?") and "state=st" in redirect
    )
    code = redirect.split("code=")[1].split("&")[0]
    ac = await prov.load_authorization_code(c, code)
    assert ac.client_id == "c1" and ac.scopes == ["mcp"] and ac.code_challenge == CHALLENGE
    assert str(ac.redirect_uri) == "https://claude.ai/api/mcp/auth_callback"
    assert ac.redirect_uri_provided_explicitly and ac.subject == "owner"
    assert ac.resource == "http://testserver/mcp"


async def test_code_expires_and_is_bound_to_client(prov, clock):
    c, code = await issue_code(prov)
    other = client(cid="c2")
    await prov.register_client(other)
    assert await prov.load_authorization_code(other, code) is None
    ac = await prov.load_authorization_code(c, code)
    with pytest.raises(TokenError):
        await prov.exchange_authorization_code(other, ac)
    clock[0] += 301
    assert await prov.load_authorization_code(c, code) is None
    with pytest.raises(TokenError):
        await prov.exchange_authorization_code(c, ac)


async def test_refresh_token_expires(prov, clock):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    clock[0] += 30 * 86400 + 1
    assert await prov.load_refresh_token(c, tok.refresh_token) is None
    with pytest.raises(TokenError):
        await prov.exchange_refresh_token(c, rt, [])


async def test_refresh_exchange_is_single_use(prov):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    await prov.exchange_refresh_token(c, rt, [])
    with pytest.raises(TokenError):
        await prov.exchange_refresh_token(c, rt, [])


async def test_refresh_exchange_bound_to_client(prov):
    c, tok = await full_flow(prov)
    other = client(cid="c2")
    await prov.register_client(other)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    with pytest.raises(TokenError):
        await prov.exchange_refresh_token(other, rt, [])
    assert await prov.load_refresh_token(c, tok.refresh_token) is not None


async def test_refresh_scopes_cannot_widen(prov):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    tok2 = await prov.exchange_refresh_token(c, rt, ["admin"])
    assert tok2.scope == "mcp"
    assert (await prov.load_access_token(tok2.access_token)).scopes == ["mcp"]
    rt2 = await prov.load_refresh_token(c, tok2.refresh_token)
    tok3 = await prov.exchange_refresh_token(c, rt2, ["mcp"])
    assert tok3.scope == "mcp"


async def test_refreshed_tokens_keep_resource(prov):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    assert rt.resource == "http://testserver/mcp" and rt.subject == "owner"
    tok2 = await prov.exchange_refresh_token(c, rt, [])
    at = await prov.load_access_token(tok2.access_token)
    assert at.resource == "http://testserver/mcp" and at.subject == "owner"


async def test_reuse_revocation_is_limited_to_family(prov):
    c, tok_a = await full_flow(prov)
    _, code = await issue_code(prov, c)
    tok_b = await prov.exchange_authorization_code(c, await prov.load_authorization_code(c, code))
    rt = await prov.load_refresh_token(c, tok_a.refresh_token)
    await prov.exchange_refresh_token(c, rt, [])
    assert await prov.load_refresh_token(c, tok_a.refresh_token) is None  # reuse -> family A dead
    assert await prov.load_access_token(tok_b.access_token) is not None
    assert await prov.load_refresh_token(c, tok_b.refresh_token) is not None


async def test_reuse_detection_logs_without_secrets(prov, caplog):
    c, tok = await full_flow(prov)
    rt = await prov.load_refresh_token(c, tok.refresh_token)
    tok2 = await prov.exchange_refresh_token(c, rt, [])
    with caplog.at_level(logging.DEBUG):
        assert await prov.load_refresh_token(c, tok.refresh_token) is None
    assert "reuse" in caplog.text
    for secret in (tok.access_token, tok.refresh_token, tok2.access_token, tok2.refresh_token):
        assert secret not in caplog.text and hash_token(secret) not in caplog.text


async def test_access_token_resource_is_checked(prov, db):
    _, tok = await full_flow(prov)
    at = await prov.load_access_token(tok.access_token)
    assert at.resource == "http://testserver/mcp" and at.subject == "owner"
    h = hash_token(tok.access_token)
    db.execute(
        "UPDATE oauth_tokens SET resource=? WHERE token_hash=?", ("https://other.example/mcp", h)
    )
    assert await prov.load_access_token(tok.access_token) is None
    db.execute("UPDATE oauth_tokens SET resource=NULL WHERE token_hash=?", (h,))
    at = await prov.load_access_token(tok.access_token)
    assert at is not None and at.resource is None


async def test_token_kinds_are_not_interchangeable(prov):
    c, tok = await full_flow(prov)
    assert await prov.load_access_token(tok.refresh_token) is None
    assert await prov.load_refresh_token(c, tok.access_token) is None


async def test_revoke_by_refresh_token_and_unknown_is_noop(prov):
    c, tok = await full_flow(prov)
    await prov.revoke_token(AccessToken(token="unknown", client_id="c1", scopes=["mcp"]))
    assert await prov.load_access_token(tok.access_token) is not None
    await prov.revoke_token(await prov.load_refresh_token(c, tok.refresh_token))
    assert await prov.load_access_token(tok.access_token) is None
    assert await prov.load_refresh_token(c, tok.refresh_token) is None


async def test_oauth_tokens_never_use_api_key_prefix(prov, monkeypatch):
    c, code = await issue_code(prov)
    ac = await prov.load_authorization_code(c, code)
    real = provider_mod.new_token
    forced = iter(["prm_x1", "prm_x2", "prm_x3"])
    monkeypatch.setattr(
        provider_mod, "new_token", lambda prefix="": next(forced, None) or real(prefix)
    )
    tok = await prov.exchange_authorization_code(c, ac)
    assert not tok.access_token.startswith("prm_") and not tok.refresh_token.startswith("prm_")
    assert await prov.load_access_token(tok.access_token) is not None


async def test_api_key_last_used_is_throttled(prov, clock):
    key = prov.create_api_key("k")
    assert prov.list_api_keys()[0].last_used_at is None
    await prov.load_access_token(key)
    first = prov.list_api_keys()[0].last_used_at
    assert first == int(clock[0])
    clock[0] += 30
    await prov.load_access_token(key)
    assert prov.list_api_keys()[0].last_used_at == first
    clock[0] += 31
    await prov.load_access_token(key)
    assert prov.list_api_keys()[0].last_used_at == int(clock[0])


async def test_api_key_revocation_is_per_key(prov):
    k1, k2 = prov.create_api_key("one"), prov.create_api_key("two")
    assert k1 != k2
    r1, r2 = prov.list_api_keys()
    prov.revoke_api_key(r1.id)
    assert await prov.load_access_token(k1) is None
    assert await prov.load_access_token(k2) is not None
    r1, r2 = prov.list_api_keys()
    assert r1.revoked and not r2.revoked
    assert (await prov.load_access_token(k2)).client_id == f"apikey:{r2.id}"


async def test_api_key_is_not_revocable_via_oauth_revoke(prov):
    key = prov.create_api_key("k")
    await prov.revoke_token(await prov.load_access_token(key))
    assert await prov.load_access_token(key) is not None


async def test_get_client_touches_last_used_throttled(prov, clock):
    await prov.register_client(client())
    assert prov.list_clients()[0].last_used_at is None
    await prov.get_client("c1")
    assert prov.list_clients()[0].last_used_at == int(clock[0])
    clock[0] += 30
    await prov.get_client("c1")
    assert prov.list_clients()[0].last_used_at == int(clock[0]) - 30
    assert await prov.get_client("nope") is None


async def test_revoke_client_kills_outstanding_grants(prov):
    c, code = await issue_code(prov)
    txn = (await prov.authorize(c, params())).split("txn=")[1]
    prov.revoke_client("c1")
    assert await prov.load_authorization_code(c, code) is None
    assert prov.get_pending(txn) is None
    with pytest.raises(LookupError):
        prov.approve(txn)
    assert prov.list_clients() == []


async def test_purge_expired_rows_and_keeps_live_clients(prov, db, clock):
    c, tok = await full_flow(prov)
    await prov.authorize(c, params())  # leaves a pending row
    await issue_code(prov, c)  # leaves an unused code
    # stale by age, but it still holds live tokens -> kept
    db.execute(
        "UPDATE oauth_clients SET created_at=?, last_used_at=NULL", (int(clock[0]) - 31 * 86400,)
    )
    prov.purge()
    assert await prov.get_client("c1") is not None
    assert await prov.load_access_token(tok.access_token) is not None
    clock[0] += 601
    prov.purge()
    assert db.one("SELECT count(*) FROM oauth_pending")[0] == 0
    assert db.one("SELECT count(*) FROM oauth_codes")[0] == 0
    clock[0] += 32 * 86400  # every token expired more than a day ago; client idle > 30 days
    prov.purge()
    assert db.one("SELECT count(*) FROM oauth_tokens")[0] == 0
    assert await prov.get_client("c1") is None


# --- Storage bounds for the unauthenticated DCR and /authorize endpoints (final review I1). ---


async def test_register_stores_only_the_metadata_it_uses(prov, db):
    c = client()
    c.jwks = {"keys": [{"k": "x" * 100_000}]}
    c.logo_uri = AnyHttpUrl("https://evil.example/logo.png")
    c.client_uri = AnyHttpUrl("https://evil.example/")
    c.contacts = ["a@evil.example"] * 1000
    c.software_id = "s" * 10_000
    c.software_version = "v" * 10_000
    c.scope = " ".join(["mcp"] * 10_000)
    c.grant_types = ["authorization_code", "refresh_token"] + ["g" * 1000] * 100
    c.response_types = ["code"] + ["r" * 1000] * 100
    await prov.register_client(c)
    [stored] = db.query("SELECT info_json FROM oauth_clients")
    assert len(stored[0]) < 1000
    got = await prov.get_client("c1")
    assert got.client_name == "Claude" and got.scope == "mcp"
    assert [str(u) for u in got.redirect_uris] == ["https://claude.ai/api/mcp/auth_callback"]
    assert got.grant_types == ["authorization_code", "refresh_token"]
    assert got.response_types == ["code"] and got.token_endpoint_auth_method == "none"
    for field in ("jwks", "logo_uri", "client_uri", "contacts", "software_id", "software_version"):
        assert getattr(got, field) is None
        assert getattr(c, field) is None  # the registration response echoes what was stored


async def test_register_rejects_oversized_metadata(prov, db):
    long_uri = "https://claude.ai/api/mcp/auth_callback?" + "x" * 2000
    cases = [
        client(cid="name"),
        client(cid="many", uris=[f"https://claude.ai/cb{i}" for i in range(6)]),
        client(cid="long", uris=(long_uri,)),
    ]
    cases[0].client_name = "n" * 201
    for c in cases:
        with pytest.raises(RegistrationError) as err:
            await prov.register_client(c)
        assert err.value.error == "invalid_client_metadata"
    assert db.one("SELECT count(*) FROM oauth_clients")[0] == 0
    # The limits themselves are allowed.
    ok = client(cid="ok", uris=[f"https://claude.ai/cb{i}" for i in range(5)])
    ok.client_name = "n" * 200
    await prov.register_client(ok)
    assert (await prov.get_client("ok")).client_name == "n" * 200


async def test_authorize_bounds_stored_parameters(prov, db):
    c = client()
    await prov.register_client(c)
    for bad in (
        params(state="s" * 1001),
        params(challenge="c" * 100_000),
        params(challenge=CHALLENGE[:-1]),
        params(challenge=CHALLENGE[:-1] + "="),
    ):
        with pytest.raises(AuthorizeError) as err:
            await prov.authorize(c, bad)
        assert err.value.error == "invalid_request"
    assert db.one("SELECT count(*) FROM oauth_pending")[0] == 0
    await prov.authorize(c, params(state="s" * 1000))
    await prov.authorize(c, params(state=None))
    assert db.one("SELECT count(*) FROM oauth_pending")[0] == 2


async def test_list_clients_does_not_load_metadata_blobs(prov, db, clock):
    """Rows stored before the bounds existed (or by an older version) may be ~1 MB each; the
    admin page must not pull them all into memory at once."""
    import tracemalloc

    from mcp.shared.auth import OAuthClientInformationFull as Info

    for i in range(20):
        info = client(cid=f"big{i}", uris=[f"https://claude.ai/cb{j}" for j in range(50)])
        info.client_name = "N" * 100_000
        info.jwks = {"keys": ["k" * 1_000_000]}
        db.execute(
            "INSERT INTO oauth_clients(client_id, info_json, created_at) VALUES (?, ?, ?)",
            (info.client_id, Info.model_dump_json(info), int(clock[0]) - i),
        )
    tracemalloc.start()
    try:
        rows = prov.list_clients()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(rows) == 20 and peak < 2_000_000
    assert rows[0].client_id == "big0" and len(rows[0].client_name) == 200
    assert rows[0].redirect_hosts == ["claude.ai"]
