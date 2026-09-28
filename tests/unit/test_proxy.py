import argparse
import base64
from ipaddress import ip_network

import httpx
import pytest

from postroom import cli
from postroom.config import Settings
from postroom.web.proxy import ClientAddressMiddleware, parse_ip

TRUSTED = [ip_network("10.0.0.0/8"), ip_network("fd00::/8")]


def make_app(seen: dict):
    async def app(scope, receive, send):
        seen["client"] = scope["client"][0]
        seen["scheme"] = scope["scheme"]
        seen["headers"] = [(k.decode(), v.decode()) for k, v in scope["headers"]]
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    return app


async def call(peer: str, headers: dict | list | None = None) -> dict:
    seen: dict = {}
    mw = ClientAddressMiddleware(make_app(seen), TRUSTED)
    transport = httpx.ASGITransport(app=mw, client=(peer, 5555))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await c.get("/", headers=headers)
    return seen


def real_ips(seen: dict) -> list[str]:
    return [v for k, v in seen["headers"] if k == "x-real-ip"]


async def test_untrusted_peer_cannot_spoof():
    seen = await call(
        "203.0.113.7",
        {
            "X-Forwarded-For": "198.51.100.1",
            "X-Real-IP": "198.51.100.2",
            "X-Forwarded-Proto": "https",
            "Forwarded": "for=198.51.100.3",
        },
    )
    assert seen["client"] == "203.0.113.7"
    assert real_ips(seen) == ["203.0.113.7"]
    assert seen["scheme"] == "http"
    names = {k for k, _ in seen["headers"]}
    assert not names & {"x-forwarded-for", "x-forwarded-proto", "forwarded"}


async def test_trusted_proxy_forwarded_for():
    seen = await call("10.1.2.3", {"X-Forwarded-For": "198.51.100.1", "X-Forwarded-Proto": "https"})
    assert seen["client"] == "198.51.100.1"
    assert real_ips(seen) == ["198.51.100.1"]
    assert seen["scheme"] == "https"


async def test_client_supplied_forwarded_for_entries_are_skipped():
    # The proxy appended the real peer; the left entries came from the client.
    seen = await call("10.1.2.3", {"X-Forwarded-For": "1.2.3.4, 198.51.100.1, 10.9.9.9"})
    assert seen["client"] == "198.51.100.1"


async def test_forwarded_for_wins_over_client_x_real_ip():
    seen = await call("10.1.2.3", {"X-Forwarded-For": "198.51.100.1", "X-Real-IP": "1.2.3.4"})
    assert seen["client"] == "198.51.100.1" and real_ips(seen) == ["198.51.100.1"]


async def test_trusted_proxy_x_real_ip_only():
    seen = await call("10.1.2.3", {"X-Real-IP": "198.51.100.9"})
    assert seen["client"] == "198.51.100.9"


async def test_trusted_proxy_without_headers_or_with_garbage():
    assert (await call("10.1.2.3"))["client"] == "10.1.2.3"
    seen = await call("10.1.2.3", {"X-Forwarded-For": "not-an-ip"})
    assert seen["client"] == "10.1.2.3"
    seen = await call("10.1.2.3", {"X-Real-IP": "evil<script>"})
    assert seen["client"] == "10.1.2.3"


async def test_all_hops_trusted_uses_leftmost():
    seen = await call("10.1.2.3", {"X-Forwarded-For": "10.0.0.5, 10.0.0.6"})
    assert seen["client"] == "10.0.0.5"


async def test_ipv6_and_mapped_ipv4():
    seen = await call("fd00::1", {"X-Forwarded-For": "2001:db8::7"})
    assert seen["client"] == "2001:db8::7"
    seen = await call("::ffff:10.1.2.3", {"X-Forwarded-For": "198.51.100.1"})
    assert seen["client"] == "198.51.100.1"


def test_parse_ip():
    assert str(parse_ip(" [2001:db8::1] ")) == "2001:db8::1"
    assert str(parse_ip("::ffff:192.0.2.1")) == "192.0.2.1"
    assert parse_ip("unknown") is None


def test_trusted_proxies_setting(settings):
    assert [str(n) for n in settings.trusted_proxy_networks] == ["127.0.0.1/32", "::1/128"]
    settings.trusted_proxies = " 172.16.0.0/12, ,fc00::/7 "
    assert [str(n) for n in settings.trusted_proxy_networks] == ["172.16.0.0/12", "fc00::/7"]
    settings.trusted_proxies = "nonsense"
    with pytest.raises(ValueError):
        settings.trusted_proxy_networks  # noqa: B018


async def test_app_ignores_forwarding_headers_from_untrusted_peer(settings):
    from postroom.app import build_services, create_app

    settings.public_url = "http://localhost"
    settings.trusted_proxies = "10.0.0.0/8"
    app = create_app(settings, build_services(settings))
    transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 1))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://localhost") as c,
    ):
        # Each request claims a new address, yet all of them share the peer's bucket.
        for i in range(10):
            r = await c.post("/login", headers={"X-Real-IP": f"198.51.100.{i}"})
            assert r.status_code != 429
        r = await c.post("/login", headers={"X-Forwarded-For": "198.51.100.99"})
        assert r.status_code == 429


def test_serve_disables_uvicorn_proxy_headers(monkeypatch):
    import uvicorn

    import postroom.app

    calls = {}
    monkeypatch.setattr(postroom.app, "create_app", lambda: "app")
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.update(kw))
    cli._cmd_serve(argparse.Namespace(host="127.0.0.1", port=8000))
    assert calls["proxy_headers"] is False
    assert "forwarded_allow_ips" not in calls


def test_settings_default():
    s = Settings(master_key=base64.b64encode(bytes(32)).decode(), session_secret="y")
    assert s.auth_rate_limit_per_minute == 10
