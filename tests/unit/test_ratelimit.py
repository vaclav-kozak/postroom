import base64

import httpx
import pytest

from postroom.app import build_services, create_app
from postroom.crypto import hash_password
from postroom.web.ratelimit import AuthRateLimitMiddleware, TokenBucketLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_burst_then_refill_at_rate():
    clock = Clock()
    limiter = TokenBucketLimiter(per_minute=10, burst=10, clock=clock)
    assert all(limiter.acquire("a") == 0 for _ in range(10))
    wait = limiter.acquire("a")
    assert wait == pytest.approx(6.0)  # 10/min: one token every 6 s
    clock.now += 5.9
    assert limiter.acquire("a") > 0
    clock.now += 0.2
    assert limiter.acquire("a") == 0
    assert limiter.acquire("a") > 0


def test_denied_requests_do_not_consume_tokens():
    clock = Clock()
    limiter = TokenBucketLimiter(per_minute=60, burst=1, clock=clock)
    assert limiter.acquire("a") == 0
    for _ in range(50):
        assert limiter.acquire("a") > 0
    clock.now += 1.0
    assert limiter.acquire("a") == 0


def test_buckets_are_per_key():
    limiter = TokenBucketLimiter(per_minute=10, burst=2, clock=Clock())
    assert limiter.acquire("a") == 0 and limiter.acquire("a") == 0
    assert limiter.acquire("a") > 0
    assert limiter.acquire("b") == 0


def test_idle_buckets_are_evicted():
    clock = Clock()
    limiter = TokenBucketLimiter(per_minute=10, burst=10, clock=clock)
    for i in range(100):
        limiter.acquire(f"10.0.0.{i}")
    assert len(limiter) == 100
    clock.now += 60  # 10 tokens at 10/min: every bucket is full again
    limiter.acquire("192.0.2.1")
    assert len(limiter) == 1


def test_table_size_is_capped_lru():
    limiter = TokenBucketLimiter(per_minute=10, burst=1, max_clients=3, clock=Clock())
    for key in ("a", "b", "c"):
        limiter.acquire(key)
    limiter.acquire("a")  # a becomes most recently used
    limiter.acquire("d")  # evicts b
    assert len(limiter) == 3
    assert limiter.acquire("a") > 0 and limiter.acquire("c") > 0
    assert limiter.acquire("b") == 0  # fresh bucket


def test_invalid_parameters():
    with pytest.raises(ValueError):
        TokenBucketLimiter(per_minute=0)


async def _ok(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _client(app, ip="203.0.113.5") -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 1234)), base_url="http://t"
    )


async def test_middleware_limits_only_auth_endpoints():
    app = AuthRateLimitMiddleware(_ok, per_minute=10, burst=2, clock=Clock())
    async with _client(app) as c:
        assert (await c.post("/login")).status_code == 200
        assert (await c.get("/authorize")).status_code == 200
        r = await c.post("/token")
        assert r.status_code == 429 and r.headers["retry-after"] == "6"
        # Not limited: other paths and methods.
        assert (await c.get("/login")).status_code == 200
        assert (await c.post("/mcp")).status_code == 200
        assert (await c.get("/healthz")).status_code == 200
    async with _client(app, ip="203.0.113.6") as c:
        assert (await c.post("/register")).status_code == 200


async def test_middleware_disabled_with_zero():
    app = AuthRateLimitMiddleware(_ok, per_minute=0)
    async with _client(app) as c:
        for _ in range(50):
            assert (await c.post("/login")).status_code == 200


PASSWORD = "correct horse battery staple"


@pytest.fixture
async def app(settings):
    settings.public_url = "http://localhost"
    settings.admin_password_hash_b64 = base64.b64encode(hash_password(PASSWORD).encode()).decode()
    app = create_app(settings, build_services(settings))
    async with app.router.lifespan_context(app):
        yield app


async def test_app_rate_limits_login_per_client_ip(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost"
    ) as c:
        statuses = [(await c.post("/login", data={"password": "x"})).status_code for _ in range(10)]
        assert 429 not in statuses
        r = await c.post("/login", data={"password": "x"})
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) >= 1
        assert r.headers["x-content-type-options"] == "nosniff"  # security headers still apply
        # Another client (via the trusted loopback proxy) has its own bucket.
        r = await c.post("/login", data={"password": "x"}, headers={"X-Real-IP": "192.0.2.1"})
        assert r.status_code != 429
