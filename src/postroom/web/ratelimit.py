"""In-memory per-client-IP rate limit for the authentication endpoints.

Covers the owner login, OAuth dynamic client registration, authorization and token endpoints
(brute force, DCR spam, global-lockout DoS). A token bucket per IP: `burst` requests at once,
refilled at `per_minute`. Excess requests get 429 with `Retry-After`.

Memory is bounded: buckets idle long enough to be full again are dropped (a fresh bucket is
identical), and the table never holds more than `max_clients` entries (least recently used
first out). The client IP is `scope["client"]`, as resolved by `ClientAddressMiddleware`.
Pure ASGI middleware, so nothing is buffered.
"""

import math
import time
from collections import OrderedDict
from collections.abc import Callable

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_BURST = 10
DEFAULT_MAX_CLIENTS = 10_000

LIMITED: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/login"),
        ("POST", "/register"),
        ("GET", "/authorize"),
        ("POST", "/authorize"),
        ("POST", "/token"),
    }
)


class TokenBucketLimiter:
    def __init__(
        self,
        per_minute: int,
        burst: int = DEFAULT_BURST,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if per_minute <= 0 or burst <= 0 or max_clients <= 0:
            raise ValueError("per_minute, burst and max_clients must be positive")
        self.rate = per_minute / 60.0  # tokens per second
        self.burst = float(burst)
        self.max_clients = max_clients
        self._clock = clock
        # key -> (tokens, last update); ordered by last update, oldest first.
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._buckets)

    def _evict_idle(self, now: float) -> None:
        refill_time = self.burst / self.rate
        while self._buckets:
            key, (_, last) = next(iter(self._buckets.items()))
            if now - last < refill_time:
                break
            del self._buckets[key]

    def acquire(self, key: str) -> float:
        """Take one token for `key`. Returns 0 if allowed, else the seconds until one is free."""
        now = self._clock()
        self._evict_idle(now)
        tokens, last = self._buckets.pop(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens >= 1:
            tokens -= 1
            wait = 0.0
        else:
            wait = (1 - tokens) / self.rate
        self._buckets[key] = (tokens, now)
        while len(self._buckets) > self.max_clients:
            self._buckets.popitem(last=False)
        return wait


class AuthRateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        per_minute: int,
        burst: int = DEFAULT_BURST,
        max_clients: int = DEFAULT_MAX_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.app = app
        self.limiter = (
            TokenBucketLimiter(per_minute, burst, max_clients, clock) if per_minute > 0 else None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            self.limiter is not None
            and scope["type"] == "http"
            and (scope["method"], scope["path"]) in LIMITED
        ):
            client = scope.get("client")
            wait = self.limiter.acquire(client[0] if client else "unknown")
            if wait > 0:
                response = PlainTextResponse(
                    "Too many requests. Try again later.\n",
                    status_code=429,
                    headers={"Retry-After": str(max(1, math.ceil(wait)))},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
