"""Security headers for every HTTP response, plus the robots.txt body.

Pure ASGI middleware (wraps `send`), never `BaseHTTPMiddleware`, which would buffer and
break the streaming MCP responses.
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ROBOTS_TXT = "User-agent: *\nDisallow: /\n"

# No `form-action`: Chrome applies it to the redirect after the consent POST, which goes to the
# OAuth client's own redirect URI (another origin).
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Robots-Tag", "noindex, nofollow, noarchive"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers") or [])
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    if name not in headers:
                        headers.append(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)
