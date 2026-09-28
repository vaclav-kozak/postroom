"""Public pages: root, robots.txt, health, static assets, owner login/logout and OAuth consent."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.resources
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from importlib.resources.abc import Traversable
from typing import TYPE_CHECKING
from urllib.parse import quote, urlparse

import jinja2
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)

from postroom.accounts import MailAccess
from postroom.auth.owner import client_ip, safe_next
from postroom.web.security import ROBOTS_TXT

if TYPE_CHECKING:
    from postroom.app import Services

log = logging.getLogger(__name__)

templates = jinja2.Environment(
    loader=jinja2.PackageLoader("postroom.web", "templates"),
    autoescape=True,
)


@jinja2.pass_context
def _format_ts(ctx: jinja2.runtime.Context, value: int | None) -> str:
    """A Unix time as local time in the page's `tz` (the server's POSTROOM_TIMEZONE)."""
    if not value:
        return "—"
    tz: tzinfo = ctx.get("tz") or UTC
    return datetime.fromtimestamp(value, tz).strftime("%Y-%m-%d %H:%M")


templates.filters["ts"] = _format_ts

# ----- static assets ------------------------------------------------------------------------
# Everything under `static/` is read into memory once at import: a fixed map from path to bytes,
# so a request can never reach outside it (no path traversal, no filesystem access per request).
# Only known file types are served. Pages reference assets as `/static/<path>?v=<ASSET_VERSION>`,
# and a versioned URL (or a font, whose file name already pins its face) is cached for a year.

_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
}
LONG_CACHE = "public, max-age=31536000, immutable"
SHORT_CACHE = "public, max-age=3600"


@dataclass(frozen=True)
class StaticAsset:
    body: bytes
    media_type: str


def _walk(node: Traversable, prefix: str = "") -> dict[str, StaticAsset]:
    found: dict[str, StaticAsset] = {}
    for child in sorted(node.iterdir(), key=lambda c: c.name):
        path = f"{prefix}{child.name}"
        if child.is_dir():
            found.update(_walk(child, path + "/"))
            continue
        suffix = "." + child.name.rsplit(".", 1)[-1] if "." in child.name else ""
        if suffix in _CONTENT_TYPES:
            found[path] = StaticAsset(child.read_bytes(), _CONTENT_TYPES[suffix])
    return found


STATIC: dict[str, StaticAsset] = _walk(importlib.resources.files("postroom.web") / "static")
ASSET_VERSION = hashlib.sha256(
    b"".join(name.encode() + b"\0" + a.body for name, a in STATIC.items())
).hexdigest()[:12]
templates.globals["asset_v"] = ASSET_VERSION

EXPIRED_TXN = "Authorization request expired — start again from Claude."


def render(name: str, status: int = 200, **ctx) -> HTMLResponse:
    ctx.setdefault("owner", False)
    ctx.setdefault("csrf", "")
    resp = HTMLResponse(templates.get_template(name).render(**ctx), status_code=status)
    # Pages can carry CSRF tokens, consent details or a fresh API key: never cache them.
    resp.headers["Cache-Control"] = "no-store"
    return resp


def message_page(
    services: Services, request: Request, title: str, message: str, status: int, **ctx
) -> HTMLResponse:
    owner = services.owner.is_owner(request)
    return render(
        "message.html",
        status=status,
        title=title,
        message=message,
        owner=owner,
        csrf=services.owner.csrf_token(request) if owner else "",
        **ctx,
    )


async def form_data(request: Request) -> dict[str, str]:
    """Form fields as plain strings (file uploads and repeated keys are ignored)."""
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


def login_redirect(request: Request) -> RedirectResponse:
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(f"/login?next={quote(target, safe='')}", status_code=302)


def _accounts(n: int) -> str:
    return f"{n} account" if n == 1 else f"{n} accounts"


def consent_grants(accounts) -> dict[str, str]:
    """What an approved client may do, per the owner's current account settings (enabled
    accounts only; the levels can change later in the admin UI)."""
    total = len(accounts)
    organize = sum(1 for a in accounts if a.allows(MailAccess.ORGANIZE))
    send = sum(1 for a in accounts if a.can_send)
    return {
        "read": f"Read and search mail and save drafts in {_accounts(total)}.",
        "organize": (
            "Organize mail (mark read, star, move, archive, trash, create folders) in "
            + ("all of them." if organize == total else f"{organize} of them.")
            if organize
            else "Organizing mail is not enabled on any account."
        ),
        "send": (
            f"Sending is enabled on {_accounts(send)}: it can send email as you there."
            if send
            else "Sending is not enabled on any account."
        ),
        "pim": "Use calendars, tasks and contacts where they are connected.",
    }


def register_pages(mcp: FastMCP, services: Services) -> None:
    owner = services.owner
    # Login attempts are strictly serialized: the lockout check, the argon2 verify and the
    # recording of the result happen under one lock. Otherwise concurrent guesses all pass the
    # check before any failure is recorded (lockout bypass), and parallel argon2 verifies (64 MiB
    # each) could exhaust the container's memory.
    login_lock = asyncio.Lock()

    @mcp.custom_route("/", methods=["GET"], include_in_schema=False)
    async def root(request: Request) -> Response:
        return RedirectResponse("/admin" if owner.is_owner(request) else "/login", status_code=302)

    @mcp.custom_route("/robots.txt", methods=["GET"], include_in_schema=False)
    async def robots(request: Request) -> Response:
        return PlainTextResponse(ROBOTS_TXT)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/static/{path:path}", methods=["GET"], include_in_schema=False)
    async def static(request: Request) -> Response:
        path = request.path_params["path"]
        asset = STATIC.get(path)
        if asset is None:
            return PlainTextResponse("Not found", status_code=404)
        versioned = request.query_params.get("v") == ASSET_VERSION
        long_lived = versioned or path.startswith("fonts/")
        return Response(
            asset.body,
            media_type=asset.media_type,
            headers={"Cache-Control": LONG_CACHE if long_lived else SHORT_CACHE},
        )

    @mcp.custom_route("/favicon.ico", methods=["GET"], include_in_schema=False)
    async def favicon(request: Request) -> Response:
        # Browsers probe /favicon.ico even with a <link rel=icon>; point them at the SVG.
        return RedirectResponse(f"/static/favicon.svg?v={ASSET_VERSION}", status_code=301)

    # ----- login / logout -----------------------------------------------------------------

    def login_page(request: Request, status: int, next_: str, error: str | None) -> Response:
        cookie_carrier = Response()
        token = owner.ensure_pre_token(request, cookie_carrier)
        resp = render("login.html", status=status, csrf=token, next=next_, error=error)
        for name, value in cookie_carrier.raw_headers:
            if name == b"set-cookie":
                resp.raw_headers.append((name, value))
        return resp

    @mcp.custom_route("/login", methods=["GET"], include_in_schema=False)
    async def login_get(request: Request) -> Response:
        next_ = safe_next(request.query_params.get("next"))
        if owner.is_owner(request):
            return RedirectResponse(next_, status_code=302)
        return login_page(request, 200, next_, None)

    @mcp.custom_route("/login", methods=["POST"], include_in_schema=False)
    async def login_post(request: Request) -> Response:
        form = await form_data(request)
        next_ = safe_next(form.get("next"))
        if not owner.check_csrf(request, form.get("csrf")):
            return message_page(
                services,
                request,
                "Session expired",
                "The login form expired. Please try again.",
                400,
                link="/login",
                link_text="Back to login",
            )
        ip = client_ip(request)
        password = form.get("password", "")
        async with login_lock:
            blocked = owner.guard.blocked_for(ip)
            if blocked <= 0:
                ok = await asyncio.to_thread(owner.check_password, password)
                owner.guard.record(ip, ok)
        if blocked > 0:
            minutes = max(1, math.ceil(blocked / 60))
            log.warning("login blocked ip=%s", ip)
            return login_page(
                request, 429, next_, f"Too many attempts, try again in {minutes} minutes."
            )
        if not ok:
            log.warning("login failed ip=%s", ip)
            return login_page(request, 401, next_, "Wrong password.")
        resp = RedirectResponse(next_, status_code=303)
        owner.start_session(resp)
        owner.clear_pre_token(resp)
        return resp

    @mcp.custom_route("/logout", methods=["POST"], include_in_schema=False)
    async def logout(request: Request) -> Response:
        form = await form_data(request)
        if not owner.check_csrf(request, form.get("csrf")):
            return message_page(
                services, request, "Forbidden", "Invalid or missing form token.", 403
            )
        if owner.is_owner(request):  # a pre-login CSRF token must not log the owner out
            owner.revoke_sessions()
        resp = RedirectResponse("/login", status_code=303)
        owner.end_session(resp)
        return resp

    # ----- consent --------------------------------------------------------------------------

    @mcp.custom_route("/consent", methods=["GET"], include_in_schema=False)
    async def consent_get(request: Request) -> Response:
        if not owner.is_owner(request):
            return login_redirect(request)
        txn = request.query_params.get("txn", "")
        pending = services.provider.get_pending(txn) if txn else None
        if pending is None:
            return message_page(services, request, "Request expired", EXPIRED_TXN, 400)
        client, params = pending
        redirect_uri = str(params.redirect_uri)
        return render(
            "consent.html",
            owner=True,
            csrf=owner.csrf_token(request),
            txn=txn,
            client_name=client.client_name,
            client_id=client.client_id,
            redirect_host=urlparse(redirect_uri).hostname or redirect_uri,
            redirect_uri=redirect_uri,
            scopes=" ".join(params.scopes or ["mcp"]),
            grants=consent_grants(services.repo.list(include_disabled=False)),
        )

    @mcp.custom_route("/consent", methods=["POST"], include_in_schema=False)
    async def consent_post(request: Request) -> Response:
        form = await form_data(request)
        if not owner.is_owner(request) or not owner.check_csrf(request, form.get("csrf")):
            return message_page(
                services, request, "Forbidden", "Invalid session or form token.", 403
            )
        txn = form.get("txn", "")
        action = form.get("action")
        if action not in ("allow", "deny") or not txn:
            return message_page(services, request, "Bad request", "Unknown action.", 400)
        try:
            target = (
                services.provider.approve(txn) if action == "allow" else services.provider.deny(txn)
            )
        except LookupError:
            return message_page(services, request, "Request expired", EXPIRED_TXN, 400)
        return RedirectResponse(target, status_code=303)
