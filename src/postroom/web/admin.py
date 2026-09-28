"""Owner admin UI: accounts (incoming and outgoing mail, access level), Google connect,
API keys and OAuth clients.

Every route requires the owner session (else 302 to /login); every POST also requires the
session's CSRF token (else 403). Flash messages come only from the fixed `MESSAGES` map.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastmcp import FastMCP
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from postroom.accounts import Account, AccountStatus, MailAccess, Provider, SmtpStatus
from postroom.crypto import SecretError, new_token, pkce_pair
from postroom.google.oauth import GoogleOAuthError
from postroom.mail.imap import ImapError
from postroom.mail.smtp import SmtpError
from postroom.web.pages import form_data, login_redirect, message_page, render

if TYPE_CHECKING:
    from postroom.app import Services

log = logging.getLogger(__name__)

MESSAGES = {
    "account_added": "Account added.",
    "account_updated": "Account updated.",
    "account_toggled": "Account updated.",
    "account_removed": "Account removed.",
    "confirm_mismatch": "Type the account email to confirm removal.",
    "check_ok": "Connection OK.",
    "check_failed": "Connection failed — see the account's last error.",
    "check_smtp_failed": "Incoming mail OK, but the SMTP test failed — see the account's SMTP error.",
    "google_disabled": "Google OAuth is not configured.",
    "google_denied": "Google authorization was cancelled.",
    "google_connected": "Google account connected.",
    "key_revoked": "API key revoked.",
    "client_revoked": "Client access revoked.",
    "key_name_invalid": "API key name must be 1–60 characters.",
}

GSTATE_COOKIE = "postroom_gstate"
GSTATE_MAX_AGE = 600
GSTATE_PATH = "/admin/google"
IMPORT_COMMAND = (
    "docker compose exec -T postroom postroom import-emclient - --passphrase-first-line"
    " < export-with-passphrase.txt"
)
MAX_FIELD = 320
ACCESS_LEVELS = [
    (MailAccess.READ.value, "Read", "Search and read mail, and create drafts."),
    (
        MailAccess.ORGANIZE.value,
        "Organize",
        "Also mark read or unread, star, move, archive, trash, and create folders.",
    ),
    (MailAccess.FULL.value, "Full", "Also send mail (needs an outgoing mail server)."),
]
DEFAULT_SMTP_PORTS = {"ssl": "465", "starttls": "587"}


def _host_ok(host: str) -> bool:
    return bool(host) and not any(ch.isspace() or ch in "/@:?#" for ch in host)


def _port_ok(port: str) -> bool:
    return port.isdigit() and 1 <= int(port) <= 65535


def _dav_url_ok(url: str) -> bool:
    """DAV calls send the mailbox password as Basic auth: https only (http on loopback)."""
    try:
        parts = urlparse(url)
        host = parts.hostname
    except ValueError:
        return False
    if not host:
        return False
    return parts.scheme == "https" or (
        parts.scheme == "http" and host in ("localhost", "127.0.0.1", "::1")
    )


@dataclass
class AccountForm:
    email: str = ""
    display_name: str = ""
    imap_host: str = ""
    imap_port: str = "993"
    imap_security: str = "ssl"
    imap_username: str = ""
    caldav_url: str = ""
    carddav_url: str = ""
    smtp_host: str = ""
    smtp_port: str = "465"
    smtp_security: str = "ssl"
    smtp_username: str = ""
    mail_access: str = MailAccess.FULL.value

    @classmethod
    def from_form(
        cls, form: dict[str, str], mail_access: str = MailAccess.FULL.value
    ) -> AccountForm:
        """`mail_access` is used when the form has no access level (e.g. an older page)."""

        def get(name: str, default: str = "") -> str:
            return form.get(name, default).strip()[:MAX_FIELD]

        smtp_security = get("smtp_security", "ssl")
        return cls(
            email=get("email").lower(),
            display_name=get("display_name"),
            imap_host=get("imap_host").lower(),
            imap_port=get("imap_port"),
            imap_security=get("imap_security"),
            imap_username=get("imap_username"),
            caldav_url=get("caldav_url"),
            carddav_url=get("carddav_url"),
            smtp_host=get("smtp_host").lower(),
            smtp_port=get("smtp_port") or DEFAULT_SMTP_PORTS.get(smtp_security, ""),
            smtp_security=smtp_security,
            smtp_username=get("smtp_username"),
            mail_access=get("mail_access") or mail_access,
        )

    @classmethod
    def from_account(cls, a: Account) -> AccountForm:
        return cls(
            email=a.email,
            display_name=a.display_name or "",
            imap_host=a.imap_host or "",
            imap_port=str(a.imap_port or 993),
            imap_security=a.imap_security or "ssl",
            imap_username=a.imap_username or "",
            caldav_url=a.caldav_url or "",
            carddav_url=a.carddav_url or "",
            smtp_host=a.smtp_host or "",
            smtp_port=str(a.smtp_port or DEFAULT_SMTP_PORTS.get(a.smtp_security or "ssl")),
            smtp_security=a.smtp_security or "ssl",
            smtp_username=a.smtp_username or "",
            mail_access=a.mail_access.value,
        )

    def validate(self, password: str, password_required: bool) -> str | None:
        email = self.email
        if (
            "@" not in email
            or email.startswith("@")
            or email.endswith("@")
            or any(ch.isspace() for ch in email)
        ):
            return "Enter a valid email address."
        if not _host_ok(self.imap_host):
            return "Enter the IMAP server host name."
        if not _port_ok(self.imap_port):
            return "Port must be a number between 1 and 65535."
        if self.imap_security not in ("ssl", "starttls"):
            return "Security must be SSL or STARTTLS."
        if self.smtp_host:
            if not _host_ok(self.smtp_host):
                return "Enter the SMTP server host name, or leave it empty to disable sending."
            if not _port_ok(self.smtp_port):
                return "SMTP port must be a number between 1 and 65535."
            if self.smtp_security not in ("ssl", "starttls"):
                return "SMTP security must be SSL/TLS or STARTTLS."
            if any(ch.isspace() or ord(ch) < 32 for ch in self.smtp_username):
                return "The SMTP username must not contain spaces."
        if self.mail_access not in {level.value for level in MailAccess}:
            return "Choose an access level."
        if password_required and not password:
            return "Enter the password."
        for url in (self.caldav_url, self.carddav_url):
            if url and not _dav_url_ok(url):
                return "CalDAV/CardDAV URLs must be https URLs (http only on localhost)."
        return None

    def to_account(self, provider: Provider = Provider.IMAP) -> Account:
        """A transient account for the pre-save test login (never stored)."""
        return Account(
            id=0,
            email=self.email,
            display_name=self.display_name or None,
            provider=provider,
            imap_host=self.imap_host,
            imap_port=int(self.imap_port),
            imap_security=self.imap_security,
            imap_username=self.imap_username or None,
            caldav_url=self.caldav_url or None,
            carddav_url=self.carddav_url or None,
            has_secret=True,
            enabled=True,
            status=AccountStatus.PENDING,
            last_error=None,
            last_ok_at=None,
            last_check_at=None,
            mail_access=MailAccess(self.mail_access),
            smtp_host=self.smtp_host or None,
            smtp_port=int(self.smtp_port) if self.smtp_host else None,
            smtp_security=self.smtp_security if self.smtp_host else None,
            smtp_username=self.smtp_username or None if self.smtp_host else None,
        )

    def save_outgoing(self, repo, email: str) -> None:
        """Store the SMTP settings and the access level (the IMAP ones go through upsert)."""
        repo.set_smtp(
            email,
            host=self.smtp_host or None,
            port=int(self.smtp_port) if self.smtp_host else None,
            security=self.smtp_security,
            username=self.smtp_username or None,
        )
        repo.set_mail_access(email, self.mail_access)


def _safe_error(e: Exception) -> str:
    """Error text for the owner. IMAP/Google messages are written to be secret-free."""
    safe = (ImapError, GoogleOAuthError, SmtpError)
    text = str(e) if isinstance(e, safe) else f"{type(e).__name__}: {e}"
    return text[:300]


def register_admin(mcp: FastMCP, services: Services) -> None:
    owner = services.owner
    settings = services.settings
    gstate = URLSafeTimedSerializer(settings.session_secret, salt="postroom-google")

    Handler = Callable[..., Awaitable[Response]]

    def owner_get(path: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            async def endpoint(request: Request) -> Response:
                if not owner.is_owner(request):
                    return login_redirect(request)
                return await fn(request)

            mcp.custom_route(path, methods=["GET"], include_in_schema=False)(endpoint)
            return fn

        return deco

    def owner_post(path: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            async def endpoint(request: Request) -> Response:
                if not owner.is_owner(request):
                    return login_redirect(request)
                form = await form_data(request)
                if not owner.check_csrf(request, form.get("csrf")):
                    return message_page(
                        services, request, "Forbidden", "Invalid or missing form token.", 403
                    )
                return await fn(request, form)

            mcp.custom_route(path, methods=["POST"], include_in_schema=False)(endpoint)
            return fn

        return deco

    def page(request: Request, name: str, status: int = 200, **ctx) -> Response:
        return render(name, status=status, owner=True, csrf=owner.csrf_token(request), **ctx)

    def back(msg: str) -> RedirectResponse:
        return RedirectResponse(f"/admin?msg={msg}", status_code=303)

    def not_found(request: Request) -> Response:
        return message_page(services, request, "Not found", "No such account.", 404)

    def account_by_id(request: Request) -> Account | None:
        return services.repo.get_by_id(request.path_params["id"])

    def form_page(
        request: Request, f: AccountForm, account: Account | None, error: str | None, status: int
    ) -> Response:
        return page(
            request,
            "account_form.html",
            status=status,
            f=f,
            account=account,
            error=error,
            access_levels=ACCESS_LEVELS,
        )

    def google_page(
        request: Request, account: Account, f: AccountForm, error: str | None, status: int
    ) -> Response:
        return page(
            request,
            "account_google.html",
            status=status,
            f=f,
            account=account,
            error=error,
            access_levels=ACCESS_LEVELS,
            google_enabled=services.google is not None,
        )

    async def test_login(f: AccountForm, password: str) -> str | None:
        """One login + logout with the submitted settings; returns an error text or None."""

        def work() -> None:
            client = services.pool.connector.connect(f.to_account(), password)
            try:
                client.logout()
            except Exception:  # noqa: BLE001, S110 -- the login itself succeeded
                pass

        try:
            await asyncio.to_thread(work)
        except Exception as e:  # noqa: BLE001 -- any failure is shown to the owner
            return f"Test login failed — {_safe_error(e)}"
        if f.smtp_host:
            # One SMTP login + QUIT with the submitted settings; nothing is sent.
            try:
                await asyncio.to_thread(
                    services.mail.smtp.connector.check, f.to_account(), password
                )
            except Exception as e:  # noqa: BLE001 -- any failure is shown to the owner
                return f"SMTP test failed — {_safe_error(e)}"
        return None

    def saved(f: AccountForm, email: str) -> None:
        f.save_outgoing(services.repo, email)
        if f.smtp_host:
            services.repo.set_smtp_status(email, SmtpStatus.OK)  # just tested

    # ----- overview ---------------------------------------------------------------------------

    @owner_get("/admin")
    async def admin_home(request: Request) -> Response:
        return page(
            request,
            "admin.html",
            flash=MESSAGES.get(request.query_params.get("msg", "")),
            accounts=services.repo.list(),
            clients=services.provider.list_clients(),
            api_keys=[k for k in services.provider.list_api_keys() if not k.revoked],
            mcp_url=settings.mcp_url,
            import_command=IMPORT_COMMAND,
            google_enabled=services.google is not None,
        )

    # ----- accounts ---------------------------------------------------------------------------

    @owner_get("/admin/accounts/new")
    async def account_new(request: Request) -> Response:
        return form_page(request, AccountForm(), None, None, 200)

    @owner_post("/admin/accounts")
    async def account_create(request: Request, form: dict[str, str]) -> Response:
        f = AccountForm.from_form(form)
        password = form.get("password", "")
        error = f.validate(password, password_required=True)
        if error:
            return form_page(request, f, None, error, 400)
        existing = services.repo.get(f.email)
        if existing is not None:
            return RedirectResponse(f"/admin/accounts/{existing.id}/edit", status_code=303)
        error = await test_login(f, password)
        if error:
            return form_page(request, f, None, error, 200)
        services.repo.upsert(
            email=f.email,
            provider=Provider.IMAP,
            display_name=f.display_name or None,
            imap_host=f.imap_host,
            imap_port=int(f.imap_port),
            imap_security=f.imap_security,
            imap_username=f.imap_username or None,
            caldav_url=f.caldav_url or None,
            carddav_url=f.carddav_url or None,
            secret=password,
            status=AccountStatus.CONNECTED,
        )
        saved(f, f.email)
        services.repo.set_status(f.email, AccountStatus.CONNECTED)
        services.pool.drop(f.email)
        return back("account_added")

    @owner_get("/admin/accounts/{id:int}/edit")
    async def account_edit(request: Request) -> Response:
        account = account_by_id(request)
        if account is None:
            return not_found(request)
        if account.provider == Provider.GOOGLE:
            return google_page(request, account, AccountForm.from_account(account), None, 200)
        return form_page(request, AccountForm.from_account(account), account, None, 200)

    @owner_post("/admin/accounts/{id:int}")
    async def account_update(request: Request, form: dict[str, str]) -> Response:
        account = account_by_id(request)
        if account is None:
            return not_found(request)
        if account.provider == Provider.GOOGLE:
            return await google_update(request, account, form)
        f = AccountForm.from_form(form, mail_access=account.mail_access.value)
        f.email = account.email  # the email is the account's identity; never renamed here
        password = form.get("password", "")
        error = f.validate(password, password_required=False)
        if error:
            return form_page(request, f, account, error, 400)
        if not password:
            try:
                password = services.repo.get_secret(account.email) or ""
            except SecretError:
                password = ""
            if not password:
                return form_page(request, f, account, "No password stored — enter it.", 400)
        error = await test_login(f, password)
        if error:
            return form_page(request, f, account, error, 200)
        services.repo.upsert(
            email=account.email,
            provider=Provider.IMAP,
            display_name=f.display_name,
            imap_host=f.imap_host,
            imap_port=int(f.imap_port),
            imap_security=f.imap_security,
            imap_username=f.imap_username,
            caldav_url=f.caldav_url,
            carddav_url=f.carddav_url,
            secret=password,
            status=AccountStatus.CONNECTED,
        )
        saved(f, account.email)
        services.repo.set_status(account.email, AccountStatus.CONNECTED)
        services.pool.drop(account.email)
        return back("account_updated")

    async def google_update(request: Request, account: Account, form: dict[str, str]) -> Response:
        """Google accounts: only the display name and the access level are editable (the
        servers and the sign-in come from Google; use Reconnect to sign in again)."""
        display_name = form.get("display_name", "").strip()[:MAX_FIELD]
        level = form.get("mail_access", "").strip() or account.mail_access.value
        if level not in {m.value for m in MailAccess}:
            f = AccountForm.from_account(account)
            f.display_name, f.mail_access = display_name, level
            return google_page(request, account, f, "Choose an access level.", 400)
        services.repo.set_display_name(account.email, display_name)
        services.repo.set_mail_access(account.email, level)
        return back("account_updated")

    @owner_post("/admin/accounts/{id:int}/test")
    async def account_test(request: Request, form: dict[str, str]) -> Response:
        """The owner's check: one IMAP login + NOOP, then, when the account has an outgoing
        server, one SMTP login + QUIT (never a message). The background checker never
        tests SMTP, to keep failed logins on the mail server to a minimum."""
        account = account_by_id(request)
        if account is None:
            return not_found(request)
        status = await services.check_account(account.email, True)
        if status != AccountStatus.CONNECTED:
            return back("check_failed")
        if account.smtp_host or account.can_send:
            error = await asyncio.to_thread(services.mail.smtp.check, account.email)
            if error is not None:
                return back("check_smtp_failed")
        return back("check_ok")

    @owner_post("/admin/accounts/{id:int}/toggle")
    async def account_toggle(request: Request, form: dict[str, str]) -> Response:
        account = account_by_id(request)
        if account is None:
            return not_found(request)
        services.repo.set_enabled(account.email, not account.enabled)
        services.pool.drop(account.email)
        return back("account_toggled")

    @owner_post("/admin/accounts/{id:int}/delete")
    async def account_delete(request: Request, form: dict[str, str]) -> Response:
        account = account_by_id(request)
        if account is None:
            return not_found(request)
        if form.get("confirm", "").strip().lower() != account.email:
            return back("confirm_mismatch")
        if account.provider == Provider.GOOGLE and services.google is not None:
            try:
                secret = services.repo.get_secret(account.email)
            except SecretError:
                secret = None
            if secret:
                await asyncio.to_thread(services.google.revoke, secret)
            services.google.invalidate(account.email)
        services.pool.drop(account.email)
        services.repo.delete(account.email)
        return back("account_removed")

    # ----- Google -----------------------------------------------------------------------------

    def clear_gstate(resp: Response) -> None:
        resp.delete_cookie(
            GSTATE_COOKIE,
            path=GSTATE_PATH,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )

    @owner_get("/admin/google/connect")
    async def google_connect(request: Request) -> Response:
        google = services.google
        if google is None:
            return back("google_disabled")
        login_hint = None
        account_id = request.query_params.get("account_id", "")
        if account_id.isdigit():
            account = services.repo.get_by_id(int(account_id))
            login_hint = account.email if account is not None else None
        state = new_token()
        verifier, challenge = pkce_pair()
        sid = owner.session(request)["sid"]
        resp = RedirectResponse(
            google.authorization_url(state, challenge, login_hint=login_hint), status_code=302
        )
        resp.set_cookie(
            GSTATE_COOKIE,
            gstate.dumps({"state": state, "verifier": verifier, "sid": sid}),
            max_age=GSTATE_MAX_AGE,
            path=GSTATE_PATH,
            secure=settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )
        return resp

    def load_gstate(request: Request) -> dict | None:
        raw = request.cookies.get(GSTATE_COOKIE)
        if not raw:
            return None
        try:
            data = gstate.loads(raw, max_age=GSTATE_MAX_AGE)
        except BadSignature:  # includes SignatureExpired
            return None
        if not isinstance(data, dict) or not all(
            isinstance(data.get(k), str) and data.get(k) for k in ("state", "verifier", "sid")
        ):
            return None
        return data

    @owner_get("/admin/google/callback")
    async def google_callback(request: Request) -> Response:
        google = services.google
        if google is None:
            return back("google_disabled")
        if request.query_params.get("error"):
            resp = back("google_denied")
            clear_gstate(resp)
            return resp
        data = load_gstate(request)
        state = request.query_params.get("state", "")
        code = request.query_params.get("code", "")
        sid = owner.session(request)["sid"]
        if (
            data is None
            or not code
            or not hmac.compare_digest(data["state"].encode(), state.encode())
            or not hmac.compare_digest(data["sid"].encode(), sid.encode())
        ):
            return message_page(
                services,
                request,
                "Google connection failed",
                "The Google sign-in expired or did not match this browser session. "
                "Start again from the admin page.",
                400,
                link="/admin",
                link_text="Back to admin",
            )
        try:
            grant = await asyncio.to_thread(google.exchange_code, code, data["verifier"])
        except GoogleOAuthError as e:
            resp = message_page(
                services, request, "Google connection failed", str(e), 400, link="/admin"
            )
            clear_gstate(resp)
            return resp
        services.repo.upsert(
            email=grant.email,
            provider=Provider.GOOGLE,
            imap_host="imap.gmail.com",
            imap_port=993,
            imap_security="ssl",
            secret=grant.refresh_token,
            status=AccountStatus.PENDING,
        )
        google.invalidate(grant.email)
        services.pool.drop(grant.email)
        await services.check_account(grant.email, True)
        resp = back("google_connected")
        clear_gstate(resp)
        return resp

    # ----- API keys + OAuth clients -----------------------------------------------------------

    @owner_post("/admin/api-keys")
    async def api_key_create(request: Request, form: dict[str, str]) -> Response:
        name = form.get("name", "").strip()
        if not 1 <= len(name) <= 60:
            return back("key_name_invalid")
        key = services.provider.create_api_key(name)
        return page(
            request, "api_key_created.html", key=key, key_name=name, mcp_url=settings.mcp_url
        )

    @owner_post("/admin/api-keys/{id:int}/revoke")
    async def api_key_revoke(request: Request, form: dict[str, str]) -> Response:
        services.provider.revoke_api_key(request.path_params["id"])
        return back("key_revoked")

    @owner_post("/admin/clients/{client_id}/revoke")
    async def client_revoke(request: Request, form: dict[str, str]) -> Response:
        services.provider.revoke_client(request.path_params["client_id"])
        return back("client_revoked")
