"""Background account checker and the maintenance loop.

Checks are fail2ban-safe: they go through `ImapPool.session`, so an account whose breaker
has tripped (`needs_reconnect` / `needs_google_connect`) is never logged into again unless
the owner explicitly asks (`manual=True`). Background checks run one account at a time and
back off from accounts in `error` for `ERROR_BACKOFF_SECONDS`.
"""

import asyncio
import logging
import time
from collections.abc import Callable

from postroom.accounts import AccountRepo, AccountStatus
from postroom.auth.provider import PostroomOAuthProvider
from postroom.google.oauth import GoogleOAuthError
from postroom.mail.imap import ImapError, ImapPool

log = logging.getLogger(__name__)

ERROR_BACKOFF_SECONDS = 300
_ELIGIBLE = (AccountStatus.PENDING, AccountStatus.CONNECTED, AccountStatus.ERROR)


class AccountChecker:
    # Maintenance tick: idle IMAP connections are closed this often; the first full check
    # runs one tick after start.
    tick_seconds: float = 60

    def __init__(self, repo: AccountRepo, pool: ImapPool, clock: Callable[[], float] = time.time):
        self.repo = repo
        self.pool = pool
        self.clock = clock

    async def check_account(self, email: str, manual: bool = False) -> AccountStatus:
        """Log in (or reuse the cached connection) and NOOP; the pool records the outcome."""

        def work() -> None:
            try:
                with self.pool.session(email, manual=manual) as c:
                    c.noop()
            except ImapError:
                pass  # the pool has stored the status/error (or the account is blocked/disabled)
            except GoogleOAuthError as e:
                # Google's token endpoint failed (network/5xx): not an auth failure, no breaker.
                self.repo.set_status(email, AccountStatus.ERROR, str(e))

        await asyncio.to_thread(work)
        account = self.repo.get(email)
        return account.status if account is not None else AccountStatus.ERROR

    def _eligible(self, background: bool) -> list[str]:
        now = self.clock()
        emails = []
        for acc in self.repo.list(include_disabled=False):
            if not acc.enabled or acc.status not in _ELIGIBLE:
                continue
            if (
                background
                and acc.status == AccountStatus.ERROR
                and acc.last_check_at is not None
                and now - acc.last_check_at < ERROR_BACKOFF_SECONDS
            ):
                continue
            emails.append(acc.email)
        return emails

    async def check_all(self, background: bool = True) -> dict[str, AccountStatus]:
        # Sequential on purpose: one login at a time is gentle on the upstream server.
        results: dict[str, AccountStatus] = {}
        for email in self._eligible(background):
            results[email] = await self.check_account(email, manual=False)
        return results

    async def run_maintenance(
        self, provider: PostroomOAuthProvider, interval: int, stop: asyncio.Event
    ) -> None:
        # Full checks run on tick 1 (60 s after start) and then every `interval` seconds.
        ticks_per_check = max(1, round(interval / self.tick_seconds))
        tick = 0
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.tick_seconds)
                break
            except TimeoutError:
                pass
            tick += 1
            try:
                await asyncio.to_thread(self.pool.close_idle)
            except Exception:
                log.exception("maintenance: closing idle IMAP connections failed")
            if (tick - 1) % ticks_per_check:
                continue
            try:
                results = await self.check_all()
                log.info(
                    "maintenance: checked %d account(s): %s",
                    len(results),
                    ", ".join(f"{e}={s.value}" for e, s in results.items()) or "-",
                )
            except Exception:
                log.exception("maintenance: account check failed")
            try:
                await asyncio.to_thread(provider.purge)
            except Exception:
                log.exception("maintenance: OAuth purge failed")
