"""Per-account login locks that keep parallel calls from multiplying failed logins.

mailcow's fail2ban bans the server's IP after 10 failed logins in 10 minutes, counted
across IMAP and SOGo (CalDAV/CardDAV) and across all accounts. The circuit breaker
(`needs_reconnect`) stops further logins once one has failed, but only for calls that
start after it tripped. So every call that logs in to an account's mail server holds that
account's lock and re-reads the account's status after acquiring it:

- the IMAP pool holds it around `connect()` (a cached session needs no new login);
- every CalDAV/CardDAV call holds it for the whole call, since each call logs in afresh
  (`PimService` also queues those calls per account in asyncio, so waiting for a turn
  does not tie up a worker thread).

A wrong password therefore costs exactly one failed login per account, however many
IMAP and DAV calls are in flight when it is noticed.
"""

import threading


class LoginLocks:
    def __init__(self):
        self._accounts: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def account(self, email: str) -> threading.Lock:
        """The lock serialising logins to `email`'s mail server (IMAP and DAV)."""
        key = email.strip().lower()
        with self._guard:
            lock = self._accounts.get(key)
            if lock is None:
                lock = self._accounts[key] = threading.Lock()
            return lock
