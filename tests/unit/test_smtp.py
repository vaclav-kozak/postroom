"""The SMTP client: connect / TLS / login paths, transmission, error mapping, and the
sender's fail2ban care (login lock, auth-failure breaker, no retry). smtplib is faked."""

import base64
import smtplib
import threading
from typing import ClassVar

import pytest

from postroom.accounts import AccountStatus, Provider, SmtpStatus
from postroom.login_locks import LoginLocks
from postroom.mail.imap import AuthFailed
from postroom.mail.smtp import (
    CONNECT_TIMEOUT,
    SmtpAuthFailed,
    SmtpConnector,
    SmtpError,
    SmtpMaybeSent,
    SmtpRejected,
    SmtpSender,
    SmtpUnavailable,
)

A, G = "user@example.com", "me@gmail.com"
PASSWORD = "s3cret-pass"


class FakeSMTP:
    """Records what the client does; behaviour is set per test through class attributes.

    AUTH is answered like a real server (PLAIN with an initial response; LOGIN as three
    steps) and every attempt is recorded as one ("auth", mechanism, credentials) call, so
    tests can count failed logins. DATA is recorded as ("data", the bytes on the wire)."""

    instances: ClassVar[list["FakeSMTP"]] = []
    extensions: ClassVar[dict[str, str]] = {
        "starttls": "",
        "auth": "PLAIN LOGIN XOAUTH2",
        "8bitmime": "",
    }
    auth_reply = (235, b"2.7.0 accepted")
    connect_error: Exception | None = None
    mail_reply = (250, b"2.1.0 ok")
    rcpt_replies: ClassVar[dict[str, tuple[int, bytes]]] = {}
    data_cmd_reply = (354, b"go ahead")
    data_result: object = (250, b"2.0.0 queued")

    def __init__(self, host, port, local_hostname=None, timeout=None, context=None):
        if self.connect_error is not None:
            raise self.connect_error
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.local_hostname = local_hostname
        self.calls: list[tuple] = []
        self.esmtp_features = dict(self.extensions)
        self.sock = None
        self._login_steps: list[str] | None = None
        self._wire: list[bytes] | None = None
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append(("ehlo",))

    def has_extn(self, name):
        return name.lower() in self.esmtp_features

    def starttls(self, context=None):
        self.calls.append(("starttls", context))

    def login(self, user, password):
        raise AssertionError("smtplib's login() tries every mechanism; it must not be used")

    def auth(self, mechanism, authobject, initial_response_ok=True):
        self.calls.append(("auth", mechanism, authobject()))
        if self.auth_reply[0] != 235:
            raise smtplib.SMTPAuthenticationError(*self.auth_reply)

    def docmd(self, cmd, args=""):
        if cmd.upper() == "DATA":
            if self.data_cmd_reply[0] == 354:
                self._wire = []
            return self.data_cmd_reply
        if cmd.upper() == "AUTH" and args.startswith("PLAIN "):
            self.calls.append(("auth", "PLAIN", base64.b64decode(args[6:])))
            return self.auth_reply
        if cmd.upper() == "AUTH" and args == "LOGIN":
            self._login_steps = []
            return (334, b"VXNlcm5hbWU6")
        if self._login_steps is not None:
            self._login_steps.append(base64.b64decode(cmd).decode())
            if len(self._login_steps) == 1:
                return (334, b"UGFzc3dvcmQ6")
            self.calls.append(("auth", "LOGIN", self._login_steps))
            self._login_steps = None
            return self.auth_reply
        self.calls.append(("docmd", cmd, args))
        return (250, b"ok")

    def send(self, data):
        assert self._wire is not None, "send() outside DATA"
        self._wire.append(bytes(data))

    def getreply(self):
        wire, self._wire = b"".join(self._wire or []), None
        self.calls.append(("data", wire))
        if isinstance(self.data_result, Exception):
            raise self.data_result
        return self.data_result

    def mail(self, sender, options=()):
        self.calls.append(("mail", sender, list(options)))
        return self.mail_reply

    def rcpt(self, addr, options=()):
        self.calls.append(("rcpt", addr))
        return self.rcpt_replies.get(addr, (250, b"2.1.5 ok"))

    def rset(self):
        self.calls.append(("rset",))

    def quit(self):
        self.calls.append(("quit",))

    def close(self):
        self.calls.append(("close",))

    def names(self):
        return [c[0] for c in self.calls]


class FakeSMTPSSL(FakeSMTP):
    pass


@pytest.fixture(autouse=True)
def reset_fake():
    """Each test sets behaviour on the fake classes; restore it afterwards."""
    saved = {
        cls: {k: v for k, v in vars(cls).items() if not k.startswith("__")}
        for cls in (FakeSMTP, FakeSMTPSSL)
    }
    FakeSMTP.instances = []
    yield
    for cls, attrs in saved.items():
        for k in [k for k in vars(cls) if not k.startswith("__") and k not in attrs]:
            delattr(cls, k)
        for k, v in attrs.items():
            setattr(cls, k, v)
    FakeSMTP.instances = []


def connector(**kw):
    return SmtpConnector(smtp_class=FakeSMTP, smtp_ssl_class=FakeSMTPSSL, **kw)


@pytest.fixture
def accounts(repo):
    repo.upsert(
        email=A,
        provider=Provider.IMAP,
        imap_host="imap.example.com",
        imap_port=993,
        imap_security="ssl",
        secret=PASSWORD,
        status=AccountStatus.CONNECTED,
        smtp_host="smtp.example.com",
    )
    repo.upsert(email=G, provider=Provider.GOOGLE, status=AccountStatus.CONNECTED)


def last() -> FakeSMTP:
    return FakeSMTP.instances[-1]


# -- connector ---------------------------------------------------------------------------


def test_ssl_login_then_quit(repo, accounts):
    connector().check(repo.get(A), PASSWORD)
    s = last()
    assert isinstance(s, FakeSMTPSSL)
    assert (s.host, s.port, s.timeout) == ("smtp.example.com", 465, CONNECT_TIMEOUT)
    assert s.context is not None  # certificate-verifying default context
    assert s.names() == ["ehlo", "auth", "quit"]
    assert s.calls[1] == ("auth", "PLAIN", b"\0" + A.encode() + b"\0" + PASSWORD.encode())


def test_starttls_and_a_separate_username(repo, accounts):
    repo.set_smtp(A, host="mail.example.com", port=587, security="starttls", username="u1")
    connector(local_hostname="postroom.example.org").check(repo.get(A), PASSWORD)
    s = last()
    assert type(s) is FakeSMTP and s.port == 587
    assert s.local_hostname == "postroom.example.org"
    assert s.names() == ["ehlo", "starttls", "ehlo", "auth", "quit"]
    assert s.calls[1][1] is not None
    assert s.calls[3] == ("auth", "PLAIN", b"\0u1\0" + PASSWORD.encode())


def test_starttls_not_offered_is_refused_before_login(repo, accounts):
    repo.set_smtp(A, host="mail.example.com", port=587, security="starttls")
    FakeSMTP.extensions = {"auth": "PLAIN"}
    with pytest.raises(SmtpError, match="does not offer STARTTLS"):
        connector().check(repo.get(A), PASSWORD)
    assert "auth" not in last().names() and "quit" in last().names()


def test_auth_failure_is_mapped_without_the_password(repo, accounts):
    FakeSMTPSSL.auth_reply = (535, b"5.7.8 bad credentials")
    with pytest.raises(SmtpAuthFailed) as e:
        connector().check(repo.get(A), PASSWORD)
    assert "535 5.7.8 bad credentials" in str(e.value)
    assert PASSWORD not in str(e.value)
    assert last().names()[-1] == "quit"


def test_connect_failure_names_the_server(repo, accounts):
    FakeSMTPSSL.connect_error = ConnectionRefusedError(111, "refused")
    with pytest.raises(SmtpError, match="could not connect to smtp.example.com:465"):
        connector().check(repo.get(A), PASSWORD)


def test_non_ascii_password_uses_utf8_auth_plain(repo, accounts):
    pw = "heslo-žluťoučký"
    connector().check(repo.get(A), pw)
    (call,) = [c for c in last().calls if c[0] == "auth"]
    assert call == ("auth", "PLAIN", b"\0" + A.encode() + b"\0" + pw.encode())


def test_login_mechanism_when_plain_is_not_offered(repo, accounts):
    FakeSMTP.extensions = {"auth": "CRAM-MD5 LOGIN"}
    connector().check(repo.get(A), "heslo-č")
    (call,) = [c for c in last().calls if c[0] == "auth"]
    assert call == ("auth", "LOGIN", [A, "heslo-č"])


def test_no_supported_mechanism_is_a_clear_error(repo, accounts):
    FakeSMTP.extensions = {"auth": "CRAM-MD5 GSSAPI"}
    with pytest.raises(SmtpError, match="AUTH CRAM-MD5 GSSAPI; PLAIN or LOGIN is needed"):
        connector().check(repo.get(A), PASSWORD)
    assert "auth" not in last().names()


def test_a_wrong_password_costs_exactly_one_auth_attempt(repo, accounts):
    """smtplib's login() would try PLAIN, then LOGIN (and CRAM-MD5): two or three failed
    logins per attempt on a mailcow server, which fail2ban counts."""
    FakeSMTP.extensions = {"auth": "CRAM-MD5 PLAIN LOGIN"}
    FakeSMTPSSL.auth_reply = (535, b"5.7.8 bad credentials")
    s = sender(repo)
    with pytest.raises(SmtpAuthFailed):
        s.send(A, A, ["b@example.org"], b"x\r\n")
    with pytest.raises(SmtpUnavailable):
        s.send(A, A, ["b@example.org"], b"x\r\n")
    attempts = [c for i in FakeSMTP.instances for c in i.calls if c[0] == "auth"]
    assert len(attempts) == 1


def test_temporary_auth_failure_does_not_pause_sending(repo, accounts):
    FakeSMTPSSL.auth_reply = (454, b"4.7.0 Temporary authentication failure")
    s = sender(repo)
    with pytest.raises(SmtpError, match="temporary authentication failure") as e:
        s.send(A, A, ["b@example.org"], b"x\r\n")
    assert not isinstance(e.value, SmtpAuthFailed)
    assert repo.get(A).smtp_status == SmtpStatus.ERROR
    FakeSMTPSSL.auth_reply = (235, b"2.7.0 ok")
    s.send(A, A, ["b@example.org"], b"x\r\n")  # not paused


def test_non_ascii_password_rejected(repo, accounts):
    FakeSMTPSSL.auth_reply = (535, b"5.7.8 nope")
    with pytest.raises(SmtpAuthFailed, match="535"):
        connector().check(repo.get(A), "pässword")


def test_gmail_uses_xoauth2_with_the_imap_token(repo, accounts):
    asked = []

    def token(email):
        asked.append(email)
        return "ya29.token"

    connector(google_token=token).check(repo.get(G), None)
    s = last()
    assert isinstance(s, FakeSMTPSSL) and (s.host, s.port) == ("smtp.gmail.com", 465)
    assert asked == [G]
    (auth,) = [c for c in s.calls if c[0] == "auth"]
    assert auth[1] == "XOAUTH2"
    assert auth[2] == f"user={G}\x01auth=Bearer ya29.token\x01\x01"
    assert len([c for c in s.calls if c[0] == "auth"]) == 1


def test_gmail_refused_token_is_refreshed_once_and_never_pauses(repo, accounts):
    tokens = iter(["ya29.stale", "ya29.fresh", "ya29.third"])
    dropped = []

    def token(email):
        return next(tokens)

    FakeSMTPSSL.auth_reply = (535, b"5.7.8 Username and Password not accepted")
    c = connector(google_token=token, google_invalidate=dropped.append)
    s = SmtpSender(repo, c, LoginLocks())
    with pytest.raises(SmtpError, match="fresh access token too") as e:
        s.send(G, G, ["b@example.org"], b"x\r\n")
    assert not isinstance(e.value, SmtpAuthFailed)
    assert dropped == [G]
    bearer = [c[2] for i in FakeSMTP.instances for c in i.calls if c[0] == "auth"]
    assert [b.split("Bearer ")[1].split("\x01")[0] for b in bearer] == ["ya29.stale", "ya29.fresh"]
    assert repo.get(G).smtp_status == SmtpStatus.ERROR  # not auth_failed: not paused

    # A stale token that works once refreshed: the send goes through.
    FakeSMTP.instances = []
    tokens2 = iter(["ya29.stale", "ya29.fresh"])

    class OnlyFresh(FakeSMTPSSL):
        def auth(self, mechanism, authobject, initial_response_ok=True):
            self.calls.append(("auth", mechanism, authobject()))
            if "stale" in self.calls[-1][2]:
                raise smtplib.SMTPAuthenticationError(535, b"5.7.8 expired")

    c = SmtpConnector(
        google_token=lambda e: next(tokens2),
        google_invalidate=dropped.append,
        smtp_ssl_class=OnlyFresh,
    )
    assert SmtpSender(repo, c, LoginLocks()).send(G, G, ["b@example.org"], b"x\r\n").refused == {}
    assert repo.get(G).smtp_status == SmtpStatus.OK


def test_gmail_token_failure_is_an_smtp_error(repo, accounts):
    def token(email):
        raise AuthFailed("Google access was revoked")

    with pytest.raises(SmtpError, match="revoked"):
        connector(google_token=token).check(repo.get(G), None)
    assert FakeSMTP.instances == []  # no connection without a token


def test_unconfigured_account_is_refused(repo, accounts):
    repo.set_smtp(A, host="")
    with pytest.raises(SmtpError, match="not configured"):
        connector().check(repo.get(A), PASSWORD)


# -- transmit ------------------------------------------------------------------------------


def smtp_session():
    s = FakeSMTP("h", 25)
    s.calls.clear()
    return s


def test_transmit_sends_the_bytes_as_given():
    s = smtp_session()
    raw = b"From: a@example.com\r\nTo: b@example.org\r\n\r\nhi\r\n"
    out = SmtpConnector.transmit(s, A, ["b@example.org", "c@example.org"], raw)
    assert out.refused == {}
    assert s.calls == [
        ("mail", A, []),
        ("rcpt", "b@example.org"),
        ("rcpt", "c@example.org"),
        ("data", raw + b".\r\n"),
    ]


def test_data_dot_stuffs_lines_that_start_with_a_dot():
    s = smtp_session()
    raw = b".starts\r\nmid\r\n.\r\n..two\r\nend"
    SmtpConnector.transmit(s, A, ["b@example.org"], raw)
    assert s.calls[-1] == ("data", b"..starts\r\nmid\r\n..\r\n...two\r\nend\r\n.\r\n")
    assert smtplib._quote_periods(raw) + b"\r\n.\r\n" == s.calls[-1][1]


def test_transmit_8bit_uses_8bitmime():
    s = smtp_session()
    SmtpConnector.transmit(s, A, ["b@example.org"], "Subject: č\r\n\r\nž\r\n".encode())
    assert s.calls[0] == ("mail", A, ["BODY=8BITMIME"])


def test_partial_recipient_refusal_is_reported():
    s = smtp_session()
    FakeSMTP.rcpt_replies = {"bad@example.org": (550, b"5.1.1 no such user")}
    out = SmtpConnector.transmit(s, A, ["bad@example.org", "ok@example.org"], b"x\r\n")
    assert out.refused == {"bad@example.org": "550 5.1.1 no such user"}
    assert "data" in s.names()


def test_every_recipient_refused_sends_nothing():
    s = smtp_session()
    FakeSMTP.rcpt_replies = {"bad@example.org": (550, b"5.7.1 relaying denied")}
    with pytest.raises(SmtpRejected, match="550 5.7.1 relaying denied"):
        SmtpConnector.transmit(s, A, ["bad@example.org"], b"x\r\n")
    assert "data" not in s.names() and "rset" in s.names()


def test_sender_refused():
    s = smtp_session()
    FakeSMTP.mail_reply = (553, b"5.7.1 sender not owned by user")
    with pytest.raises(SmtpRejected, match=f"refused the sender {A}: 553 5.7.1"):
        SmtpConnector.transmit(s, A, ["b@example.org"], b"x\r\n")
    assert "rcpt" not in s.names()


def test_data_refused_is_a_rejection():
    s = smtp_session()
    FakeSMTP.data_cmd_reply = (554, b"5.6.0 message refused")
    with pytest.raises(SmtpRejected, match="554 5.6.0 message refused"):
        SmtpConnector.transmit(s, A, ["b@example.org"], b"x\r\n")


def test_data_final_reply_not_250_is_a_rejection():
    s = smtp_session()
    FakeSMTP.data_result = (552, b"5.3.4 message too big")
    with pytest.raises(SmtpRejected, match="552 5.3.4"):
        SmtpConnector.transmit(s, A, ["b@example.org"], b"x\r\n")


def test_connection_lost_during_data_may_have_sent():
    s = smtp_session()
    FakeSMTP.data_result = smtplib.SMTPServerDisconnected("Connection unexpectedly closed")
    with pytest.raises(SmtpMaybeSent, match="may or may not have been sent"):
        SmtpConnector.transmit(s, A, ["b@example.org"], b"x\r\n")


def test_size_limit_is_checked_before_mail_from():
    s = smtp_session()
    s.esmtp_features["size"] = "100"
    with pytest.raises(SmtpRejected, match="larger than the SMTP server accepts"):
        SmtpConnector.transmit(s, A, ["b@example.org"], b"x" * 200)
    assert s.calls == []


def test_non_ascii_address_needs_smtputf8():
    s = smtp_session()
    with pytest.raises(SmtpRejected, match="non-ASCII"):
        SmtpConnector.transmit(s, A, ["žofie@example.org"], b"x\r\n")
    s.esmtp_features["smtputf8"] = ""
    SmtpConnector.transmit(s, A, ["žofie@example.org"], b"x\r\n")
    assert ("mail", A, ["SMTPUTF8"]) in s.calls


# -- sender: lock, breaker, bookkeeping ----------------------------------------------------


def sender(repo, **kw):
    return SmtpSender(repo, connector(**kw), LoginLocks())


def test_send_logs_in_transmits_and_records_ok(repo, accounts):
    out = sender(repo).send(A, A, ["b@example.org"], b"x\r\n")
    assert out.refused == {}
    assert last().names() == ["ehlo", "auth", "mail", "rcpt", "data", "quit"]
    assert repo.get(A).smtp_status == SmtpStatus.OK


def test_auth_failure_pauses_sending_until_a_manual_test(repo, accounts):
    s = sender(repo)
    FakeSMTPSSL.auth_reply = (535, b"5.7.8 bad credentials")
    with pytest.raises(SmtpAuthFailed):
        s.send(A, A, ["b@example.org"], b"x\r\n")
    acc = repo.get(A)
    assert acc.smtp_status == SmtpStatus.AUTH_FAILED and "535" in acc.smtp_error
    assert acc.status == AccountStatus.CONNECTED  # IMAP is untouched
    count = len(FakeSMTP.instances)
    with pytest.raises(SmtpUnavailable, match="sending is paused"):
        s.send(A, A, ["b@example.org"], b"x\r\n")
    assert len(FakeSMTP.instances) == count  # no second failed login
    # The owner's Test now logs in again; once it works, sending resumes.
    FakeSMTPSSL.auth_reply = (235, b"2.7.0 ok")
    assert s.check(A) is None
    assert repo.get(A).smtp_status == SmtpStatus.OK
    s.send(A, A, ["b@example.org"], b"x\r\n")


def test_check_reports_the_error(repo, accounts):
    FakeSMTPSSL.auth_reply = (535, b"5.7.8 bad credentials")
    message = sender(repo).check(A)
    assert message.startswith("SMTP: authentication failed") and PASSWORD not in message
    assert repo.get(A).smtp_status == SmtpStatus.AUTH_FAILED


def test_imap_breaker_blocks_smtp_even_for_a_test(repo, accounts):
    repo.upsert(email=A, provider=Provider.IMAP, status=AccountStatus.NEEDS_RECONNECT)
    s = sender(repo)
    with pytest.raises(SmtpUnavailable, match="needs reconnect"):
        s.send(A, A, ["b@example.org"], b"x\r\n")
    assert "needs reconnect" in s.check(A)
    assert FakeSMTP.instances == []


def test_disabled_and_unknown_accounts(repo, accounts):
    repo.set_enabled(A, False)
    with pytest.raises(SmtpUnavailable, match="disabled"):
        sender(repo).send(A, A, ["b@example.org"], b"x\r\n")
    with pytest.raises(SmtpUnavailable, match="unknown account"):
        sender(repo).send("nobody@example.com", A, ["b@example.org"], b"x\r\n")


def test_login_holds_the_shared_login_lock(repo, accounts):
    locks = LoginLocks()
    s = SmtpSender(repo, connector(), locks, lock_timeout=0.05)
    lock = locks.account(A)
    lock.acquire()
    try:
        with pytest.raises(SmtpError, match="busy"):
            s.send(A, A, ["b@example.org"], b"x\r\n")
    finally:
        lock.release()
    assert FakeSMTP.instances == []

    seen = []

    class LockCheckingSMTP(FakeSMTPSSL):
        def docmd(self, cmd, args=""):
            seen.append(lock.locked())
            return super().docmd(cmd, args)

    s = SmtpSender(repo, SmtpConnector(smtp_ssl_class=LockCheckingSMTP), locks)
    s.send(A, A, ["b@example.org"], b"x\r\n")
    # Held for the login only, not for the (possibly long) upload.
    assert seen == [True, False]


def test_a_send_is_never_retried(repo, accounts):
    FakeSMTP.data_result = smtplib.SMTPServerDisconnected("gone")
    with pytest.raises(SmtpMaybeSent):
        sender(repo).send(A, A, ["b@example.org"], b"x\r\n")
    assert len(FakeSMTP.instances) == 1


def test_sends_on_different_threads_share_nothing(repo, accounts):
    s = sender(repo)
    errors = []

    def run():
        try:
            s.send(A, A, ["b@example.org"], b"x\r\n")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and len(FakeSMTP.instances) == 4
