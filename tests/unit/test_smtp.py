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
    """Records what the client does; behaviour is set per test through class attributes."""

    instances: ClassVar[list["FakeSMTP"]] = []
    extensions: ClassVar[dict[str, str]] = {
        "starttls": "",
        "auth": "PLAIN LOGIN XOAUTH2",
        "8bitmime": "",
    }
    login_error: Exception | None = None
    connect_error: Exception | None = None
    mail_reply = (250, b"2.1.0 ok")
    rcpt_replies: ClassVar[dict[str, tuple[int, bytes]]] = {}
    data_result: object = (250, b"2.0.0 queued")
    docmd_reply = (235, b"2.7.0 accepted")

    def __init__(self, host, port, local_hostname=None, timeout=None, context=None):
        if self.connect_error is not None:
            raise self.connect_error
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.local_hostname = local_hostname
        self.calls: list[tuple] = []
        self.esmtp_features = dict(self.extensions)
        self.sock = None
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append(("ehlo",))

    def has_extn(self, name):
        return name.lower() in self.esmtp_features

    def starttls(self, context=None):
        self.calls.append(("starttls", context))

    def login(self, user, password):
        self.calls.append(("login", user, password))
        if self.login_error is not None:
            raise self.login_error

    def auth(self, mechanism, authobject, initial_response_ok=True):
        self.calls.append(("auth", mechanism, authobject()))
        if self.login_error is not None:
            raise self.login_error

    def docmd(self, cmd, args=""):
        self.calls.append(("docmd", cmd, args))
        return self.docmd_reply

    def mail(self, sender, options=()):
        self.calls.append(("mail", sender, list(options)))
        return self.mail_reply

    def rcpt(self, addr, options=()):
        self.calls.append(("rcpt", addr))
        return self.rcpt_replies.get(addr, (250, b"2.1.5 ok"))

    def data(self, raw):
        self.calls.append(("data", raw))
        if isinstance(self.data_result, Exception):
            raise self.data_result
        return self.data_result

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
    assert s.names() == ["ehlo", "login", "quit"]
    assert s.calls[1] == ("login", A, PASSWORD)


def test_starttls_and_a_separate_username(repo, accounts):
    repo.set_smtp(A, host="mail.example.com", port=587, security="starttls", username="u1")
    connector(local_hostname="postroom.example.org").check(repo.get(A), PASSWORD)
    s = last()
    assert type(s) is FakeSMTP and s.port == 587
    assert s.local_hostname == "postroom.example.org"
    assert s.names() == ["ehlo", "starttls", "ehlo", "login", "quit"]
    assert s.calls[1][1] is not None
    assert s.calls[3] == ("login", "u1", PASSWORD)


def test_starttls_not_offered_is_refused_before_login(repo, accounts):
    repo.set_smtp(A, host="mail.example.com", port=587, security="starttls")
    FakeSMTP.extensions = {"auth": "PLAIN"}
    with pytest.raises(SmtpError, match="does not offer STARTTLS"):
        connector().check(repo.get(A), PASSWORD)
    assert "login" not in last().names() and "quit" in last().names()


def test_auth_failure_is_mapped_without_the_password(repo, accounts):
    FakeSMTPSSL.login_error = smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")
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
    s = last()
    (call,) = [c for c in s.calls if c[0] == "docmd"]
    assert call[1] == "AUTH" and call[2].startswith("PLAIN ")
    assert base64.b64decode(call[2][6:]) == b"\0" + A.encode() + b"\0" + pw.encode()
    assert "login" not in s.names()


def test_non_ascii_password_rejected(repo, accounts):
    FakeSMTPSSL.docmd_reply = (535, b"5.7.8 nope")
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
    assert "login" not in s.names()


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
        ("data", raw),
    ]


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
    FakeSMTP.data_result = smtplib.SMTPDataError(554, b"5.6.0 message refused")
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
    assert last().names() == ["ehlo", "login", "mail", "rcpt", "data", "quit"]
    assert repo.get(A).smtp_status == SmtpStatus.OK


def test_auth_failure_pauses_sending_until_a_manual_test(repo, accounts):
    s = sender(repo)
    FakeSMTPSSL.login_error = smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")
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
    FakeSMTPSSL.login_error = None
    assert s.check(A) is None
    assert repo.get(A).smtp_status == SmtpStatus.OK
    s.send(A, A, ["b@example.org"], b"x\r\n")


def test_check_reports_the_error(repo, accounts):
    FakeSMTPSSL.login_error = smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")
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
        def login(self, user, password):
            seen.append(lock.locked())
            super().login(user, password)

        def data(self, raw):
            seen.append(lock.locked())
            return super().data(raw)

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
