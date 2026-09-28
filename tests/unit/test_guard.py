"""Static guard: the package never expunges a whole folder (only UID EXPUNGE of named
messages, in the mail service), SMTP lives only in the SMTP client module (behind the
"full" access level, checked by the mail service), and the IMAP writes that organise mail
(flags, move, trash, create folder) live only in the mail service, behind the per-account
access level."""

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "postroom"
SERVICE = pathlib.Path("mail") / "service.py"
SMTP = pathlib.Path("mail") / "smtp.py"

# Only in the SMTP client module.
SMTP_ONLY = [r"\bsmtplib\b"]

# Never anywhere. A plain EXPUNGE (or CLOSE, which expunges) would also purge messages
# someone else marked \Deleted; set_flags on the client would replace every flag.
FORBIDDEN = [
    r"\.delete_messages\(",
    r"\.expunge\(",
    r"(?<!mail)\.set_flags\(",
    r"_gmail_labels\(",
    r"\.delete_folder\(",
    r"\.rename_folder\(",
    r"\.unsubscribe_folder\(",
    r"\.close_folder\(",
]

# Only in the mail service (the tools call the service's methods of the same name).
SERVICE_ONLY = [
    r"\.uid_expunge\(",
    r"(?<!mail)\.move\(\s*[^)\s]",
    r"\.copy\(\s*[^)\s]",
    r"\.add_flags\(",
    r"\.remove_flags\(",
    r"(?<!mail)\.create_folder\(",
    r"\.subscribe_folder\(",
]


def _sources():
    return [p for p in SRC.rglob("*.py")]


def _find(patterns, skip=()):
    offenders = []
    for path in _sources():
        if path.relative_to(SRC) in skip:
            continue
        text = path.read_text()
        for pattern in patterns:
            for m in re.finditer(pattern, text):
                line = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{path.relative_to(SRC)}:{line}: {pattern}")
    return offenders


def test_no_forbidden_imap_or_smtp_operations():
    offenders = _find(FORBIDDEN)
    assert not offenders, "Forbidden operations found:\n" + "\n".join(offenders)


def test_smtp_only_in_the_smtp_module():
    offenders = _find(SMTP_ONLY, skip=(SMTP,))
    assert not offenders, "smtplib outside mail/smtp.py:\n" + "\n".join(offenders)
    assert "import smtplib" in (SRC / SMTP).read_text()


def test_organising_writes_only_in_the_mail_service():
    offenders = _find(SERVICE_ONLY, skip=(SERVICE,))
    assert not offenders, "IMAP writes outside the mail service:\n" + "\n".join(offenders)


def _function(text: str, name: str) -> str:
    """A top-level function's source: up to the next top-level statement."""
    body = text[text.index(f"\ndef {name}(") + 1 :]
    end = re.search(r"\n(?=\S)", body)
    return body[: end.start()] if end else body


def test_uid_expunge_only_in_the_move_and_sent_draft_helpers():
    """UID EXPUNGE only of the UIDs just moved, or of the one draft just sent."""
    text = (SRC / SERVICE).read_text()
    move, draft = _function(text, "_move_uids"), _function(text, "_expunge_one")
    assert text.count(".uid_expunge(") == 2
    assert move.count(".uid_expunge(uids)") == 1
    assert draft.count(".uid_expunge([uid])") == 1


def test_every_select_folder_says_how_it_opens():
    """Reads open folders read-only; only the mail service's organising code opens one
    read-write, and it says so explicitly."""
    offenders = []
    for path in _sources():
        text = path.read_text()
        for m in re.finditer(r"\.select_folder\(([^)]*)\)", text):
            args = m.group(1)
            if "readonly=True" in args:
                continue
            if "readonly=False" in args and path.relative_to(SRC) == SERVICE:
                continue
            offenders.append(f"{path.relative_to(SRC)}: {m.group(0)}")
    assert not offenders, offenders


def test_body_fetches_use_peek():
    offenders = []
    for path in _sources():
        text = path.read_text()
        # Request strings "BODY[...]" would set \Seen; response keys are bytes (b"BODY[]") and allowed.
        for m in re.finditer(r"(?<![bB])[\"']BODY\[", text):
            offenders.append(f"{path.relative_to(SRC)}: non-PEEK BODY fetch")
        for m in re.finditer(r"(?<![bB])[\"']RFC822[\"']", text):
            offenders.append(f"{path.relative_to(SRC)}: RFC822 fetch sets \\Seen")
    assert not offenders, offenders
