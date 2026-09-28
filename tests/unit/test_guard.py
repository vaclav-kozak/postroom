"""Static guard: the package must never delete mail permanently or send it, and the IMAP
writes that organise mail (flags, move, trash, create folder) live only in the mail service,
behind the per-account access level."""

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "postroom"
SERVICE = pathlib.Path("mail") / "service.py"

# Never anywhere. A plain EXPUNGE (or CLOSE, which expunges) would also purge messages
# someone else marked \Deleted; set_flags on the client would replace every flag.
FORBIDDEN = [
    r"\bsmtplib\b",
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


def test_organising_writes_only_in_the_mail_service():
    offenders = _find(SERVICE_ONLY, skip=(SERVICE,))
    assert not offenders, "IMAP writes outside the mail service:\n" + "\n".join(offenders)


def test_uid_expunge_only_in_the_move_helper():
    text = (SRC / SERVICE).read_text()
    body = text[text.index("def _move_uids(") :]
    body = body[: body.index("\ndef ")]
    assert text.count(".uid_expunge(") == body.count(".uid_expunge(") == 1
    assert ".uid_expunge(uids)" in body


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
