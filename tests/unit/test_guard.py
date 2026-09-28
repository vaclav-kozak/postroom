"""Static guard: the package must never contain mail-mutating or sending code."""

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "postroom"

FORBIDDEN = [
    r"\bsmtplib\b",
    r"\.delete_messages\(",
    r"\.expunge\(",
    r"\.uid_expunge\(",
    r"\.move\(\s*[^)\s]",
    r"\.copy\(\s*[^)\s]",
    r"\.add_flags\(",
    r"\.set_flags\(",
    r"\.remove_flags\(",
    r"_gmail_labels\(",
    r"\.create_folder\(",
    r"\.delete_folder\(",
    r"\.rename_folder\(",
    r"\.subscribe_folder\(",
    r"\.unsubscribe_folder\(",
    r"\.close_folder\(",
]


def _sources():
    return [p for p in SRC.rglob("*.py")]


def test_no_forbidden_imap_or_smtp_operations():
    offenders = []
    for path in _sources():
        text = path.read_text()
        for pattern in FORBIDDEN:
            for m in re.finditer(pattern, text):
                line = text.count("\n", 0, m.start()) + 1
                offenders.append(f"{path.relative_to(SRC)}:{line}: {pattern}")
    assert not offenders, "Forbidden operations found:\n" + "\n".join(offenders)


def test_every_select_folder_is_readonly():
    offenders = []
    for path in _sources():
        text = path.read_text()
        for m in re.finditer(r"\.select_folder\(([^)]*)\)", text):
            if "readonly=True" not in m.group(1):
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
