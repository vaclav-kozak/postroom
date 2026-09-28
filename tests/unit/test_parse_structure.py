"""The BODYSTRUCTURE path for messages too large to parse whole (final fix round)."""

import base64
from email.message import EmailMessage

import pytest

from postroom.mail import parse
from tests.unit.bodystructure import bodystructure_of


def _mixed() -> EmailMessage:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@b.example.net", "c@d.example.net", "Faktura"
    m.set_content("Dobrý den, v příloze posílám fakturu za září. S pozdravem")
    m.add_alternative("<p>Dobrý den, v <b>příloze</b> posílám fakturu.</p>", subtype="html")
    m.add_attachment(
        b"%PDF-1.4 x" * 100, maintype="application", subtype="pdf", filename="faktura.pdf"
    )
    m.add_attachment(
        "poznámka".encode("iso-8859-2"),
        maintype="text",
        subtype="plain",
        filename="žluťoučký kůň úpěl ďábelské ódy – dlouhý název souboru.txt",
    )
    inner = EmailMessage()
    inner["Subject"] = "forwarded"
    inner.set_content("inner body")
    m.add_attachment(inner)
    m.add_attachment(
        b"\x89PNG....",
        maintype="image",
        subtype="png",
        filename="logo.png",
        disposition="inline",
        cid="<logo@x>",
    )
    return m


def _related() -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "newsletter"
    m.set_content("<h1>News</h1><img src='cid:img1'>", subtype="html")
    m.add_related(b"GIF89a...", maintype="image", subtype="gif", cid="<img1>")
    m.add_attachment(b"PK\x03\x04", maintype="application", subtype="zip", filename="a.zip")
    return m


def _single_html() -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "html only"
    m.set_content("<p>only html here</p>", subtype="html")
    return m


def _attached_text_only() -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "report"
    m.set_content("see attached report file, it is below this line")
    m.add_attachment("a,b\n1,2\n", subtype="csv", filename="report.csv")
    return m


SHAPES = [_mixed, _related, _single_html, _attached_text_only]


@pytest.mark.parametrize("make", SHAPES)
def test_structure_plan_matches_the_full_parse(make):
    raw = make().as_bytes()
    full = parse.parse_message(raw)
    plan = parse.structure_plan(bodystructure_of(raw))
    got = [(i.index, i.filename, i.content_type, i.inline, i.charset) for i, _ in plan.attachments]
    want = [(a.index, a.filename, a.content_type, a.inline, a.charset) for a in full.attachments]
    assert got == want


def test_structure_plan_sections_and_bodies():
    raw = _mixed().as_bytes()
    plan = parse.structure_plan(bodystructure_of(raw))
    assert plan.plain.section == "1.1" and plan.html.section == "1.2"
    assert [p.section for _, p in plan.attachments] == ["2", "3", "4", "5"]
    # RFC 2231 continuations (FILENAME*0*, *1*, *2*) as Dovecot passes them through
    assert plan.attachments[1][0].filename.startswith("žluťoučký kůň")


def test_single_part_message_body_is_section_1():
    plan = parse.structure_plan(bodystructure_of(_single_html().as_bytes()))
    assert plan.html.section == "1" and plan.plain is None and plan.attachments == []


def test_structure_plan_rejects_missing_structure():
    with pytest.raises(ValueError, match="structure"):
        parse.structure_plan(None)


def test_count_parts():
    assert parse.count_parts(bodystructure_of(_mixed().as_bytes())) == 6
    assert parse.count_parts(None) == 0


def test_parse_large_message_uses_the_same_body_choice():
    m = _mixed()
    raw = m.as_bytes()
    header = raw.split(b"\n\n", 1)[0] + b"\n\n"
    plan = parse.structure_plan(bodystructure_of(raw))
    plain = m.get_body(("plain",)).get_payload().encode()  # still transfer-encoded
    texts = {plan.plain.section: plain}
    parsed = parse.parse_large_message(header, plan, texts)
    assert parsed.subject == "Faktura" and parsed.from_ == "a@b.example.net"
    assert parsed.body_source == "plain" and parsed.body_text.startswith("Dobrý den, v příloze")
    assert [a.filename for a in parsed.attachments][:2] == [
        "faktura.pdf",
        "žluťoučký kůň úpěl ďábelské ódy – dlouhý název souboru.txt",
    ]


def test_parse_large_message_falls_back_to_html():
    raw = _single_html().as_bytes()
    header, body = raw.split(b"\n\n", 1)
    plan = parse.structure_plan(bodystructure_of(raw))
    parsed = parse.parse_large_message(header, plan, {"1": body})
    assert parsed.body_source == "html" and parsed.body_text == "only html here"


def test_decode_transfer_tolerates_a_cut_off_base64_stream():
    data = base64.encodebytes("příliš žluťoučký kůň".encode() * 50)
    assert parse.decode_transfer(data, "base64") == "příliš žluťoučký kůň".encode() * 50
    cut = parse.decode_transfer(data[:101], "base64")
    assert "příliš žluťoučký kůň".encode() * 2 in cut


def test_decode_transfer_quoted_printable_and_identity():
    assert parse.decode_transfer(b"=C5=BEluv=\r\nou", "quoted-printable") == "žluvou".encode()
    assert parse.decode_transfer(b"raw", "8bit") == b"raw"
