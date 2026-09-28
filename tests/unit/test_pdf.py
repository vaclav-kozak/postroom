"""PDF text extraction runs in a memory-limited child process (final fix round, review B I1)."""

import io
import resource
import sys
import time
import zlib

import pytest

from postroom.mail import pdf
from tests.unit.test_mail_tools import make_pdf


def make_bomb_pdf(decompressed_mib: float) -> bytes:
    """One page whose Flate content stream inflates to `decompressed_mib` of text operators.

    The reviewer's probe: 5 MiB of `BT ... Tj ET` compresses to a 16 KiB PDF and cost
    +222 MiB when pypdf extracted it in-process.
    """
    unit = b"BT /F1 12 Tf 10 10 Td (ab) Tj ET\n"
    content = unit * int(decompressed_mib * 1024 * 1024 // len(unit))
    comp = zlib.compress(content, 9)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp) + comp + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + o + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    )
    return out.getvalue()


def _maxrss_mib(who) -> float:
    return resource.getrusage(who).ru_maxrss / 1024


def test_extracts_text_in_a_child_process(monkeypatch):
    def in_process(*a, **kw):
        raise AssertionError("pypdf must not run in the server process")

    monkeypatch.setattr(pdf, "extract_text", in_process)
    text, pages = pdf.extract_text_isolated(make_pdf("Invoice 2026-042"), 1000, 50, 20)
    assert "Invoice 2026-042" in text and pages is None


def test_damaged_pdf_raises_pdf_error():
    with pytest.raises(pdf.PdfError):
        pdf.extract_text_isolated(b"%PDF-1.4 garbage", 1000, 50, 20)


def test_zlib_content_bomb_stays_inside_the_child_limit():
    bomb = make_bomb_pdf(5)
    assert len(bomb) < 20 * 1024
    parent_before = _maxrss_mib(resource.RUSAGE_SELF)
    start = time.monotonic()
    with pytest.raises(pdf.PdfError):
        pdf.extract_text_isolated(bomb, 50_000, 50, 20)
    assert time.monotonic() - start < 15
    # (The child's own peak can't be read here: a child's ru_maxrss starts at the
    # parent's RSS at fork. The scratchpad probe measures it from a tiny parent.)
    assert _maxrss_mib(resource.RUSAGE_SELF) - parent_before < 20


def test_hitting_the_memory_limit_is_reported_as_too_complex(monkeypatch):
    # Under pypdf's decompression limit, but tokenising 1 MiB of operators needs ~45 MiB.
    monkeypatch.setattr(pdf, "CHILD_MEMORY_BYTES", 64 * 1024 * 1024)
    with pytest.raises(pdf.PdfTooComplex):
        pdf.extract_text_isolated(make_bomb_pdf(1), 50_000, 50, 20)


def test_child_is_killed_on_timeout(monkeypatch):
    monkeypatch.setattr(
        pdf, "_child_command", lambda *a: [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        pdf.extract_text_isolated(make_pdf("x"), 1000, 50, 0.5)
    assert time.monotonic() - start < 5


def test_child_does_not_inherit_the_server_environment(monkeypatch):
    monkeypatch.setenv("POSTROOM_MASTER_KEY", "secret-value")
    assert not any(name.startswith("POSTROOM_") for name in pdf._child_env())
