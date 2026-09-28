"""PDF text extraction in a short-lived, memory-limited child process.

pypdf on a hostile PDF can allocate far more than the 256 MiB container allows: a 16 KiB
PDF whose content stream inflates to 5 MiB of text operators cost +222 MiB, because pypdf
turns every operator into Python objects. A worker thread can't be stopped or limited, so
extraction runs in a child Python (`python -m postroom.mail.pdf`) that:

- caps its own address space with RLIMIT_AS, so pypdf gets a MemoryError instead of the
  kernel OOM-killing the whole container;
- lowers pypdf's decompression limits, so a zlib bomb fails fast;
- is killed when it runs past the timeout;
- gets the PDF on stdin and a minimal environment (no POSTROOM_* secrets), and writes JSON
  to stdout.

The child's whole footprint, startup included, stays under `CHILD_MEMORY_BYTES`, and
callers run one extraction at a time (heavy-work gate).
"""

import json
import os
import resource
import subprocess
import sys

# Address-space ceiling of the child. Python + pypdf start at ~47 MiB of virtual memory
# (34 MiB RSS), which leaves ~50 MiB for one PDF. Measured: ordinary PDFs peak at 37 MiB
# RSS, a page with 1 MiB of text operators at 78 MiB, and the 5 MiB content bomb stops
# with MemoryError at 84 MiB (it reached 253 MiB without the ceiling).
CHILD_MEMORY_BYTES = 96 * 1024 * 1024
# Per-stream decompression cap inside the child. Page content beyond ~1.5 MiB already
# exhausts the memory ceiling when tokenised, so bigger streams can only be bombs.
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024


class PdfError(Exception):
    """The text could not be extracted (damaged or encrypted PDF, or the child failed)."""


class PdfTooComplex(PdfError):
    """Extraction needed more memory than the child is allowed."""


def extract_text(data: bytes, max_chars: int, max_pages: int) -> tuple[str, int | None]:
    """Extract text in this process. Only the child calls this: never in the server."""
    import io

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        reader.decrypt("")  # many "protected" PDFs only restrict editing, with no password
    pages: list[str] = []
    total = 0
    page_count = len(reader.pages)
    for page in reader.pages[:max_pages]:
        text = page.extract_text() or ""
        pages.append(text)
        total += len(text)
        if total > max_chars:  # enough to fill the answer; skip the remaining pages
            break
    return "\n\n".join(pages)[: max_chars + 1], (page_count if page_count > max_pages else None)


def _child_command(max_chars: int, max_pages: int, memory_bytes: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "postroom.mail.pdf",
        str(max_chars),
        str(max_pages),
        str(memory_bytes),
    ]


def _child_env() -> dict[str, str]:
    """Only what the child needs to start; the server's secrets stay out of it."""
    return {k: v for k, v in os.environ.items() if k in ("PATH", "PYTHONPATH", "LANG", "LC_ALL")}


def extract_text_isolated(
    data: bytes, max_chars: int, max_pages: int, timeout: float
) -> tuple[str, int | None]:
    """Extracted text (at most max_chars + 1 characters) and the total page count when
    pages beyond max_pages were skipped.

    Raises `TimeoutError` (child killed), `PdfTooComplex` (memory ceiling hit) or
    `PdfError` (anything else). Blocks: call it from a worker thread.
    """
    cmd = _child_command(max_chars, max_pages, CHILD_MEMORY_BYTES)
    try:
        proc = subprocess.run(  # fixed argv: our own interpreter and module, no shell
            cmd,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # pypdf may warn endlessly on a hostile file
            env=_child_env(),
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:  # subprocess.run has already killed the child
        raise TimeoutError("PDF text extraction timed out") from e
    try:
        result = json.loads(proc.stdout)
    except ValueError:
        result = {}
    if not isinstance(result, dict):
        result = {}
    if result.get("error") == "memory":
        raise PdfTooComplex("PDF needs too much memory to extract")
    if proc.returncode != 0 or not isinstance(result.get("text"), str):
        raise PdfError("could not extract text from this PDF")
    pages = result.get("pages")
    return result["text"], (pages if isinstance(pages, int) else None)


def _child_main(argv: list[str]) -> int:
    max_chars, max_pages, memory_bytes = (int(a) for a in argv)
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    try:
        import logging

        import pypdf

        logging.disable(logging.CRITICAL)  # warnings go nowhere anyway (stderr is /dev/null)
        pypdf.overwrite_configuration(
            **{
                name: MAX_DECOMPRESSED_BYTES
                for name in (
                    "maximum_declared_stream_length",
                    "array_based_stream_maximum_output_length",
                    "jbig2_maximum_output_length",
                    "lzw_maximum_output_length",
                    "run_length_maximum_output_length",
                    "zlib_maximum_output_length",
                    "flate_maximum_buffer_size",
                    "image_maximum_buffer_size",
                )
                if hasattr(pypdf.Configuration, name)
            }
        )
        text, pages = extract_text(sys.stdin.buffer.read(), max_chars, max_pages)
        out = {"text": text, "pages": pages}
    except MemoryError:
        out = {"error": "memory"}
    except Exception:  # noqa: BLE001 -- pypdf raises many types on damaged/encrypted files
        out = {"error": "failed"}
    try:
        sys.stdout.buffer.write(json.dumps(out).encode())
    except MemoryError:
        return 3
    return 0 if "text" in out else 2


if __name__ == "__main__":
    sys.exit(_child_main(sys.argv[1:]))
