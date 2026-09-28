"""PDF text extraction in a short-lived, memory-limited child process.

pypdf on a hostile PDF can allocate far more than the 256 MiB container allows: a 16 KiB
PDF whose content stream inflates to 5 MiB of text operators cost +222 MiB, because pypdf
turns every operator into Python objects. A worker thread can't be stopped or limited, so
extraction runs in a child Python (`python -m postroom.mail.pdf`) that:

- imports pypdf first, then caps its own address space with RLIMIT_AS, so pypdf gets a
  MemoryError instead of the kernel OOM-killing the whole container;
- lowers pypdf's decompression limits, so a zlib bomb fails fast;
- is killed when it runs past the timeout;
- gets the PDF on stdin and a minimal environment (no POSTROOM_* secrets), and writes JSON
  to stdout.

The PDF gets `PARSE_MEMORY_BYTES` on top of the child's footprint after its imports, the
whole child stays under `CHILD_MEMORY_BYTES`, and callers run one extraction at a time
(heavy-work gate).
"""

import json
import os
import resource
import subprocess
import sys

# Address space the PDF may use, on top of the child's footprint once pypdf is imported.
# The limit is applied after the imports because that footprint depends on the build, and
# is only known then (virtual size after `import pypdf`):
#   - python:3.13-slim-bookworm image (.pyc prebuilt): 48 MiB (37 MiB RSS);
#   - uv's python-build-standalone 3.13.12/3.13.15: 60 MiB with .pyc cached, and 75 MiB
#     (peak 103 MiB) when the child has to compile pypdf first, as in a fresh CI venv.
# A fixed 96 MiB ceiling set before the imports therefore failed on every PDF on the
# standalone builds. Measured with the old 96 MiB/48 MiB split: ordinary PDFs peak at
# 37 MiB RSS, a page with 1 MiB of text operators at 78 MiB, and the 5 MiB content bomb
# stops with MemoryError at 84 MiB (it reached 253 MiB without a limit).
PARSE_MEMORY_BYTES = 48 * 1024 * 1024
# Hard ceiling of the child's whole address space, whatever its import footprint: the
# production image lands at ~96 MiB, a cold standalone build at ~123 MiB.
CHILD_MEMORY_BYTES = 128 * 1024 * 1024
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


def _child_command(
    max_chars: int, max_pages: int, parse_bytes: int, ceiling_bytes: int
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "postroom.mail.pdf",
        str(max_chars),
        str(max_pages),
        str(parse_bytes),
        str(ceiling_bytes),
    ]


def _child_env() -> dict[str, str]:
    """Only what the child needs to start; the server's secrets stay out of it."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "PYTHONPATH", "LANG", "LC_ALL")}
    # One malloc arena: a second glibc arena reserves 64 MiB of address space up front.
    env["MALLOC_ARENA_MAX"] = "1"
    return env


def _address_space_bytes() -> int | None:
    """This process's current virtual size (what RLIMIT_AS counts), or None if unknown."""
    try:
        with open("/proc/self/statm", "rb") as f:
            return int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


def _address_space_limit(parse_bytes: int, ceiling_bytes: int) -> int:
    """RLIMIT_AS for the child: its current size plus the parse budget, never above the
    ceiling nor above a hard limit it already has."""
    used = _address_space_bytes()
    limit = ceiling_bytes if used is None else min(used + parse_bytes, ceiling_bytes)
    hard = resource.getrlimit(resource.RLIMIT_AS)[1]
    return limit if hard == resource.RLIM_INFINITY else min(limit, hard)


def extract_text_isolated(
    data: bytes, max_chars: int, max_pages: int, timeout: float
) -> tuple[str, int | None]:
    """Extracted text (at most max_chars + 1 characters) and the total page count when
    pages beyond max_pages were skipped.

    Raises `TimeoutError` (child killed), `PdfTooComplex` (memory ceiling hit) or
    `PdfError` (anything else). Blocks: call it from a worker thread.
    """
    cmd = _child_command(max_chars, max_pages, PARSE_MEMORY_BYTES, CHILD_MEMORY_BYTES)
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
    max_chars, max_pages, parse_bytes, ceiling_bytes = (int(a) for a in argv)
    try:
        # Unlimited until pypdf is imported and configured: this footprint is fixed by the
        # interpreter and the installed pypdf, not by the PDF, which is read only after the
        # limit is in place.
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
        limit = _address_space_limit(parse_bytes, ceiling_bytes)
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
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
