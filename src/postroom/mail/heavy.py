"""A process-wide gate around memory-heavy mail work.

The container has 256 MiB and idles at 80-130 MiB. Parsing a message of several MiB,
converting HTML to text and extracting PDF text each need tens of MiB for a moment, and
tool calls on different accounts run in parallel worker threads, so without a gate they
stack up. `heavy_work()` lets one such job run at a time. The others queue for up to
`HEAVY_WAIT_SECONDS` (kept below the 90 s per-call timeout, so a queued thread never
outlives its caller for long) and then fail with `ServerBusy`.

The gate is re-entrant within one thread, so a heavy job can call another one (for
example `parse_message` calling `html_to_text`). Only take it in worker threads, never on
the event loop: waiting on it blocks.
"""

import threading
from collections.abc import Iterator
from contextlib import contextmanager

HEAVY_WAIT_SECONDS = 60

_gate = threading.Semaphore(1)
_local = threading.local()


class ServerBusy(RuntimeError):
    """Another large email or attachment is being processed; the caller may retry."""

    def __init__(self) -> None:
        super().__init__(
            "the server is busy with another large email or attachment; try again in a minute"
        )


@contextmanager
def heavy_work() -> Iterator[None]:
    depth = getattr(_local, "depth", 0)
    if depth == 0 and not _gate.acquire(timeout=HEAVY_WAIT_SECONDS):
        raise ServerBusy()
    _local.depth = depth + 1
    try:
        yield
    finally:
        _local.depth = depth
        if depth == 0:
            _gate.release()
