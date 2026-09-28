import threading
import time

import pytest

from postroom.mail import heavy
from postroom.mail.heavy import ServerBusy, heavy_work


def test_heavy_work_runs_one_job_at_a_time():
    running = 0
    peak = 0
    lock = threading.Lock()

    def job():
        nonlocal running, peak
        with heavy_work():
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.05)
            with lock:
                running -= 1

    threads = [threading.Thread(target=job) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1


def test_heavy_work_is_reentrant_in_one_thread():
    with heavy_work(), heavy_work():  # parse_message -> html_to_text both take the gate
        pass
    with heavy_work():  # and it is released afterwards
        pass


def test_heavy_work_gives_up_with_server_busy(monkeypatch):
    monkeypatch.setattr(heavy, "HEAVY_WAIT_SECONDS", 0.05)
    holding = threading.Event()
    release = threading.Event()

    def holder():
        with heavy_work():
            holding.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(5)
    try:
        with pytest.raises(ServerBusy, match="busy"), heavy_work():
            pass
    finally:
        release.set()
        t.join()
    with heavy_work():  # a failed wait does not leak the slot
        pass
