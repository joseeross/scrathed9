import threading
import time

from security_agent.watcher import _wait_until_stable


def test_wait_until_stable_true_for_already_written_file(tmp_path):
    target = tmp_path / "stable.txt"
    target.write_bytes(b"hello")

    assert _wait_until_stable(target, poll_interval=0.01, attempts=3) is True


def test_wait_until_stable_returns_false_when_deleted_mid_poll(tmp_path):
    """A file can vanish between being enqueued and the stability check completing
    (e.g. a short-lived temp file, or another process cleaning up). The watcher
    loop must treat that as False and move on, not raise."""
    target = tmp_path / "vanishing.txt"
    target.write_bytes(b"x" * 100)

    def delete_after_first_check():
        time.sleep(0.01)  # well inside the first poll_interval sleep below
        target.unlink()

    threading.Thread(target=delete_after_first_check).start()

    assert _wait_until_stable(target, poll_interval=0.05, attempts=10) is False
