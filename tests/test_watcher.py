import time as time_module

from security_agent.watcher import _wait_until_stable


def test_wait_until_stable_true_for_already_written_file(tmp_path):
    target = tmp_path / "stable.txt"
    target.write_bytes(b"hello")

    assert _wait_until_stable(target, poll_interval=0.01, attempts=3) is True


def test_wait_until_stable_returns_false_when_deleted_mid_poll(tmp_path, monkeypatch):
    """A file can vanish between being enqueued and the stability check completing
    (e.g. a short-lived temp file, or another process cleaning up). The watcher
    loop must treat that as False and move on, not raise.

    Deletes the file from inside the loop's own sleep call instead of racing two
    independent timers (a real thread + a real sleep): that construction is a
    coin flip by nature and gets flaky again under CI load. Monkeypatching sleep
    to delete synchronously makes the ordering deterministic - the file is
    guaranteed gone before the second stability check, not merely likely to be.
    """
    target = tmp_path / "vanishing.txt"
    target.write_bytes(b"x" * 100)

    def delete_instead_of_sleep(_seconds):
        target.unlink(missing_ok=True)

    monkeypatch.setattr(time_module, "sleep", delete_instead_of_sleep)

    assert _wait_until_stable(target, poll_interval=0.05, attempts=10) is False
