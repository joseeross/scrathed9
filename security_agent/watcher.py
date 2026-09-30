from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .config import AgentConfig
from .pipeline import SecurityPipeline

logger = logging.getLogger(__name__)


class _DebouncedHandler(FileSystemEventHandler):
    """Enqueues created/modified paths, coalescing create+modify events for one write
    into a single queued job via a pending-set guarded by a lock."""

    def __init__(
        self,
        work_queue: "queue.Queue[Path]",
        ignore_dirs: set[Path],
        pending: set[Path],
        pending_lock: threading.Lock,
    ):
        self.work_queue = work_queue
        self.ignore_dirs = ignore_dirs
        self.pending = pending
        self.pending_lock = pending_lock

    def _maybe_enqueue(self, src_path: str) -> None:
        path = Path(src_path)
        if path.name.startswith("."):
            return
        if any(str(path).startswith(str(ignored)) for ignored in self.ignore_dirs):
            return
        with self.pending_lock:
            if path in self.pending:
                return
            self.pending.add(path)
        self.work_queue.put(path)

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._maybe_enqueue(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._maybe_enqueue(event.src_path)


def _wait_until_stable(path: Path, poll_interval: float, attempts: int = 5) -> bool:
    """Waits for a file's size to stop changing, so we don't scan a partial write.

    Uses lstat, not stat: this loop only checks size, but a symlink shouldn't have
    its target touched anywhere in the pipeline, even just to poll metadata. The
    actual open-time rejection of symlinks happens later in pipeline.process(); this
    is defense in depth, not the enforcement point.
    """
    last_size = -1
    for _ in range(attempts):
        try:
            size = path.lstat().st_size
        except OSError:
            return False
        if size == last_size:
            return True
        last_size = size
        time.sleep(poll_interval)
    return True


def run_watch(config: AgentConfig) -> None:
    pipeline = SecurityPipeline(config)
    work_queue: "queue.Queue[Path]" = queue.Queue()
    ignore_dirs = {Path(config.quarantine_dir).resolve(), Path(config.report_dir).resolve()}
    pending: set[Path] = set()
    pending_lock = threading.Lock()

    def worker() -> None:
        while True:
            path = work_queue.get()
            try:
                if _wait_until_stable(path, config.debounce_seconds):
                    try:
                        pipeline.process(path)
                    except Exception:
                        logger.exception("Unhandled error processing %s", path)
            finally:
                with pending_lock:
                    pending.discard(path)
                work_queue.task_done()

    threading.Thread(target=worker, daemon=True).start()

    handler = _DebouncedHandler(work_queue, ignore_dirs, pending, pending_lock)
    observer = Observer()
    observer.schedule(handler, str(config.watch_dir), recursive=True)
    observer.start()
    logger.info("Watching %s for new/modified files...", config.watch_dir)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
