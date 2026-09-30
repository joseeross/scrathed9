from __future__ import annotations

import errno
import logging
import mimetypes
import os
import re
import stat as stat_module
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .claude_analyzer import ClaudeAnalyzer
from .config import AgentConfig
from .heuristics import analyze_file as run_heuristics
from .quarantine import Quarantine
from .report import ReportWriter, ScanReport
from .yara_scan import YaraScanner

logger = logging.getLogger(__name__)

# INVARIANT for anyone adding a new file-handling helper here: once a file has been
# opened symlink-safely (via _open_regular_file_no_follow, below) and its bytes read,
# every downstream consumer of that file's content - heuristics, YARA, the Claude
# analyzer, anything added later - must take those bytes (or the fd), never the Path.
# A helper that takes a Path and does its own I/O is a second entry point: it can
# silently reopen the file by name and reintroduce the exact TOCTOU race this module
# closes at the one point that's supposed to matter. This is exactly how the YARA
# scanner regressed the fix once already (it matched by path, so yara-python reopened
# the file itself, bypassing pipeline.process()'s guard entirely) - see yara_scan.py.

# Hard floor, independent of config: never auto-quarantine below this confidence.
# Not exposed as a config option on purpose - a model-reported confidence score is
# not a calibrated probability, especially against a truncated/partial excerpt, and
# the cost asymmetry (moving a file the user wanted vs. leaving a malicious file in
# place) doesn't justify letting a user dial this down. Also never auto-quarantine
# off a truncated excerpt at all, regardless of reported confidence - see `process()`.
AUTO_QUARANTINE_MIN_CONFIDENCE = 0.9

# O_NOFOLLOW/O_NONBLOCK are POSIX-only (absent on Windows); fall back to a no-op flag
# there. On Windows, symlink rejection falls back to a pre-open check in _open_file,
# which is best-effort (a TOCTOU window remains) rather than atomic - creating a
# symlink on Windows normally requires elevated privileges, which narrows the risk
# but does not eliminate it.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _read_fd_fully(fd: int, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _open_regular_file_no_follow(path: Path) -> tuple[Optional[int], Optional[str]]:
    """Opens path atomically, refusing to follow a symlink at open time so a file
    swapped for a symlink after any earlier check (TOCTOU) is rejected rather than
    silently followed. O_NONBLOCK keeps a FIFO from hanging the caller; harmless on
    regular files, where POSIX defines it as a no-op. Returns (fd, None) on success,
    or (None, "symlink" | "not_regular" | <errno message>) on rejection/failure."""
    try:
        fd = os.open(str(path), os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return None, "symlink"
        return None, str(e)

    try:
        st = os.fstat(fd)
    except OSError as e:
        os.close(fd)
        return None, str(e)

    if not stat_module.S_ISREG(st.st_mode):
        os.close(fd)
        return None, "not_regular"

    return fd, None


def _make_excerpt(data: bytes, max_bytes: int) -> tuple[str, bool]:
    truncated = len(data) > max_bytes
    chunk = data[:max_bytes]
    try:
        return chunk.decode("utf-8"), truncated
    except UnicodeDecodeError:
        pass

    strings_found = re.findall(rb"[\x20-\x7e]{4,}", chunk)
    printable = b"\n".join(strings_found[:2000])
    return printable.decode("ascii", errors="ignore"), True


class SecurityPipeline:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.yara = YaraScanner(config.rules_dir)
        self.claude = ClaudeAnalyzer(config)
        self.quarantine = Quarantine(Path(config.quarantine_dir))
        self.reports = ReportWriter(Path(config.report_dir))

    def process(self, path: Path) -> Optional[ScanReport]:
        fd, err = _open_regular_file_no_follow(path)
        if fd is None:
            if err == "symlink":
                logger.info("Skipping %s: symlink rejected at open time (not followed)", path)
            elif err == "not_regular":
                logger.info("Skipping %s: not a regular file", path)
            else:
                logger.warning("Could not open %s: %s", path, err)
            return None

        try:
            size = os.fstat(fd).st_size
            max_bytes = self.config.max_file_size_mb * 1024 * 1024
            if size > max_bytes:
                logger.info("Skipping %s: %d bytes exceeds max_file_size_mb limit", path, size)
                return None
            data = _read_fd_fully(fd, size)
        except OSError as e:
            logger.warning("Could not read %s: %s", path, e)
            return None
        finally:
            os.close(fd)

        heuristic_result = run_heuristics(path, data)
        yara_matches = self.yara.scan(data)
        risk_score = heuristic_result.score + 25 * len(yara_matches)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        file_meta = {
            "path": str(path),
            "size_bytes": size,
            "mime_type": mimetypes.guess_type(path.name)[0] or "unknown",
            "entropy": round(heuristic_result.entropy, 3),
        }

        escalate = risk_score >= self.config.local_risk_threshold
        claude_verdict: Optional[dict] = None
        action_taken = "none"

        if escalate:
            excerpt, truncated = _make_excerpt(data, self.config.content_excerpt_bytes)
            verdict = self.claude.analyze(
                file_meta, heuristic_result.findings, yara_matches, excerpt, truncated
            )
            claude_verdict = asdict(verdict)

            if verdict.error:
                action_taken = "analysis_error"
            elif verdict.quarantine_recommended:
                effective_threshold = max(self.config.auto_quarantine_confidence, AUTO_QUARANTINE_MIN_CONFIDENCE)
                should_auto = (
                    self.config.auto_quarantine
                    and not truncated
                    and verdict.confidence >= effective_threshold
                )
                if should_auto:
                    self.quarantine.move(path, reason=f"{verdict.threat_type}: {verdict.summary}")
                    action_taken = "quarantined"
                else:
                    action_taken = "quarantine_recommended"
            else:
                action_taken = "reviewed_clear"

            logger.warning(
                "Analyzed %s: risk=%d verdict=%s action=%s",
                path, risk_score, verdict.verdict, action_taken,
            )

        report = ScanReport(
            path=str(path),
            timestamp=timestamp,
            file_size=size,
            local_risk_score=risk_score,
            local_findings=heuristic_result.findings,
            yara_matches=yara_matches,
            escalated_to_claude=escalate,
            claude_verdict=claude_verdict,
            action_taken=action_taken,
        )
        self.reports.write(report)
        return report
