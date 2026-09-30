from __future__ import annotations

import logging
import mimetypes
import re
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

# Hard floor, independent of config: never auto-quarantine below this confidence,
# and never auto-quarantine off a truncated/partial content excerpt at all - a
# verdict on partial evidence isn't a safe basis for an automatic, unattended action.
AUTO_QUARANTINE_MIN_CONFIDENCE = 0.9


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
        if path.is_symlink():
            logger.info("Skipping %s: symlinks are not followed (would read outside the watched dir)", path)
            return None

        try:
            if not path.is_file():
                return None
            size = path.stat().st_size
        except OSError as e:
            logger.warning("Could not stat %s: %s", path, e)
            return None

        max_bytes = self.config.max_file_size_mb * 1024 * 1024
        if size > max_bytes:
            logger.info("Skipping %s: %d bytes exceeds max_file_size_mb limit", path, size)
            return None

        try:
            data = path.read_bytes()
        except OSError as e:
            logger.warning("Could not read %s: %s", path, e)
            return None

        heuristic_result = run_heuristics(path, data)
        yara_matches = self.yara.scan(path)
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
