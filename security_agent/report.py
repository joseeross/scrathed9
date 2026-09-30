from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanReport:
    path: str
    timestamp: str
    file_size: int
    local_risk_score: int
    local_findings: list[str]
    yara_matches: list[str]
    escalated_to_claude: bool
    claude_verdict: Optional[dict[str, Any]]
    action_taken: str


class ReportWriter:
    def __init__(self, report_dir: Path):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.report_dir / "events.jsonl"

    def write(self, report: ScanReport) -> Path:
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(report)) + "\n")

        if report.local_risk_score > 0 or report.escalated_to_claude:
            safe_name = Path(report.path).name.replace("/", "_")
            detail_path = self.report_dir / f"{report.timestamp}_{safe_name}.md"
            detail_path.write_text(_render_markdown(report), encoding="utf-8")
            return detail_path
        return self.events_path


def _render_markdown(report: ScanReport) -> str:
    lines = [
        f"# Security Report: {report.path}",
        "",
        f"- **Timestamp:** {report.timestamp}",
        f"- **File size:** {report.file_size} bytes",
        f"- **Local risk score:** {report.local_risk_score}",
        f"- **Action taken:** {report.action_taken}",
        "",
        "## Local heuristic findings",
    ]
    lines += [f"- {finding}" for finding in report.local_findings] or ["- None"]
    lines += ["", "## YARA matches"]
    lines += [f"- {m}" for m in report.yara_matches] or ["- None"]

    if report.claude_verdict:
        v = report.claude_verdict
        lines += [
            "",
            "## Claude analysis",
            f"- **Verdict:** {v.get('verdict')}",
            f"- **Confidence:** {v.get('confidence')}",
            f"- **Threat type:** {v.get('threat_type')}",
            f"- **Quarantine recommended:** {v.get('quarantine_recommended')}",
            "",
            f"**Summary:** {v.get('summary')}",
            "",
            "### Key indicators",
        ]
        lines += [f"- {i}" for i in v.get("key_indicators", [])] or ["- None"]
        lines += ["", "### Remediation steps"]
        lines += [f"- {s}" for s in v.get("remediation_steps", [])] or ["- None"]

    return "\n".join(lines) + "\n"
