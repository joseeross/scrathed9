from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import anthropic

from .config import AgentConfig

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior cybersecurity analyst performing static triage on a file flagged \
by an automated file-integrity monitor. You are reviewing evidence only - you cannot execute code \
and have no network access. Analyze the metadata, local heuristic findings, and content excerpt \
provided, then decide whether the file is benign, suspicious, or malicious.

Respond with a single JSON object and nothing else, matching exactly this shape:
{
  "verdict": "benign" | "suspicious" | "malicious",
  "confidence": <float 0.0-1.0>,
  "threat_type": <short string, e.g. "none", "trojan", "webshell", "ransomware-precursor", \
"obfuscated-script", "credential-stealer", "unknown">,
  "summary": <2-4 sentence plain-English explanation an analyst could paste into a ticket>,
  "key_indicators": [<short strings, each one concrete indicator you relied on>],
  "quarantine_recommended": <true | false>,
  "remediation_steps": [<short imperative strings, e.g. "Isolate host from network">]
}

Be conservative: only recommend quarantine when indicators are genuinely consistent with malicious \
intent, not merely unusual. Base your verdict strictly on the evidence given - do not assume \
additional context you were not given. If the excerpt is truncated or the file is binary with no \
readable strings, say so in the summary and lower your confidence accordingly."""


@dataclass
class ClaudeVerdict:
    verdict: str
    confidence: float
    threat_type: str
    summary: str
    key_indicators: list[str] = field(default_factory=list)
    quarantine_recommended: bool = False
    remediation_steps: list[str] = field(default_factory=list)
    raw_response: str = ""
    error: Optional[str] = None


def _build_user_prompt(
    file_meta: dict[str, Any],
    local_findings: list[str],
    yara_matches: list[str],
    excerpt: str,
    truncated: bool,
) -> str:
    return json.dumps(
        {
            "file_metadata": file_meta,
            "local_heuristic_findings": local_findings,
            "yara_matches": yara_matches,
            "content_excerpt_truncated": truncated,
            "content_excerpt": excerpt,
        },
        indent=2,
    )


def _parse_verdict(text: str) -> ClaudeVerdict:
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        payload = json.loads(text[start:end])
        return ClaudeVerdict(
            verdict=payload.get("verdict", "unknown"),
            confidence=float(payload.get("confidence", 0.0)),
            threat_type=payload.get("threat_type", "unknown"),
            summary=payload.get("summary", ""),
            key_indicators=payload.get("key_indicators", []) or [],
            quarantine_recommended=bool(payload.get("quarantine_recommended", False)),
            remediation_steps=payload.get("remediation_steps", []) or [],
            raw_response=text,
        )
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("Failed to parse Claude response as JSON: %s", e)
        return ClaudeVerdict(
            verdict="unknown",
            confidence=0.0,
            threat_type="unknown",
            summary="Could not parse a structured verdict from Claude's response.",
            raw_response=text,
            error=str(e),
        )


class ClaudeAnalyzer:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.client = anthropic.Anthropic()

    def analyze(
        self,
        file_meta: dict[str, Any],
        local_findings: list[str],
        yara_matches: list[str],
        excerpt: str,
        truncated: bool,
    ) -> ClaudeVerdict:
        user_prompt = _build_user_prompt(file_meta, local_findings, yara_matches, excerpt, truncated)
        try:
            response = self.client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=SYSTEM_PROMPT,
                output_config={"effort": self.config.claude_effort},
                messages=[{"role": "user", "content": user_prompt}],
            )
        except anthropic.RateLimitError as e:
            logger.error("Claude API rate limited analyzing %s: %s", file_meta.get("path"), e)
            return ClaudeVerdict(
                verdict="unknown", confidence=0.0, threat_type="unknown",
                summary=f"Claude API rate limited: {e}", error=str(e),
            )
        except anthropic.APIStatusError as e:
            logger.error("Claude API error analyzing %s: %s", file_meta.get("path"), e)
            return ClaudeVerdict(
                verdict="unknown", confidence=0.0, threat_type="unknown",
                summary=f"Claude API error: {e}", error=str(e),
            )
        except anthropic.APIConnectionError as e:
            logger.error("Claude API connection error analyzing %s: %s", file_meta.get("path"), e)
            return ClaudeVerdict(
                verdict="unknown", confidence=0.0, threat_type="unknown",
                summary=f"Claude API connection error: {e}", error=str(e),
            )
        except Exception as e:
            # Catches misconfiguration (e.g. missing credentials raises a bare TypeError
            # from the SDK, not an anthropic.* exception) so one bad file/config never
            # crashes the watcher loop.
            logger.exception("Unexpected error calling Claude API for %s", file_meta.get("path"))
            return ClaudeVerdict(
                verdict="unknown", confidence=0.0, threat_type="unknown",
                summary=f"Unexpected error calling Claude API: {e}", error=str(e),
            )

        if response.stop_reason == "refusal":
            return ClaudeVerdict(
                verdict="unknown", confidence=0.0, threat_type="unknown",
                summary="Claude declined to analyze this file.", error="refusal",
            )

        text = "".join(block.text for block in response.content if block.type == "text")
        return _parse_verdict(text)
