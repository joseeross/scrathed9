from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class AgentConfig:
    watch_dir: str = ""
    quarantine_dir: str = "./quarantine"
    report_dir: str = "./reports"
    rules_dir: str = "./rules"
    ignore_patterns: list[str] = field(
        default_factory=lambda: [".git", "__pycache__", "node_modules", ".venv"]
    )
    max_file_size_mb: int = 50
    content_excerpt_bytes: int = 200_000
    debounce_seconds: float = 2.0
    local_risk_threshold: int = 25
    auto_quarantine: bool = False
    auto_quarantine_confidence: float = 0.85
    model: str = "claude-opus-5-5"
    claude_effort: str = "medium"
    max_tokens: int = 2048
    log_level: str = "INFO"


def load_config(path: Optional[Path] = None) -> AgentConfig:
    """Load config from a YAML file (explicit path, then ./config.yaml), falling back to defaults."""
    data: dict = {}
    candidate = path if path is not None else Path("config.yaml")

    if path is not None and not candidate.exists():
        raise FileNotFoundError(f"Config file not found: {candidate}")

    if candidate.exists():
        with candidate.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    valid_fields = set(AgentConfig.__dataclass_fields__)
    filtered = {k: v for k, v in data.items() if k in valid_fields}
    return AgentConfig(**filtered)
