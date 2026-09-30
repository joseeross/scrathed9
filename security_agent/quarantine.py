from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class Quarantine:
    """Moves files into a timestamped quarantine folder. Never deletes - always reversible."""

    def __init__(self, quarantine_dir: Path):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "manifest.jsonl"

    def move(self, source: Path, reason: str) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        dest_dir = self.quarantine_dir / timestamp
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / source.name

        shutil.move(str(source), str(dest))

        record = {
            "timestamp": timestamp,
            "original_path": str(source),
            "quarantined_path": str(dest),
            "reason": reason,
        }
        with self.manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        logger.warning("Quarantined %s -> %s (%s)", source, dest, reason)
        return dest
