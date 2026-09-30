from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import yara

    _YARA_AVAILABLE = True
except ImportError:
    yara = None
    _YARA_AVAILABLE = False


class YaraScanner:
    """Wraps yara-python; degrades to no-op if the library or rules are unavailable."""

    def __init__(self, rules_dir: str):
        self.rules = None
        if not _YARA_AVAILABLE:
            logger.warning(
                "yara-python not installed; YARA scanning disabled. "
                "Install with `pip install yara-python` to enable it."
            )
            return

        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning("YARA rules directory not found: %s", rules_dir)
            return

        rule_files = {p.stem: str(p) for p in rules_path.glob("*.yar")}
        rule_files.update({p.stem: str(p) for p in rules_path.glob("*.yara")})

        if not rule_files:
            logger.warning("No YARA rule files (.yar/.yara) found in %s", rules_dir)
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
        except Exception:
            logger.exception("Failed to compile YARA rules from %s", rules_dir)
            self.rules = None

    def scan(self, data: bytes) -> list[str]:
        """Matches against already-read bytes, not a path - matching by path would
        have yara-python reopen the file itself, reintroducing a TOCTOU window
        after the caller's own symlink-safe read."""
        if self.rules is None:
            return []
        try:
            matches = self.rules.match(data=data)
            return [m.rule for m in matches]
        except Exception:
            logger.exception("YARA scan failed")
            return []
