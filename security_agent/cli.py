from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .config import load_config
from .pipeline import SecurityPipeline
from .watcher import run_watch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-agent",
        description="AI-assisted file and script security monitor.",
    )
    parser.add_argument("--config", type=Path, default=None, help="Path to a YAML config file")
    parser.add_argument("--watch-dir", type=Path, default=None)
    parser.add_argument("--quarantine-dir", type=Path, default=None)
    parser.add_argument("--report-dir", type=Path, default=None)
    parser.add_argument("--rules-dir", type=Path, default=None)
    parser.add_argument(
        "--auto-quarantine", action="store_true", default=False,
        help="Automatically move high-confidence malicious files to quarantine (default: recommend only)",
    )
    parser.add_argument("--log-level", default=None)

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("watch", help="Watch a directory continuously for new/modified files")
    sub.add_parser("scan", help="Scan existing files in a directory once, then exit")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.watch_dir:
        config.watch_dir = str(args.watch_dir)
    if args.quarantine_dir:
        config.quarantine_dir = str(args.quarantine_dir)
    if args.report_dir:
        config.report_dir = str(args.report_dir)
    if args.rules_dir:
        config.rules_dir = str(args.rules_dir)
    if args.auto_quarantine:
        config.auto_quarantine = True
    if args.log_level:
        config.log_level = args.log_level

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger(__name__)

    if not config.watch_dir:
        parser.error("watch_dir must be set via --watch-dir or a config file")

    watch_dir = Path(config.watch_dir)
    if not watch_dir.exists():
        parser.error(f"watch directory does not exist: {watch_dir}")

    if config.auto_quarantine:
        logger.warning(
            "auto_quarantine is ENABLED: files Claude flags as malicious with confidence >= %s "
            "will be moved to %s automatically.",
            config.auto_quarantine_confidence, config.quarantine_dir,
        )

    if args.command == "scan":
        pipeline = SecurityPipeline(config)
        count = 0
        for file_path in watch_dir.rglob("*"):
            if file_path.is_file():
                pipeline.process(file_path)
                count += 1
        logger.info("Scan complete: %d files processed", count)
        return 0

    if args.command == "watch":
        run_watch(config)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
