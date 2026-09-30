# Security Agent

An AI-assisted file and script security monitor. It watches a directory (e.g. `~/Downloads`)
for new or modified files, runs fast local static checks (YARA rules + heuristics), and
escalates anything suspicious to Claude for deep threat analysis, a quarantine
recommendation, and a written security report.

This is a **defensive** tool intended for monitoring your own systems and files you're
authorized to inspect. It never executes or opens the files it analyzes.

## How it works

```
new/modified file
      |
      v
local heuristics (entropy, suspicious strings, risky extensions, macros, EICAR)
      |
      v
YARA rule matching (optional, degrades gracefully if yara-python isn't installed)
      |
      v
risk score >= local_risk_threshold?  --no--> logged, done
      |
     yes
      v
Claude API: deep analysis (verdict, confidence, threat type, indicators, remediation)
      |
      v
verdict == malicious & quarantine_recommended?
      |
      +--> auto_quarantine: true  --> moved (not deleted) to quarantine_dir + manifest logged
      |
      +--> auto_quarantine: false (default) --> recommendation written to report, no action taken
```

Every scan produces a line in `reports/events.jsonl` and, for anything non-clean, a
per-file Markdown report under `reports/`.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit in your ANTHROPIC_API_KEY
cp config.example.yaml config.yaml  # then edit watch_dir, etc.
```

`yara-python` needs the `libyara` system library on some platforms. If it fails to
install, leave it out - the agent still runs; it just skips YARA matching and relies on
the built-in heuristics.

## Usage

One-shot scan of everything already in a directory:

```bash
python -m security_agent --config config.yaml scan
```

Continuously watch a directory:

```bash
python -m security_agent --config config.yaml watch
```

CLI flags override the config file: `--watch-dir`, `--quarantine-dir`, `--report-dir`,
`--rules-dir`, `--auto-quarantine`, `--log-level`. Global flags must come before the
`scan`/`watch` subcommand, e.g.:

```bash
python -m security_agent --watch-dir ~/Downloads --auto-quarantine watch
```

## Safety model

- **Recommend-only by default.** `auto_quarantine` defaults to `false`. Suspicious files
  are reported, not moved, until you opt in.
- **Quarantine is a move, never a delete.** Files go to a timestamped subfolder under
  `quarantine_dir`, with every action logged to `quarantine/manifest.jsonl` (original
  path, new path, reason, timestamp) so nothing is unrecoverable.
- **Auto-quarantine, when enabled, is gated on Claude's confidence** via
  `auto_quarantine_confidence`, with a hard floor of `0.9` enforced in code regardless
  of what the config sets - a high-confidence malicious verdict is required, not just
  "suspicious."
- **Auto-quarantine never fires on a truncated content excerpt**, no matter how
  confident the verdict - a verdict built on a partial view of the file isn't a safe
  basis for an unattended action. It still gets written to the report as a
  recommendation.
- **The agent never executes analyzed files.** Content is read as bytes; binaries are
  reduced to printable-string extraction before being sent to Claude.
- **Symlinks are never followed.** A dropped symlink pointing outside the watched
  directory (e.g. at `~/.ssh/id_rsa`) is skipped rather than read and potentially sent
  to the Claude API.

## Extending detection

`rules/default.yar` is a set of illustrative starter rules, not a production detection
ruleset - they cover a few common patterns (encoded PowerShell, reverse shells, PHP
webshells, shadow-copy deletion, the EICAR test string) but haven't been tuned against
real-world corpora and shouldn't be relied on alone. Add your own `.yar`/`.yara` files
under `rules/` - they're picked up automatically. Heuristic patterns and extension risk
weights live in `security_agent/heuristics.py`.

Known limitations: double-extension detection is a heuristic signal, not a bypass-proof
control - it won't catch Unicode/RTL-override tricks or trailing-dot games some
platforms tolerate. Binary files are reduced to extracted printable strings for Claude's
review, not structural analysis (imports, sections, per-section entropy) - a heavily
packed binary may yield little usable excerpt either way.

## Configuration reference

See `config.example.yaml` for every option with inline comments: file size limits,
content excerpt size sent to Claude, the local risk score threshold that triggers
escalation, the Claude model/effort used, and logging level.

## Tests

```bash
pip install pytest
pytest
```
