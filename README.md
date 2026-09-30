# Security Agent

An AI-assisted file and script security monitor. It watches a directory (e.g. `~/Downloads`)
for new or modified files, runs fast local static checks (YARA rules + heuristics), and
escalates anything suspicious to Claude for deep threat analysis, a quarantine
recommendation, and a written security report.

This is a **defensive** tool intended for monitoring your own systems and files you're
authorized to inspect. It never executes the files it analyzes - content is read as
bytes for analysis only.

**Platform note:** developed and tested on Linux. The symlink protection described in
[Safety model](#safety-model) is atomic and kernel-enforced there (and should behave the
same on macOS, also POSIX). **On Windows it is not equivalent** - it falls back to a
non-atomic check with a real race window, so don't point `watch_dir` at a folder that
other users or lower-privileged processes can also write to.

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
- **Symlinks are never followed, and this is enforced atomically, not just checked
  up front.** Anything that can write to the watched directory (which any dropped
  file already can, by definition) could otherwise swap a real file for a symlink
  between an early `is_symlink()` check and the later read - a TOCTOU race that would
  let a malicious file redirect the agent to read (and potentially send to the Claude
  API) something like `~/.ssh/id_rsa`. The agent opens files with `O_NOFOLLOW` so the
  open itself atomically refuses a symlink target, and YARA scans the bytes already
  read rather than reopening the path itself (which would reintroduce the same race).
  **On Windows, where `O_NOFOLLOW` doesn't exist, this falls back to a check-then-open
  (`lstat` then `open`) with the identical TOCTOU shape this section just described for
  POSIX before the fix - the atomic guarantee is POSIX-only.** In practice the risk is
  narrower there because creating a filesystem symlink on Windows normally requires
  elevated privileges (Developer Mode or admin), so a low-privilege process dropping
  files into the watched folder typically can't stage the race at all - but that's a
  property of the deployment, not a guarantee this code provides. **Do not point this
  agent at a folder on Windows that other users or lower-privileged processes can also
  write to.** The real fix is `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` (Windows'
  equivalent of an atomic no-follow open), which is out of scope for v1 - tracked as
  follow-up work, not silently assumed away.
- **Test coverage and what it does and doesn't prove.** The test suite exercises the
  heuristic scoring rules, the safety guards (a simulated symlink-swap race against the
  live `O_NOFOLLOW` open path, the auto-quarantine confidence floor, the
  truncated-excerpt block, a file deleted before processing, and a file deleted mid
  stability-poll), and an end-to-end run confirming YARA matches against in-memory bytes
  with a real `yara-python` install. All of this has only been run on Linux. The
  `O_NOFOLLOW` code path is therefore verified as described; the Windows fallback path
  is not exercised by the suite at all and should be treated as unverified, consistent
  with the caveat above.

### Why the symlink handling looks like this

The first version of the symlink fix checked `is_symlink()` once up front and then
called `stat()`/`read_bytes()` separately - both of those re-resolve the path and follow
symlinks. It passed a test with a symlink present from the start, and would have shipped
looking correct: a static check, a passing test, nothing in review to flag. It wasn't
actually closed until two more things happened - simulating the swap explicitly (create
a real file, delete it, replace it with a symlink, then open) to prove the race, and
noticing that `YaraScanner.scan()` took a path and let `yara-python` reopen the file
itself, bypassing the guard entirely from a second, independent code path. The lesson
generalizes past this one bug: a fix to a check-then-use race isn't verified by a test
that never constructs the race, and a guard placed at one call site doesn't hold if
another helper re-derives file access from the same path.

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
packed binary may yield little usable excerpt either way. **For packed Windows
executables in particular, treat the local heuristic/YARA score as the primary signal,
not the Claude verdict:** a string extract of a packed `.exe` often carries almost no
readable content, so Claude legitimately comes back low-confidence on exactly the files
where a real PE parser (import table, section entropy, entry-point section) would say
the most. That's expected behavior given the current excerpt strategy, not a bug -
proper PE structural analysis is a real gap, tracked as follow-up work rather than
something bolted on here.

## Configuration reference

See `config.example.yaml` for every option with inline comments: file size limits,
content excerpt size sent to Claude, the local risk score threshold that triggers
escalation, the Claude model/effort used, and logging level.

## Tests

```bash
pip install pytest
pytest
```

Coverage: heuristic scoring rules (encoded PowerShell, reverse shells, EICAR, double
extensions), the safety guards (symlink-swap race, auto-quarantine confidence floor,
truncated-excerpt block), and filesystem edge cases (file deleted before processing,
file deleted mid stability-poll). Run on Linux; see the platform note in
[Safety model](#safety-model) for what that does and doesn't cover on Windows.
