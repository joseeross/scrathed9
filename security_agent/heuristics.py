from __future__ import annotations

import math
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

EICAR_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

HIGH_RISK_EXTENSIONS: dict[str, int] = {
    ".exe": 15, ".scr": 20, ".vbs": 20, ".vbe": 20, ".jse": 20, ".wsf": 20,
    ".hta": 20, ".ps1": 12, ".psm1": 12, ".bat": 10, ".cmd": 10, ".com": 20,
    ".pif": 25, ".jar": 8, ".msi": 10, ".dll": 8, ".reg": 10, ".js": 6,
}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.\w{2,5}\.(exe|scr|js|vbs|bat|cmd|com|pif|hta|jse|wsf)$", re.IGNORECASE
)

CONTENT_PATTERNS: list[tuple[re.Pattern, int, str]] = [
    (re.compile(rb"-enc(odedcommand)?\s", re.IGNORECASE), 25, "PowerShell encoded command"),
    (re.compile(rb"invoke-expression|iex\s*\(", re.IGNORECASE), 20, "PowerShell Invoke-Expression"),
    (re.compile(rb"downloadstring|downloadfile|net\.webclient", re.IGNORECASE), 20, "Remote payload download pattern"),
    (re.compile(rb"frombase64string", re.IGNORECASE), 15, "Base64-decoded execution"),
    (re.compile(rb"disable-realtimemonitoring|set-mppreference", re.IGNORECASE), 30, "Attempt to disable Windows Defender"),
    (re.compile(rb"vssadmin delete shadows|wbadmin delete", re.IGNORECASE), 35, "Shadow copy / backup deletion (ransomware indicator)"),
    (re.compile(rb"reg(\.exe)? add .{0,80}\\run\b", re.IGNORECASE), 15, "Registry Run-key persistence"),
    (re.compile(rb"schtasks(\.exe)? .{0,40}/create", re.IGNORECASE), 12, "Scheduled task persistence"),
    (re.compile(rb"curl .{0,120}\|\s*(bash|sh)|wget .{0,120}\|\s*(bash|sh)", re.IGNORECASE), 20, "Pipe-to-shell download"),
    (re.compile(rb"eval\s*\(\s*base64_decode", re.IGNORECASE), 25, "PHP obfuscated eval (webshell pattern)"),
    (re.compile(rb"eval\(\$_(post|get|request)", re.IGNORECASE), 30, "PHP webshell (eval on user input)"),
    (re.compile(rb"/dev/tcp/\d", re.IGNORECASE), 35, "Bash reverse shell (/dev/tcp)"),
    (re.compile(rb"nc\s+-e\s+/bin/(ba)?sh", re.IGNORECASE), 35, "Netcat reverse shell"),
    (re.compile(rb"bash -i >&"), 35, "Interactive reverse shell pattern"),
]

SCRIPT_LIKE_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".py", ".sh", ".hta", ".jse", ".wsf"}
OFFICE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx"}


@dataclass
class HeuristicResult:
    score: int
    entropy: float
    findings: list[str] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extension_findings(path: Path) -> tuple[int, list[str]]:
    score = 0
    findings: list[str] = []
    suffix = path.suffix.lower()
    if suffix in HIGH_RISK_EXTENSIONS:
        weight = HIGH_RISK_EXTENSIONS[suffix]
        score += weight
        findings.append(f"High-risk extension {suffix} (+{weight})")
    if DOUBLE_EXTENSION_RE.search(path.name):
        score += 25
        findings.append("Double extension masking true file type (+25)")
    return score, findings


def _content_findings(data: bytes) -> tuple[int, list[str]]:
    score = 0
    findings: list[str] = []
    if EICAR_STRING in data:
        score += 100
        findings.append("EICAR antivirus test signature detected (+100)")
    for pattern, weight, description in CONTENT_PATTERNS:
        if pattern.search(data):
            score += weight
            findings.append(f"{description} (+{weight})")
    return score, findings


def _macro_findings(path: Path) -> tuple[int, list[str]]:
    if path.suffix.lower() not in OFFICE_EXTENSIONS:
        return 0, []
    try:
        with zipfile.ZipFile(path) as zf:
            if any("vbaProject.bin" in name for name in zf.namelist()):
                return 20, ["Office document contains embedded VBA macro project (+20)"]
    except (zipfile.BadZipFile, OSError):
        pass
    return 0, []


def _entropy_findings(data: bytes, path: Path) -> tuple[int, list[str], float]:
    entropy = shannon_entropy(data[:262144])
    is_script_like = path.suffix.lower() in SCRIPT_LIKE_EXTENSIONS
    if is_script_like and entropy > 6.5 and len(data) > 256:
        finding = f"High entropy ({entropy:.2f}) for a script file - possible obfuscation/packing (+15)"
        return 15, [finding], entropy
    return 0, [], entropy


def analyze_file(path: Path, data: bytes) -> HeuristicResult:
    score = 0
    findings: list[str] = []

    ext_score, ext_findings = _extension_findings(path)
    score += ext_score
    findings += ext_findings

    content_score, content_findings = _content_findings(data)
    score += content_score
    findings += content_findings

    macro_score, macro_findings = _macro_findings(path)
    score += macro_score
    findings += macro_findings

    entropy_score, entropy_findings, entropy = _entropy_findings(data, path)
    score += entropy_score
    findings += entropy_findings

    return HeuristicResult(score=score, entropy=entropy, findings=findings)
