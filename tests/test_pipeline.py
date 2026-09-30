from pathlib import Path

from security_agent.claude_analyzer import ClaudeVerdict
from security_agent.config import AgentConfig
from security_agent.pipeline import SecurityPipeline


def _make_config(tmp_path: Path, **overrides) -> AgentConfig:
    config = AgentConfig(
        watch_dir=str(tmp_path),
        quarantine_dir=str(tmp_path / "quarantine"),
        report_dir=str(tmp_path / "reports"),
        rules_dir=str(tmp_path / "rules"),
        local_risk_threshold=1,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


def _stub_verdict(confidence: float) -> ClaudeVerdict:
    return ClaudeVerdict(
        verdict="malicious",
        confidence=confidence,
        threat_type="trojan",
        summary="test verdict",
        quarantine_recommended=True,
    )


def test_symlink_is_never_followed(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("super secret content")
    link = tmp_path / "dropped.txt"
    link.symlink_to(secret)

    pipeline = SecurityPipeline(_make_config(tmp_path))
    report = pipeline.process(link)

    assert report is None


def test_auto_quarantine_blocked_when_excerpt_truncated(tmp_path):
    config = _make_config(tmp_path, auto_quarantine=True, auto_quarantine_confidence=0.5,
                           content_excerpt_bytes=10)
    pipeline = SecurityPipeline(config)
    pipeline.claude.analyze = lambda *a, **k: _stub_verdict(confidence=0.99)

    target = tmp_path / "malware.ps1"
    target.write_text("-enc " + "A" * 50)

    report = pipeline.process(target)

    assert report.action_taken == "quarantine_recommended"
    assert target.exists()


def test_auto_quarantine_blocked_below_hard_confidence_floor(tmp_path):
    config = _make_config(tmp_path, auto_quarantine=True, auto_quarantine_confidence=0.1,
                           content_excerpt_bytes=10_000)
    pipeline = SecurityPipeline(config)
    pipeline.claude.analyze = lambda *a, **k: _stub_verdict(confidence=0.5)

    target = tmp_path / "malware.ps1"
    target.write_text("-enc AAAA")

    report = pipeline.process(target)

    assert report.action_taken == "quarantine_recommended"
    assert target.exists()


def test_auto_quarantine_moves_file_above_hard_floor(tmp_path):
    config = _make_config(tmp_path, auto_quarantine=True, auto_quarantine_confidence=0.1,
                           content_excerpt_bytes=10_000)
    pipeline = SecurityPipeline(config)
    pipeline.claude.analyze = lambda *a, **k: _stub_verdict(confidence=0.95)

    target = tmp_path / "malware.ps1"
    target.write_text("-enc AAAA")

    report = pipeline.process(target)

    assert report.action_taken == "quarantined"
    assert not target.exists()
