from secretsweep.core.entropy_scanner import scan_content_for_entropy


def test_high_entropy_string_detected():
    content = "secret=xK9mP2qR8nL4vB7cJ3hF6wY1tG5sD0aE"
    findings = scan_content_for_entropy(content, "test.py")
    assert len(findings) > 0
    assert findings[0]["name"] == "High Entropy String"
    assert findings[0]["source"] == "entropy"


def test_low_entropy_string_not_detected():
    content = "hello = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    findings = scan_content_for_entropy(content, "test.py")
    assert len(findings) == 0


def test_git_hash_not_detected():
    content = "commit = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    findings = scan_content_for_entropy(content, "test.py")
    assert len(findings) == 0


def test_finding_has_correct_fields():
    content = "token=xK9mP2qR8nL4vB7cJ3hF6wY1tG5sD0aE"
    findings = scan_content_for_entropy(content, "config.py")
    assert len(findings) > 0
    f = findings[0]
    assert "file" in f
    assert "line" in f
    assert "matched" in f
    assert f["category"] == "entropy"
