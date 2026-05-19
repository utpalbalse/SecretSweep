from secretsweep.core.deduplicator import deduplicate

_FINDING = {
    "file": "config.py",
    "line": 5,
    "name": "AWS Access Key",
    "severity": "critical",
    "category": "cloud",
    "source": "file",
}


def test_identical_findings_deduplicated():
    findings = [_FINDING.copy(), _FINDING.copy()]
    result = deduplicate(findings)
    assert len(result) == 1


def test_different_lines_not_deduplicated():
    a = {**_FINDING, "line": 5}
    b = {**_FINDING, "line": 10}
    result = deduplicate([a, b])
    assert len(result) == 2


def test_different_files_not_deduplicated():
    a = {**_FINDING, "file": "config.py"}
    b = {**_FINDING, "file": "settings.py"}
    result = deduplicate([a, b])
    assert len(result) == 2


def test_different_names_not_deduplicated():
    a = {**_FINDING, "name": "AWS Access Key"}
    b = {**_FINDING, "name": "Hardcoded Password"}
    result = deduplicate([a, b])
    assert len(result) == 2


def test_git_findings_deduplicated_by_commit():
    git_finding = {
        "file": "config.py",
        "line": None,
        "name": "AWS Access Key",
        "severity": "critical",
        "commit": "abc12345",
        "source": "git_history",
    }
    result = deduplicate([git_finding.copy(), git_finding.copy()])
    assert len(result) == 1


def test_empty_list_returns_empty():
    assert deduplicate([]) == []


def test_order_preserved():
    a = {**_FINDING, "file": "a.py"}
    b = {**_FINDING, "file": "b.py"}
    c = {**_FINDING, "file": "c.py"}
    result = deduplicate([a, b, c])
    assert [f['file'] for f in result] == ['a.py', 'b.py', 'c.py']
