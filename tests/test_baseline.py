import os
import tempfile
from secretsweep.core.baseline import load_baseline, write_baseline, filter_new_findings

FINDINGS = [
    {"file": "config.py", "line": 5, "name": "AWS Access Key", "severity": "critical"},
    {"file": "app.py", "line": 12, "name": "Hardcoded Password", "severity": "high"},
]


def _tmp_path():
    d = tempfile.mkdtemp()
    return os.path.join(d, 'baseline.json')


def test_write_and_load_baseline():
    path = _tmp_path()
    write_baseline(FINDINGS, path)
    baseline = load_baseline(path)
    assert len(baseline) == 2


def test_filter_removes_known_findings():
    path = _tmp_path()
    write_baseline(FINDINGS, path)
    result = filter_new_findings(FINDINGS, path)
    assert len(result) == 0


def test_filter_keeps_new_findings():
    path = _tmp_path()
    write_baseline(FINDINGS[:1], path)
    result = filter_new_findings(FINDINGS, path)
    assert len(result) == 1
    assert result[0]['name'] == 'Hardcoded Password'


def test_load_nonexistent_baseline_returns_empty():
    baseline = load_baseline('/nonexistent/baseline.json')
    assert len(baseline) == 0
