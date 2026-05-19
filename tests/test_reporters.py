import json
import io
import sys
from secretsweep.reporters.json_reporter import write_json
from secretsweep.reporters.sarif_reporter import write_sarif

SAMPLE_FINDINGS = [
    {
        "file": "config.py",
        "line": 5,
        "name": "AWS Access Key",
        "severity": "critical",
        "category": "cloud",
        "source": "file",
    },
    {
        "file": "app.py",
        "line": 12,
        "name": "Hardcoded Password",
        "severity": "high",
        "category": "config",
        "source": "file",
    },
]


def _capture_stdout(fn, *args, **kwargs):
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        fn(*args, **kwargs)
    finally:
        sys.stdout = old
    return buf.getvalue()


def test_json_output_is_valid_json():
    output = _capture_stdout(write_json, SAMPLE_FINDINGS)
    data = json.loads(output)
    assert isinstance(data, list)
    assert len(data) == 2


def test_json_output_has_all_fields():
    output = _capture_stdout(write_json, SAMPLE_FINDINGS)
    data = json.loads(output)
    assert data[0]['name'] == 'AWS Access Key'
    assert data[0]['severity'] == 'critical'


def test_sarif_output_is_valid_json():
    output = _capture_stdout(write_sarif, SAMPLE_FINDINGS)
    data = json.loads(output)
    assert data['version'] == '2.1.0'
    assert 'runs' in data


def test_sarif_has_results():
    output = _capture_stdout(write_sarif, SAMPLE_FINDINGS)
    data = json.loads(output)
    results = data['runs'][0]['results']
    assert len(results) == 2


def test_sarif_critical_maps_to_error():
    output = _capture_stdout(write_sarif, SAMPLE_FINDINGS)
    data = json.loads(output)
    results = data['runs'][0]['results']
    critical = next(r for r in results if r['ruleId'] == 'aws_access_key')
    assert critical['level'] == 'error'
