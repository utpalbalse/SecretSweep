import json
import os


def _key(finding):
    return f"{finding.get('file', '')}:{finding.get('line', '')}:{finding.get('name', '')}"


def load_baseline(path):
    if not os.path.isfile(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return {_key(f) for f in data}


def write_baseline(findings, path):
    with open(path, 'w') as f:
        json.dump(findings, f, indent=2)


def filter_new_findings(findings, baseline_path):
    baseline = load_baseline(baseline_path)
    return [f for f in findings if _key(f) not in baseline]
