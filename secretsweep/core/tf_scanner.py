import json
import regex
from secretsweep.detectors.patterns import PATTERNS


def scan_terraform_state(filepath):
    findings = []
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            state = json.load(f)
    except Exception:
        return findings

    for name, output in state.get('outputs', {}).items():
        _scan_value(str(output.get('value', '')), filepath, f"output:{name}", findings)

    for resource in state.get('resources', []):
        rtype = resource.get('type', 'resource')
        for instance in resource.get('instances', []):
            _scan_dict(instance.get('attributes', {}), filepath, rtype, findings)

    return findings


def _scan_value(value, filepath, context, findings):
    for pattern in PATTERNS:
        if regex.search(pattern['pattern'], value):
            findings.append({
                "file": filepath,
                "line": None,
                "name": pattern['name'],
                "severity": pattern['severity'],
                "category": pattern.get('category', 'unknown'),
                "source": "terraform_state",
                "tf_context": context,
            })


def _scan_dict(d, filepath, context, findings, depth=0):
    if depth > 5 or not isinstance(d, dict):
        return
    for key, value in d.items():
        ctx = f"{context}.{key}"
        if isinstance(value, str):
            _scan_value(value, filepath, ctx, findings)
        elif isinstance(value, dict):
            _scan_dict(value, filepath, ctx, findings, depth + 1)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    _scan_value(item, filepath, f"{ctx}[]", findings)
                elif isinstance(item, dict):
                    _scan_dict(item, filepath, f"{ctx}[]", findings, depth + 1)
