import json
from secretsweep import __version__

_LEVEL = {'critical': 'error', 'high': 'warning', 'medium': 'note', 'low': 'note'}


def write_sarif(findings, output_path=None):
    rules = {}
    for f in findings:
        rule_id = f['name'].lower().replace(' ', '_').replace('/', '_')
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f['name'],
                "shortDescription": {"text": f['name']},
                "properties": {"severity": f.get('severity', 'high')},
            }

    results = []
    for f in findings:
        rule_id = f['name'].lower().replace(' ', '_').replace('/', '_')
        result = {
            "ruleId": rule_id,
            "level": _LEVEL.get(f.get('severity', 'high'), 'warning'),
            "message": {"text": f"Detected {f['name']}"},
        }
        uri = f.get('file', '').replace('\\', '/')
        line = f.get('line')
        if uri and line:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }]
        elif uri:
            result["locations"] = [{
                "physicalLocation": {"artifactLocation": {"uri": uri}}
            }]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecretSweep",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    data = json.dumps(sarif, indent=2)
    if output_path:
        with open(output_path, 'w') as f:
            f.write(data)
    else:
        print(data)
