import json
import sys


def write_json(findings, output_path=None):
    data = json.dumps(findings, indent=2)
    if output_path:
        with open(output_path, 'w') as f:
            f.write(data)
    else:
        print(data)
