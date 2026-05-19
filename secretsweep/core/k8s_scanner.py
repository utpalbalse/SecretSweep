import base64
import regex
from secretsweep.detectors.patterns import PATTERNS


def scan_kubernetes_secret(filepath):
    findings = []
    try:
        import yaml
    except ImportError:
        return findings

    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            docs = list(yaml.safe_load_all(f))
    except Exception:
        return findings

    for doc in docs:
        if not isinstance(doc, dict) or doc.get('kind') != 'Secret':
            continue
        data = doc.get('data') or {}
        for k8s_key, value in data.items():
            if not value:
                continue
            try:
                decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            except Exception:
                continue
            for pattern in PATTERNS:
                if regex.search(pattern['pattern'], decoded):
                    findings.append({
                        "file": filepath,
                        "line": None,
                        "name": pattern['name'],
                        "severity": pattern['severity'],
                        "category": pattern.get('category', 'unknown'),
                        "source": "k8s_secret",
                        "k8s_key": k8s_key,
                    })

    return findings
