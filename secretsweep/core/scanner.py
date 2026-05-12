import os
import regex
from secretsweep.detectors.patterns import PATTERNS


def scan_file(filepath):
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for pattern in PATTERNS:
                    matches = regex.findall(pattern["pattern"], line)
                    if matches:
                        findings.append({
                            "file": filepath,
                            "line": line_number,
                            "name": pattern["name"],
                            "severity": pattern["severity"],
                        })
    except (PermissionError, IsADirectoryError):
        pass

    return findings


def scan_directory(path):
    all_findings = []

    for root, dirs, files in os.walk(path):
        for filename in files:
            filepath = os.path.join(root, filename)
            findings = scan_file(filepath)
            all_findings.extend(findings)

    return all_findings