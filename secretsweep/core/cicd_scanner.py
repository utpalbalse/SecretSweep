import glob
import os

import yaml

from secretsweep.core.scanner import scan_file_content

_SECRET_KEY_WORDS = {
    'key', 'token', 'secret', 'password', 'passwd', 'pwd',
    'credential', 'credentials', 'api', 'auth', 'private', 'access',
}

_CICD_ROOT_FILES = {'.gitlab-ci.yml', '.circleci/config.yml', 'bitbucket-pipelines.yml'}


def _key_is_sensitive(key):
    key_lower = key.lower()
    return any(word in key_lower for word in _SECRET_KEY_WORDS)


def _walk_dict(obj, filepath, findings, seen_raw_names):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.strip() and _key_is_sensitive(str(k)):
                synthetic = f"{k}={v}"
                for f in scan_file_content(synthetic, filepath):
                    if f['name'] not in seen_raw_names:
                        f['source'] = 'cicd'
                        f['cicd_key'] = str(k)
                        findings.append(f)
                        seen_raw_names.add(f['name'])
            _walk_dict(v, filepath, findings, seen_raw_names)
    elif isinstance(obj, list):
        for item in obj:
            _walk_dict(item, filepath, findings, seen_raw_names)


def scan_cicd_file(filepath):
    findings = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read()
    except (PermissionError, IsADirectoryError):
        return findings

    for f in scan_file_content(content, filepath):
        f['source'] = 'cicd'
        findings.append(f)

    seen_raw_names = {f['name'] for f in findings}

    try:
        data = yaml.safe_load(content)
    except Exception:
        return findings

    _walk_dict(data, filepath, findings, seen_raw_names)
    return findings


def scan_cicd_directory(repo_path):
    findings = []
    checked = set()

    for rel in _CICD_ROOT_FILES:
        full = os.path.join(repo_path, rel)
        if os.path.isfile(full) and full not in checked:
            checked.add(full)
            findings.extend(scan_cicd_file(full))

    pattern = os.path.join(repo_path, '.github', 'workflows', '*.yml')
    for full in glob.glob(pattern):
        if full not in checked:
            checked.add(full)
            findings.extend(scan_cicd_file(full))

    return findings
