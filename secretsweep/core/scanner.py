import fnmatch
import os
import regex
from secretsweep.detectors.patterns import PATTERNS

_ARCHIVE_EXTS = {'.zip', '.tar', '.gz', '.tgz', '.bz2'}
_YAML_EXTS = {'.yaml', '.yml'}

DEFAULT_SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', 'venv', '.venv', 'env',
    'dist', 'build', 'target', '.pytest_cache', '.tox', 'vendor',
    'bower_components', '.idea', '.vscode', 'site-packages',
    '.mypy_cache', '.ruff_cache', 'htmlcov', '.eggs',
}

_SKIP_DIR_PATTERNS = ['*.egg-info', '*.dist-info']


def _should_skip_dir(dirname):
    if dirname in DEFAULT_SKIP_DIRS:
        return True
    return any(fnmatch.fnmatch(dirname, p) for p in _SKIP_DIR_PATTERNS)


def _is_binary(filepath):
    try:
        with open(filepath, 'rb') as f:
            return b'\x00' in f.read(8192)
    except Exception:
        return True


def scan_file_content(content, filepath):
    findings = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern in PATTERNS:
            if regex.search(pattern['pattern'], line):
                findings.append({
                    "file": filepath,
                    "line": line_number,
                    "name": pattern['name'],
                    "severity": pattern['severity'],
                    "category": pattern.get('category', 'unknown'),
                    "source": "file",
                })
    return findings


def scan_file(filepath, entropy=False, config=None):
    findings = []
    if _is_binary(filepath):
        return findings
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (PermissionError, IsADirectoryError):
        return findings

    findings.extend(scan_file_content(content, filepath))

    if entropy:
        from secretsweep.core.entropy_scanner import scan_content_for_entropy
        findings.extend(scan_content_for_entropy(content, filepath, config=config))

    return findings


def scan_directory(
    path,
    ignorer=None,
    entropy=False,
    path_scan=False,
    archives=False,
    k8s=False,
    tf_state=False,
    config=None,
):
    all_findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if not _should_skip_dir(d)
            and (not ignorer or not ignorer.is_ignored(os.path.join(root, d)))
        ]

        for filename in files:
            filepath = os.path.join(root, filename)

            if ignorer and ignorer.is_ignored(filepath):
                continue

            if path_scan:
                from secretsweep.core.path_scanner import scan_path
                all_findings.extend(scan_path(filepath))

            _, ext = os.path.splitext(filename.lower())

            if archives and ext in _ARCHIVE_EXTS:
                from secretsweep.core.archive_scanner import scan_archive
                all_findings.extend(scan_archive(filepath))
                continue

            if k8s and ext in _YAML_EXTS:
                from secretsweep.core.k8s_scanner import scan_kubernetes_secret
                all_findings.extend(scan_kubernetes_secret(filepath))

            if tf_state and filename.endswith('.tfstate'):
                from secretsweep.core.tf_scanner import scan_terraform_state
                all_findings.extend(scan_terraform_state(filepath))
                continue

            all_findings.extend(scan_file(filepath, entropy=entropy, config=config))

    return all_findings
