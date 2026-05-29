import fnmatch
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial

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


def _scan_single_file(filepath, *, entropy, path_scan, archives, k8s, tf_state, config):
    results = []
    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename.lower())

    if path_scan:
        from secretsweep.core.path_scanner import scan_path
        results.extend(scan_path(filepath))

    if archives and ext in _ARCHIVE_EXTS:
        from secretsweep.core.archive_scanner import scan_archive
        results.extend(scan_archive(filepath))
        return results

    if k8s and ext in _YAML_EXTS:
        from secretsweep.core.k8s_scanner import scan_kubernetes_secret
        results.extend(scan_kubernetes_secret(filepath))

    if tf_state and filename.endswith('.tfstate'):
        from secretsweep.core.tf_scanner import scan_terraform_state
        results.extend(scan_terraform_state(filepath))
        return results

    results.extend(scan_file(filepath, entropy=entropy, config=config))
    return results


def scan_directory(
    path,
    ignorer=None,
    entropy=False,
    path_scan=False,
    archives=False,
    k8s=False,
    tf_state=False,
    config=None,
    workers=None,
):
    # Phase 1: collect file paths sequentially — dir filtering must be sequential
    filepaths = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if not _should_skip_dir(d)
            and (not ignorer or not ignorer.is_ignored(os.path.join(root, d)))
        ]
        for filename in files:
            filepath = os.path.join(root, filename)
            if not ignorer or not ignorer.is_ignored(filepath):
                filepaths.append(filepath)

    if not filepaths:
        return []

    # Phase 2: scan files in parallel
    scan_fn = partial(
        _scan_single_file,
        entropy=entropy,
        path_scan=path_scan,
        archives=archives,
        k8s=k8s,
        tf_state=tf_state,
        config=config,
    )

    all_findings = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for results in executor.map(scan_fn, filepaths):
            all_findings.extend(results)

    return all_findings
