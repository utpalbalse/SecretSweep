import os
import tempfile
from secretsweep.core.scanner import scan_directory, _is_binary, _should_skip_dir


def _make_project(structure):
    root = tempfile.mkdtemp()
    for rel_path, content in structure.items():
        full_path = os.path.join(root, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(full_path, mode) as f:
            f.write(content)
    return root


def test_node_modules_skipped():
    root = _make_project({
        'node_modules/lib/index.js': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE1234',
        'src/app.py': 'print("hello")',
    })
    findings = scan_directory(root)
    assert all('node_modules' not in f['file'] for f in findings)


def test_git_dir_skipped():
    root = _make_project({
        '.git/config': 'AKIAIOSFODNN7EXAMPLE1234',
        'app.py': 'print("hello")',
    })
    findings = scan_directory(root)
    assert all('.git' not in f['file'] for f in findings)


def test_pycache_skipped():
    root = _make_project({
        '__pycache__/module.cpython-311.pyc': b'AKIAIOSFODNN7EXAMPLE1234',
        'app.py': 'print("hello")',
    })
    findings = scan_directory(root)
    assert all('__pycache__' not in f['file'] for f in findings)


def test_venv_skipped():
    root = _make_project({
        'venv/lib/site.py': 'AKIAIOSFODNN7EXAMPLE1234',
        'app.py': 'print("hello")',
    })
    findings = scan_directory(root)
    assert all('venv' not in f['file'] for f in findings)


def test_binary_file_skipped():
    root = _make_project({
        'image.png': b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00AKIAIOSFODNN7EXAMPLE1234',
        'app.py': 'print("hello")',
    })
    findings = scan_directory(root)
    assert all('image.png' not in f['file'] for f in findings)


def test_secret_in_normal_file_still_found():
    root = _make_project({
        'config.py': 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"',
    })
    findings = scan_directory(root)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_is_binary_detects_null_bytes():
    tmp = tempfile.mktemp()
    with open(tmp, 'wb') as f:
        f.write(b'some text\x00more text')
    assert _is_binary(tmp) is True


def test_is_binary_returns_false_for_text():
    tmp = tempfile.mktemp()
    with open(tmp, 'w') as f:
        f.write('normal text file contents')
    assert _is_binary(tmp) is False


def test_should_skip_dir_default_dirs():
    assert _should_skip_dir('node_modules') is True
    assert _should_skip_dir('.git') is True
    assert _should_skip_dir('__pycache__') is True
    assert _should_skip_dir('venv') is True
    assert _should_skip_dir('src') is False


def test_should_skip_dir_egg_info_pattern():
    assert _should_skip_dir('secretsweep.egg-info') is True
    assert _should_skip_dir('mypackage.dist-info') is True
