import os
import tempfile
from secretsweep.core.path_scanner import scan_path


def _tmp(name):
    d = tempfile.mkdtemp()
    return os.path.join(d, name)


def test_pem_file_flagged():
    findings = scan_path(_tmp("server.pem"))
    assert len(findings) > 0
    assert any("Private Key" in f["name"] or "Certificate" in f["name"] for f in findings)


def test_key_file_flagged():
    findings = scan_path(_tmp("secret.key"))
    assert len(findings) > 0


def test_env_file_flagged():
    findings = scan_path(_tmp(".env"))
    assert len(findings) > 0
    assert any("Environment" in f["name"] for f in findings)


def test_id_rsa_flagged():
    findings = scan_path(_tmp("id_rsa"))
    assert len(findings) > 0
    assert any("SSH" in f["name"] for f in findings)


def test_regular_python_file_not_flagged():
    findings = scan_path(_tmp("main.py"))
    assert len(findings) == 0


def test_finding_has_source_path():
    findings = scan_path(_tmp("server.pem"))
    assert len(findings) > 0
    assert findings[0]["source"] == "path"
    assert findings[0]["category"] == "path"
