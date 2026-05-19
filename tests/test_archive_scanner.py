import io
import os
import tarfile
import tempfile
import zipfile
from secretsweep.core.archive_scanner import scan_archive


def _make_zip(filename, content):
    d = tempfile.mkdtemp()
    zip_path = os.path.join(d, 'test.zip')
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr(filename, content)
    return zip_path


def _make_tar(filename, content):
    d = tempfile.mkdtemp()
    tar_path = os.path.join(d, 'test.tar.gz')
    with tarfile.open(tar_path, 'w:gz') as tf:
        data = content.encode()
        info = tarfile.TarInfo(name=filename)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return tar_path


def test_zip_secret_detected():
    zip_path = _make_zip('config.txt', 'AKIAIOSFODNN7EXAMPLE1234')
    findings = scan_archive(zip_path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_zip_clean_file_no_findings():
    zip_path = _make_zip('readme.txt', 'This is a normal readme file.')
    findings = scan_archive(zip_path)
    assert len(findings) == 0


def test_tar_secret_detected():
    tar_path = _make_tar('config.txt', 'AKIAIOSFODNN7EXAMPLE1234')
    findings = scan_archive(tar_path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_archive_finding_has_source_archive():
    zip_path = _make_zip('config.txt', 'AKIAIOSFODNN7EXAMPLE1234')
    findings = scan_archive(zip_path)
    assert len(findings) > 0
    assert findings[0]['source'] == 'archive'
