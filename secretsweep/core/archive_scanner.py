import zipfile
import tarfile


def scan_archive(filepath):
    findings = []

    if zipfile.is_zipfile(filepath):
        try:
            with zipfile.ZipFile(filepath) as zf:
                for name in zf.namelist():
                    try:
                        content = zf.read(name).decode('utf-8', errors='ignore')
                        _scan_content(content, f"{filepath}::{name}", findings)
                    except Exception:
                        pass
        except Exception:
            pass

    else:
        try:
            with tarfile.open(filepath) as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    try:
                        fobj = tf.extractfile(member)
                        if fobj:
                            content = fobj.read().decode('utf-8', errors='ignore')
                            _scan_content(content, f"{filepath}::{member.name}", findings)
                    except Exception:
                        pass
        except Exception:
            pass

    return findings


def _scan_content(content, virtual_path, findings):
    from secretsweep.core.scanner import scan_file_content
    for finding in scan_file_content(content, virtual_path):
        finding['source'] = 'archive'
        findings.append(finding)
