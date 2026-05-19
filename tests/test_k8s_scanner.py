import base64
import os
import tempfile
from secretsweep.core.k8s_scanner import scan_kubernetes_secret


def _write_k8s_secret(data_dict):
    import yaml
    d = tempfile.mkdtemp()
    filepath = os.path.join(d, 'secret.yaml')
    encoded = {k: base64.b64encode(v.encode()).decode() for k, v in data_dict.items()}
    doc = {
        'apiVersion': 'v1',
        'kind': 'Secret',
        'metadata': {'name': 'test-secret'},
        'data': encoded,
    }
    with open(filepath, 'w') as f:
        yaml.dump(doc, f)
    return filepath


def test_k8s_aws_key_detected():
    filepath = _write_k8s_secret({'access_key': 'AKIAIOSFODNN7EXAMPLE1234'})
    findings = scan_kubernetes_secret(filepath)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_k8s_database_url_detected():
    filepath = _write_k8s_secret({'db_url': 'postgres://user:password@localhost/db'})
    findings = scan_kubernetes_secret(filepath)
    assert any(f['name'] == 'Database URL' for f in findings)


def test_k8s_non_secret_yaml_ignored():
    d = tempfile.mkdtemp()
    filepath = os.path.join(d, 'deployment.yaml')
    with open(filepath, 'w') as f:
        f.write('apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp\n')
    findings = scan_kubernetes_secret(filepath)
    assert len(findings) == 0


def test_k8s_finding_has_correct_fields():
    filepath = _write_k8s_secret({'key': 'AKIAIOSFODNN7EXAMPLE1234'})
    findings = scan_kubernetes_secret(filepath)
    assert len(findings) > 0
    f = findings[0]
    assert f['source'] == 'k8s_secret'
    assert 'k8s_key' in f
