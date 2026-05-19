import json
import os
import tempfile
from secretsweep.core.tf_scanner import scan_terraform_state


def _write_tfstate(outputs=None, resources=None):
    d = tempfile.mkdtemp()
    filepath = os.path.join(d, 'terraform.tfstate')
    state = {
        'version': 4,
        'outputs': outputs or {},
        'resources': resources or [],
    }
    with open(filepath, 'w') as f:
        json.dump(state, f)
    return filepath


def test_tf_secret_in_output_detected():
    filepath = _write_tfstate(outputs={
        'db_url': {'value': 'postgres://admin:mysecret@localhost/prod'}
    })
    findings = scan_terraform_state(filepath)
    assert any(f['name'] == 'Database URL' for f in findings)


def test_tf_secret_in_resource_detected():
    filepath = _write_tfstate(resources=[{
        'type': 'aws_instance',
        'instances': [{'attributes': {'user_data': 'AKIAIOSFODNN7EXAMPLE1234'}}]
    }])
    findings = scan_terraform_state(filepath)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_tf_clean_state_no_findings():
    filepath = _write_tfstate(outputs={'region': {'value': 'us-east-1'}})
    findings = scan_terraform_state(filepath)
    assert len(findings) == 0


def test_tf_finding_has_correct_fields():
    filepath = _write_tfstate(outputs={
        'conn': {'value': 'postgres://user:pass@host/db'}
    })
    findings = scan_terraform_state(filepath)
    assert len(findings) > 0
    f = findings[0]
    assert f['source'] == 'terraform_state'
    assert 'tf_context' in f
