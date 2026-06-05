import os
import tempfile
from secretsweep.core.cicd_scanner import scan_cicd_file, scan_cicd_directory


def _write(content, suffix=".yml"):
    f = tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_github_actions_env_with_known_pattern():
    content = """
jobs:
  build:
    steps:
      - name: Deploy
        env:
          AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE1234
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_gitlab_ci_variables_key_heuristic():
    content = """
variables:
  MY_API_TOKEN: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
  NODE_ENV: production
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    assert any(f['name'] == 'GitHub Token' for f in findings)


def test_non_secret_env_vars_not_flagged():
    content = """
jobs:
  build:
    env:
      NODE_ENV: production
      PORT: "8080"
      DEBUG: "false"
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    assert findings == []


def test_clean_config_no_findings():
    content = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    assert findings == []


def test_source_is_cicd():
    content = """
variables:
  API_KEY: AKIAIOSFODNN7EXAMPLE1234
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    assert all(f['source'] == 'cicd' for f in findings)


def test_scan_cicd_directory_finds_github_actions():
    root = tempfile.mkdtemp()
    workflows_dir = os.path.join(root, '.github', 'workflows')
    os.makedirs(workflows_dir)
    workflow_path = os.path.join(workflows_dir, 'ci.yml')
    with open(workflow_path, 'w') as f:
        f.write("""
jobs:
  build:
    env:
      AWS_KEY: AKIAIOSFODNN7EXAMPLE1234
""")
    findings = scan_cicd_directory(root)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_scan_cicd_directory_finds_gitlab_ci():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, '.gitlab-ci.yml'), 'w') as f:
        f.write("""
variables:
  DEPLOY_TOKEN: AKIAIOSFODNN7EXAMPLE1234
""")
    findings = scan_cicd_directory(root)
    assert any(f['name'] == 'AWS Access Key' for f in findings)


def test_no_duplicate_findings_for_same_secret():
    content = """
env:
  AWS_KEY: AKIAIOSFODNN7EXAMPLE1234
"""
    path = _write(content)
    findings = scan_cicd_file(path)
    os.unlink(path)
    aws_findings = [f for f in findings if f['name'] == 'AWS Access Key']
    assert len(aws_findings) == 1
