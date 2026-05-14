import os
import tempfile
import git
from secretsweep.core.git_scanner import scan_git_history


def make_repo_with_secret(secret_line):
    tmp = tempfile.mkdtemp()
    repo = git.Repo.init(tmp)
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@test.com").release()

    secret_file = os.path.join(tmp, "config.txt")
    with open(secret_file, "w") as f:
        f.write(secret_line + "\n")

    repo.index.add(["config.txt"])
    repo.index.commit("add config")
    return tmp


def test_git_history_finds_aws_key():
    repo_path = make_repo_with_secret("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    findings = scan_git_history(repo_path)
    assert any(f["name"] == "AWS Access Key" for f in findings)


def test_git_history_finds_database_url():
    repo_path = make_repo_with_secret("DATABASE_URL=postgres://user:password@localhost/db")
    findings = scan_git_history(repo_path)
    assert any(f["name"] == "Database URL" for f in findings)


def test_git_history_no_false_positive():
    repo_path = make_repo_with_secret("this is just a normal config file")
    findings = scan_git_history(repo_path)
    assert len(findings) == 0


def test_git_history_finding_has_commit_info():
    repo_path = make_repo_with_secret("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    findings = scan_git_history(repo_path)
    assert len(findings) > 0
    finding = findings[0]
    assert "commit" in finding
    assert "author" in finding
    assert "message" in finding
    assert finding["source"] == "git_history"
